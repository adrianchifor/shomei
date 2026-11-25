use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

use anyhow::{Result, anyhow};
use axum::http::{HeaderMap, HeaderValue, header::COOKIE};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey},
    rand::{SecureRandom, SystemRandom},
};
use zeroize::Zeroizing;

use crate::tls::unix_seconds;

const COOKIE_NAME: &str = "__Host-shomei";
const DOMAIN: &[u8] = b"shomei-http-session-v2";
const TOKEN_LEN: usize = 59;
const NONCE_LEN: usize = 12;
const PAYLOAD_LEN: usize = 16;
const RAW_LEN: usize = NONCE_LEN + PAYLOAD_LEN + aead::MAX_TAG_LEN;

pub struct Sessions {
    key: LessSafeKey,
    sequence: AtomicU64,
    started: Instant,
    epoch: u64,
    ttl: u64,
}

impl Sessions {
    pub fn new(ttl: u64) -> Result<Self> {
        let mut secret = Zeroizing::new([0; 32]);
        SystemRandom::new()
            .fill(secret.as_mut())
            .map_err(|_| anyhow!("session key generation failed"))?;
        let key = UnboundKey::new(&aead::CHACHA20_POLY1305, secret.as_ref())
            .map_err(|_| anyhow!("session key initialization failed"))?;
        Ok(Self {
            key: LessSafeKey::new(key),
            sequence: AtomicU64::new(0),
            started: Instant::now(),
            epoch: unix_seconds()?,
            ttl,
        })
    }

    pub fn issue(&self, generation: u64) -> Result<(HeaderValue, u64)> {
        let expires = self.now() + self.ttl;
        let sequence = self
            .sequence
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |num| {
                num.checked_add(1)
            })
            .map_err(|_| anyhow!("session nonce range exhausted"))?;
        let mut nonce = [0; NONCE_LEN];
        nonce[4..].copy_from_slice(&sequence.to_be_bytes());
        let mut payload = [0; PAYLOAD_LEN];
        payload[..8].copy_from_slice(&expires.to_be_bytes());
        payload[8..].copy_from_slice(&generation.to_be_bytes());
        let tag = self
            .key
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(DOMAIN),
                &mut payload,
            )
            .map_err(|_| anyhow!("session encryption failed"))?;
        let mut raw = [0; RAW_LEN];
        raw[..NONCE_LEN].copy_from_slice(&nonce);
        raw[NONCE_LEN..NONCE_LEN + PAYLOAD_LEN].copy_from_slice(&payload);
        raw[NONCE_LEN + PAYLOAD_LEN..].copy_from_slice(tag.as_ref());
        let mut token = [0; TOKEN_LEN];
        URL_SAFE_NO_PAD.encode_slice(raw, &mut token)?;
        let token = std::str::from_utf8(&token)?;
        let cookie = format!(
            "{COOKIE_NAME}={token}; Path=/; Max-Age={}; Secure; HttpOnly; SameSite=Lax",
            self.ttl
        );
        Ok((HeaderValue::from_str(&cookie)?, expires))
    }

    pub fn verify(&self, headers: &HeaderMap, generation: u64) -> bool {
        let mut tokens = headers
            .get_all(COOKIE)
            .iter()
            .filter_map(|header| header.to_str().ok())
            .flat_map(|line| line.split(';'))
            .filter_map(session_value);
        let Some(token) = tokens.next() else {
            return false;
        };
        tokens.next().is_none()
            && self
                .claims(token)
                .is_some_and(|(expires, issued_generation)| {
                    issued_generation == generation && self.now() < expires
                })
    }

    fn claims(&self, token: &str) -> Option<(u64, u64)> {
        if token.len() != TOKEN_LEN {
            return None;
        }
        let mut bytes = [0; RAW_LEN];
        if URL_SAFE_NO_PAD.decode_slice(token, &mut bytes).ok()? != RAW_LEN {
            return None;
        }
        let (nonce, payload) = bytes.split_at_mut(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce).ok()?;
        let plaintext = self
            .key
            .open_in_place(nonce, Aad::from(DOMAIN), payload)
            .ok()?;
        let (expires, generation) = plaintext.split_at(8);
        Some((
            u64::from_be_bytes(expires.try_into().ok()?),
            u64::from_be_bytes(generation.try_into().ok()?),
        ))
    }

    fn now(&self) -> u64 {
        self.epoch + self.started.elapsed().as_secs()
    }
}

pub fn session_value(pair: &str) -> Option<&str> {
    let (name, value) = pair.trim().split_once('=')?;
    (name.trim() == COOKIE_NAME).then_some(value)
}
