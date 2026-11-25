use anyhow::{Result, anyhow};
use axum::http::{HeaderMap, HeaderValue, header::COOKIE};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey},
    rand::{SecureRandom, SystemRandom},
};

use crate::tls::unix_seconds;

const COOKIE_NAME: &str = "__Host-shomei";
const TOKEN_LEN: usize = 48;
const NONCE_LEN: usize = 12;

pub struct Sessions {
    key: LessSafeKey,
    random: SystemRandom,
    ttl: u64,
}

impl Sessions {
    pub fn new(ttl: u64) -> Result<Self> {
        let random = SystemRandom::new();
        let mut secret = [0; 32];
        random
            .fill(&mut secret)
            .map_err(|_| anyhow!("session key generation failed"))?;
        let key = UnboundKey::new(&aead::CHACHA20_POLY1305, &secret)
            .map_err(|_| anyhow!("session key initialization failed"))?;
        Ok(Self {
            key: LessSafeKey::new(key),
            random,
            ttl,
        })
    }

    pub fn issue(&self) -> Result<(HeaderValue, u64)> {
        let expires = unix_seconds()? + self.ttl;
        let mut nonce = [0; NONCE_LEN];
        self.random
            .fill(&mut nonce)
            .map_err(|_| anyhow!("session nonce generation failed"))?;
        let mut payload = expires.to_be_bytes().to_vec();
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::empty(),
                &mut payload,
            )
            .map_err(|_| anyhow!("session encryption failed"))?;
        let token = URL_SAFE_NO_PAD.encode([nonce.as_slice(), &payload].concat());
        let cookie = format!(
            "{COOKIE_NAME}={token}; Path=/; Max-Age={}; Secure; HttpOnly; SameSite=Lax",
            self.ttl
        );
        Ok((HeaderValue::from_str(&cookie)?, expires))
    }

    pub fn verify(&self, headers: &HeaderMap) -> bool {
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
                .expires_at(token)
                .is_some_and(|expires| unix_seconds().is_ok_and(|now| now < expires))
    }

    fn expires_at(&self, token: &str) -> Option<u64> {
        if token.len() != TOKEN_LEN {
            return None;
        }
        let mut bytes = URL_SAFE_NO_PAD.decode(token).ok()?;
        let (nonce, payload) = bytes.split_at_mut(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce).ok()?;
        let plaintext = self.key.open_in_place(nonce, Aad::empty(), payload).ok()?;
        Some(u64::from_be_bytes(plaintext.try_into().ok()?))
    }
}

pub fn session_value(pair: &str) -> Option<&str> {
    let (name, value) = pair.trim().split_once('=')?;
    (name.trim() == COOKIE_NAME).then_some(value)
}
