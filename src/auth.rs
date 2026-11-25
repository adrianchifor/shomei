use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use openssl::{
    memcmp,
    pkey::{PKey, Public},
    sha::sha256,
    x509::X509,
};
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;

const CHALLENGE_TTL: Duration = Duration::from_secs(120);
const MAX_PENDING: usize = 512;
const UNAUTHORIZED: ApiError = ApiError(StatusCode::UNAUTHORIZED, "YubiKey verification failed");
const ENROLLED: ApiError = ApiError(StatusCode::CONFLICT, "a YubiKey is already enrolled");

#[derive(Debug)]
pub struct ApiError(pub StatusCode, pub &'static str);

impl ApiError {
    pub fn internal(error: impl std::fmt::Display) -> Self {
        eprintln!("Authentication service error: {error}");
        Self(
            StatusCode::INTERNAL_SERVER_ERROR,
            "authentication service error",
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({ "error": self.1 }))).into_response()
    }
}

pub struct Auth {
    webauthn: Webauthn,
    yubikeys: YubikeyPolicy,
    token: Option<[u8; 32]>,
    credential_file: PathBuf,
    inner: Mutex<Inner>,
    _lock: File,
}

struct Inner {
    credential: Option<AttestedPasskey>,
    counter: u32,
    pending: HashMap<Uuid, (Instant, Pending)>,
}

enum Pending {
    Enroll(AttestedPasskeyRegistration),
    Login(AttestedPasskeyAuthentication, Grant),
}

pub enum Grant {
    Http,
    Tcp(PKey<Public>),
}

#[derive(Serialize)]
pub struct Challenge<T> {
    challenge_id: Uuid,
    #[serde(flatten)]
    options: T,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedChallenge<T> {
    challenge_id: Uuid,
    credential: T,
}

impl Auth {
    pub fn new(origin: &Url, state_dir: &Path, token_file: Option<&Path>) -> Result<Self> {
        let rp = origin.domain().context("missing WebAuthn RP ID")?;
        let webauthn = WebauthnBuilder::new(rp, origin)?
            .rp_name("Shomei")
            .timeout(CHALLENGE_TTL)
            .build()?;
        let yubikeys = YubikeyPolicy::new()?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(state_dir.join(".lock"))
            .context("open state lock")?;
        lock.try_lock().context("lock state directory")?;
        let credential_file = state_dir.join("credential.json");
        let credential: Option<AttestedPasskey> = match File::open(&credential_file) {
            Ok(file) => Some(serde_json::from_reader(file).context("read stored credential")?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error).context("open stored credential"),
        };
        let (counter, token) = if let Some(credential) = &credential {
            yubikeys
                .verify(credential)
                .context("validate stored YubiKey attestation")?;
            (Credential::from(credential.clone()).counter, None)
        } else {
            let path = token_file.context("enrollment_token_file is required before enrollment")?;
            let token = fs::read_to_string(path).context("read enrollment token")?;
            let token = token.trim();
            ensure!(
                token.len() >= 32 && token.bytes().all(|byte| byte.is_ascii_graphic()),
                "invalid enrollment token"
            );
            (0, Some(sha256(token.as_bytes())))
        };
        let inner = Mutex::new(Inner {
            credential,
            counter,
            pending: HashMap::new(),
        });
        Ok(Self {
            webauthn,
            yubikeys,
            token,
            credential_file,
            inner,
            _lock: lock,
        })
    }

    pub fn start_enroll(
        &self,
        bearer: Option<&str>,
    ) -> Result<Challenge<CreationChallengeResponse>, ApiError> {
        let mut inner = self.lock()?;
        self.check_enrollment(&inner, bearer)?;
        let (options, registration) = self
            .webauthn
            .start_attested_passkey_registration(
                Uuid::new_v4(),
                "operator",
                "Operator",
                None,
                self.yubikeys.roots.clone(),
                Some(AuthenticatorAttachment::CrossPlatform),
            )
            .map_err(ApiError::internal)?;
        let challenge_id = inner.insert(Pending::Enroll(registration))?;
        Ok(Challenge {
            challenge_id,
            options,
        })
    }

    pub fn finish_enroll(
        &self,
        bearer: Option<&str>,
        signed: SignedChallenge<RegisterPublicKeyCredential>,
    ) -> Result<(), ApiError> {
        let mut inner = self.lock()?;
        self.check_enrollment(&inner, bearer)?;
        let Pending::Enroll(registration) = inner.take(signed.challenge_id)? else {
            return Err(UNAUTHORIZED);
        };
        let credential = self
            .webauthn
            .finish_attested_passkey_registration(&signed.credential, &registration)
            .map_err(|_| ApiError(StatusCode::UNAUTHORIZED, "YubiKey attestation failed"))?;
        self.yubikeys
            .verify(&credential)
            .map_err(|_| ApiError(StatusCode::UNAUTHORIZED, "unsupported YubiKey attestation"))?;
        self.save(&credential)?;
        inner.counter = Credential::from(credential.clone()).counter;
        inner.credential = Some(credential);
        inner.pending.clear();
        Ok(())
    }

    pub fn start_login(
        &self,
        grant: Grant,
    ) -> Result<Challenge<RequestChallengeResponse>, ApiError> {
        let mut inner = self.lock()?;
        let credential = inner
            .credential
            .as_ref()
            .ok_or(ApiError(StatusCode::CONFLICT, "enroll a YubiKey first"))?;
        let (options, authentication) = self
            .webauthn
            .start_attested_passkey_authentication(std::slice::from_ref(credential))
            .map_err(ApiError::internal)?;
        let challenge_id = inner.insert(Pending::Login(authentication, grant))?;
        Ok(Challenge {
            challenge_id,
            options,
        })
    }

    pub fn finish_login(
        &self,
        signed: SignedChallenge<PublicKeyCredential>,
    ) -> Result<Grant, ApiError> {
        let mut inner = self.lock()?;
        let Pending::Login(authentication, grant) = inner.take(signed.challenge_id)? else {
            return Err(UNAUTHORIZED);
        };
        let result = self
            .webauthn
            .finish_attested_passkey_authentication(&signed.credential, &authentication)
            .map_err(|_| UNAUTHORIZED)?;
        let counter = result.counter();
        if (counter != 0 || inner.counter != 0) && counter <= inner.counter {
            return Err(UNAUTHORIZED);
        }
        let mut credential = inner.credential.clone().ok_or(UNAUTHORIZED)?;
        if credential.update_credential(&result).ok_or(UNAUTHORIZED)? {
            self.save(&credential)?;
            inner.credential = Some(credential);
            inner.counter = counter;
        }
        Ok(grant)
    }

    fn check_enrollment(&self, inner: &Inner, bearer: Option<&str>) -> Result<(), ApiError> {
        if inner.credential.is_some() {
            return Err(ENROLLED);
        }
        match (self.token, bearer) {
            (Some(token), Some(bearer)) if memcmp::eq(&token, &sha256(bearer.as_bytes())) => Ok(()),
            _ => Err(ApiError(
                StatusCode::UNAUTHORIZED,
                "invalid enrollment token",
            )),
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, Inner>, ApiError> {
        self.inner
            .lock()
            .map_err(|_| ApiError::internal("state lock poisoned"))
    }

    fn save(&self, credential: &AttestedPasskey) -> Result<(), ApiError> {
        let result = (|| -> Result<()> {
            let dir = self
                .credential_file
                .parent()
                .context("missing state directory")?;
            let mut file = tempfile::NamedTempFile::new_in(dir)?;
            serde_json::to_writer(file.as_file_mut(), credential)?;
            file.as_file().sync_all()?;
            file.persist(&self.credential_file)?;
            Ok(())
        })();
        result.map_err(ApiError::internal)
    }
}

impl Inner {
    fn insert(&mut self, pending: Pending) -> Result<Uuid, ApiError> {
        let now = Instant::now();
        self.pending.retain(|_, (expires, _)| *expires > now);
        if self.pending.len() >= MAX_PENDING {
            return Err(ApiError(
                StatusCode::TOO_MANY_REQUESTS,
                "too many pending challenges",
            ));
        }
        let id = Uuid::new_v4();
        self.pending.insert(id, (now + CHALLENGE_TTL, pending));
        Ok(id)
    }

    fn take(&mut self, id: Uuid) -> Result<Pending, ApiError> {
        self.pending
            .remove(&id)
            .filter(|(expires, _)| *expires > Instant::now())
            .map(|(_, pending)| pending)
            .ok_or(ApiError(
                StatusCode::UNAUTHORIZED,
                "challenge expired or already used",
            ))
    }
}

struct YubikeyPolicy {
    roots: AttestationCaList,
    leaf_issuers: Vec<X509>,
}

impl YubikeyPolicy {
    fn new() -> Result<Self> {
        let legacy = [
            include_bytes!("../assets/yubico/fido-ca-1.pem").as_slice(),
            include_bytes!("../assets/yubico/fido-ca-2.pem").as_slice(),
        ];
        let current = include_bytes!("../assets/yubico/root-1.pem").as_slice();
        let mut roots = AttestationCaListBuilder::new();
        for pem in legacy.into_iter().chain([current]) {
            let ca = X509::from_pem(pem)?;
            for id in YUBIKEY_5_MODELS {
                roots.insert_device_x509(
                    ca.clone(),
                    Uuid::parse_str(id)?,
                    "YubiKey 5".into(),
                    Default::default(),
                )?;
            }
        }
        let mut leaf_issuers =
            X509::stack_from_pem(include_bytes!("../assets/yubico/fido-intermediates.pem"))?;
        for pem in legacy {
            leaf_issuers.push(X509::from_pem(pem)?);
        }
        Ok(Self {
            roots: roots.build(),
            leaf_issuers,
        })
    }

    fn verify(&self, credential: &AttestedPasskey) -> Result<()> {
        let attestation = credential.attestation();
        let AttestationMetadata::Packed { aaguid } = attestation.metadata else {
            anyhow::bail!("packed FIDO attestation required");
        };
        let ParsedAttestationData::Basic(chain) = &attestation.data else {
            anyhow::bail!("manufacturer attestation required");
        };
        let leaf = chain.first().context("missing attestation certificate")?;
        let root = credential.verify_attestation(&self.roots)?;
        ensure!(
            root.aaguids().contains_key(&aaguid),
            "unrecognized YubiKey model"
        );
        for issuer in &self.leaf_issuers {
            if leaf.issuer_name().try_cmp(issuer.subject_name())?.is_eq()
                && leaf.verify(&*issuer.public_key()?)?
            {
                return Ok(());
            }
        }
        anyhow::bail!("unrecognized Yubico FIDO issuer")
    }
}

const YUBIKEY_5_MODELS: &[&str] = &[
    "03012cb7-4fb2-42e7-9e8d-a81f10e2a5e9",
    "0a357157-9b18-4c8a-920e-d156e972b2f8",
    "19083c3d-8383-4b18-bc03-8f1c9ab2fd1b",
    "20ac7a17-c814-4833-93fe-539f0d5e3389",
    "24673149-6c86-42e7-98d9-433fb5b73296",
    "2fc0579f-8113-47ea-b116-bb5a8db9202a",
    "3b24bf49-1d45-4484-a917-13175df0867b",
    "4599062e-6926-4fe7-9566-9e8fb1aedaa0",
    "524de2de-982f-49b4-a769-2b5e3b73ad79",
    "662ef48a-95e2-4aaa-a6c1-5b9c40375824",
    "a02167b9-ae71-4ac7-9a07-06432ebb6f1c",
    "a25342c0-3cdc-4414-8e46-f4807fca511c",
    "b90e7dc1-316e-4fee-a25a-56a666a670fe",
    "c3479970-e58a-4f70-836f-853bf42fb063",
    "c5ef55ff-ad9a-4b9f-b580-adebafe026d0",
    "cb69481e-8ff7-4039-93ec-0a2729a154a8",
    "d7781e5d-e353-46aa-afe2-3ca49f13332a",
    "ee882879-721c-4913-9775-3dfcce97072a",
    "fa2b99dc-9e39-4257-8f92-4a30d23c4118",
    "ff4dac45-ede8-4ec2-aced-cf66103f4335",
];

#[cfg(test)]
mod tests;
