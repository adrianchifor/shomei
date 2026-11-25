use std::{
    collections::{BTreeSet, HashMap, HashSet},
    fs::{self, File, OpenOptions},
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use crypto_glue::traits::EncodeDer;
use rcgen::SubjectPublicKeyInfo;
use ring::digest::{SHA256, digest};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use serde::{Deserialize, Serialize};
use serde_cbor_2::Value;
use subtle::ConstantTimeEq;
use webauthn_rs::prelude::*;
use x509_parser::{oid_registry::*, parse_x509_certificate};

use crate::config::Limits;

const CHALLENGE_TTL: Duration = Duration::from_secs(120);
const DEFAULT_ACCOUNT: &str = "operator";
const ES256: i64 = -7;
const UNAUTHORIZED: ApiError = ApiError(StatusCode::UNAUTHORIZED, "YubiKey verification failed");
const NOT_ENROLLED: ApiError = ApiError(StatusCode::CONFLICT, "enroll a YubiKey first");

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
    accounts: HashMap<String, Arc<Account>>,
    credential_ids: Mutex<HashSet<Vec<u8>>>,
    challenges: Mutex<Challenges>,
    _lock: File,
}

struct Account {
    file: PathBuf,
    token: Option<[u8; 32]>,
    credential: Mutex<Option<StoredCredential>>,
}

struct StoredCredential {
    key: AttestedPasskey,
    counter: u32,
}

enum Pending {
    Enroll(Arc<Account>, AttestedPasskeyRegistration),
    Login(Arc<Account>, AttestedPasskeyAuthentication, Grant),
}

pub enum Grant {
    Http,
    Tcp(SubjectPublicKeyInfo),
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
    pub fn new(
        origin: &Url,
        state_dir: &Path,
        token_file: Option<&Path>,
        tokens_file: Option<&Path>,
        limits: &Limits,
    ) -> Result<Self> {
        let webauthn =
            WebauthnBuilder::new(origin.domain().context("missing WebAuthn RP ID")?, origin)?
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
        let accounts = read_accounts(state_dir, token_file, tokens_file, &yubikeys)?;
        let mut ids = HashSet::new();
        for account in accounts.values() {
            if let Some(stored) = account
                .credential
                .lock()
                .expect("new account lock")
                .as_ref()
            {
                ensure!(
                    ids.insert(stored.key.cred_id().clone()),
                    "duplicate enrolled credential"
                );
            }
        }
        let challenges = Mutex::new(Challenges::new(limits));
        Ok(Self {
            webauthn,
            yubikeys,
            accounts,
            credential_ids: Mutex::new(ids),
            challenges,
            _lock: lock,
        })
    }

    pub fn start_enroll(
        &self,
        name: Option<&str>,
        bearer: Option<&str>,
        peer: IpAddr,
    ) -> Result<Challenge<CreationChallengeResponse>, ApiError> {
        let (name, account) = self.account(name)?;
        account.check_token(bearer)?;
        if account.lock()?.is_some() {
            return Err(ApiError(
                StatusCode::CONFLICT,
                "a YubiKey is already enrolled",
            ));
        }
        self.check_challenge_capacity(peer)?;
        let (mut options, registration) = self
            .webauthn
            .start_attested_passkey_registration(
                Uuid::new_v4(),
                name,
                name,
                None,
                self.yubikeys.roots.clone(),
                Some(AuthenticatorAttachment::CrossPlatform),
            )
            .map_err(ApiError::internal)?;
        options
            .public_key
            .pub_key_cred_params
            .retain(|option| option.alg == ES256);
        let challenge_id =
            lock(&self.challenges)?.insert(peer, Pending::Enroll(account.clone(), registration))?;
        Ok(Challenge {
            challenge_id,
            options,
        })
    }

    pub fn finish_enroll(
        &self,
        bearer: Option<&str>,
        mut signed: SignedChallenge<RegisterPublicKeyCredential>,
    ) -> Result<(), ApiError> {
        let Pending::Enroll(account, registration) =
            lock(&self.challenges)?.take(signed.challenge_id)?
        else {
            return Err(UNAUTHORIZED);
        };
        account.check_token(bearer)?;
        let denied = ApiError(StatusCode::UNAUTHORIZED, "YubiKey attestation failed");
        self.yubikeys
            .complete_chain(&mut signed.credential)
            .map_err(|_| ApiError(denied.0, denied.1))?;
        let key = self
            .webauthn
            .finish_attested_passkey_registration(&signed.credential, &registration)
            .map_err(|_| ApiError(denied.0, denied.1))?;
        self.yubikeys.verify(&key).map_err(|_| denied)?;
        let mut credential = account.lock()?;
        if credential.is_some() {
            return Err(ApiError(
                StatusCode::CONFLICT,
                "a YubiKey is already enrolled",
            ));
        }
        let id = key.cred_id().clone();
        if !lock(&self.credential_ids)?.insert(id.clone()) {
            return Err(ApiError(
                StatusCode::CONFLICT,
                "credential is already enrolled",
            ));
        }
        let result = account.save(&mut credential, StoredCredential::new(key));
        if result.is_err() && credential.is_none() {
            lock(&self.credential_ids)?.remove(&id);
        }
        result
    }

    pub fn check_challenge_capacity(&self, peer: IpAddr) -> Result<(), ApiError> {
        lock(&self.challenges)?.check_capacity(peer)
    }

    pub fn start_login(
        &self,
        name: Option<&str>,
        grant: Grant,
        peer: IpAddr,
    ) -> Result<Challenge<RequestChallengeResponse>, ApiError> {
        let (_, account) = self.account(name)?;
        let credential = account.lock()?.as_ref().ok_or(NOT_ENROLLED)?.key.clone();
        let (options, authentication) = self
            .webauthn
            .start_attested_passkey_authentication(&[credential])
            .map_err(ApiError::internal)?;
        let challenge_id = lock(&self.challenges)?
            .insert(peer, Pending::Login(account.clone(), authentication, grant))?;
        Ok(Challenge {
            challenge_id,
            options,
        })
    }

    pub fn finish_login(
        &self,
        signed: SignedChallenge<PublicKeyCredential>,
    ) -> Result<Grant, ApiError> {
        let Pending::Login(account, authentication, grant) =
            lock(&self.challenges)?.take(signed.challenge_id)?
        else {
            return Err(UNAUTHORIZED);
        };
        let context: ClientContext =
            serde_json::from_slice(&signed.credential.response.client_data_json)
                .map_err(|_| UNAUTHORIZED)?;
        if context.cross_origin || context.top_origin.is_some() {
            return Err(UNAUTHORIZED);
        }
        let result = self
            .webauthn
            .finish_attested_passkey_authentication(&signed.credential, &authentication)
            .map_err(|_| UNAUTHORIZED)?;
        if !result.user_verified() || result.backup_eligible() || result.backup_state() {
            return Err(UNAUTHORIZED);
        }
        let mut credential = account.lock()?;
        let stored = credential.as_ref().ok_or(UNAUTHORIZED)?;
        let counter = result.counter();
        if (counter != 0 || stored.counter != 0) && counter <= stored.counter {
            return Err(UNAUTHORIZED);
        }
        let mut key = stored.key.clone();
        if key.update_credential(&result).ok_or(UNAUTHORIZED)? {
            account.save(&mut credential, StoredCredential { key, counter })?;
        }
        Ok(grant)
    }

    fn account<'a>(
        &'a self,
        name: Option<&'a str>,
    ) -> Result<(&'a str, &'a Arc<Account>), ApiError> {
        let name = name.unwrap_or(DEFAULT_ACCOUNT);
        if !valid_account_name(name) {
            return Err(ApiError(StatusCode::BAD_REQUEST, "invalid account name"));
        }
        Ok((name, self.accounts.get(name).ok_or(NOT_ENROLLED)?))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientContext {
    #[serde(default)]
    cross_origin: bool,
    top_origin: Option<String>,
}

impl StoredCredential {
    fn new(key: AttestedPasskey) -> Self {
        let counter = Credential::from(key.clone()).counter;
        Self { key, counter }
    }
}

impl Account {
    fn lock(&self) -> Result<MutexGuard<'_, Option<StoredCredential>>, ApiError> {
        lock(&self.credential)
    }

    fn check_token(&self, bearer: Option<&str>) -> Result<(), ApiError> {
        if let (Some(token), Some(bearer)) = (self.token, bearer)
            && bool::from(token.ct_eq(&token_digest(bearer)))
        {
            return Ok(());
        }
        Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "invalid enrollment token",
        ))
    }

    fn save(
        &self,
        credential: &mut Option<StoredCredential>,
        stored: StoredCredential,
    ) -> Result<(), ApiError> {
        let save = || -> Result<()> {
            let path = self.file.parent().context("missing state directory")?;
            let dir = File::open(path)?;
            let mut file = tempfile::NamedTempFile::new_in(path)?;
            serde_json::to_writer(file.as_file_mut(), &stored.key)?;
            file.as_file().sync_all()?;
            file.persist(&self.file)?;
            *credential = Some(stored);
            dir.sync_all()?;
            Ok(())
        };
        save().map_err(ApiError::internal)
    }
}

fn valid_account_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn token_digest(token: &str) -> [u8; 32] {
    digest(&SHA256, token.as_bytes())
        .as_ref()
        .try_into()
        .expect("SHA-256 has 32 bytes")
}

fn read_accounts(
    state_dir: &Path,
    token_file: Option<&Path>,
    tokens_file: Option<&Path>,
    yubikeys: &YubikeyPolicy,
) -> Result<HashMap<String, Arc<Account>>> {
    let named_dir = state_dir.join("accounts");
    fs::create_dir_all(&named_dir).context("create account directory")?;
    let mut tokens: HashMap<String, String> = match tokens_file {
        Some(path) => toml::from_str(&fs::read_to_string(path).context("read enrollment tokens")?)
            .context("parse enrollment tokens")?,
        None => HashMap::new(),
    };
    if let Some(path) = token_file {
        match fs::read_to_string(path) {
            Ok(token) => ensure!(
                tokens.insert(DEFAULT_ACCOUNT.into(), token).is_none(),
                "duplicate operator enrollment token"
            ),
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && state_dir.join("credential.json").is_file() => {}
            Err(error) => return Err(error).context("read enrollment token"),
        }
    }
    let mut accounts = HashMap::new();
    let mut digests = HashSet::new();
    let mut names: HashSet<String> = tokens.keys().cloned().collect();
    if state_dir.join("credential.json").is_file() {
        names.insert(DEFAULT_ACCOUNT.into());
    }
    for entry in fs::read_dir(&named_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            let name = path
                .file_stem()
                .and_then(|name| name.to_str())
                .context("invalid account file")?;
            ensure!(
                name != DEFAULT_ACCOUNT,
                "operator credential belongs in the state directory"
            );
            names.insert(name.to_string());
        }
    }
    for name in names {
        ensure!(valid_account_name(&name), "invalid account name: {name}");
        let file = if name == DEFAULT_ACCOUNT {
            state_dir.join("credential.json")
        } else {
            named_dir.join(format!("{name}.json"))
        };
        let credential = match File::open(&file) {
            Ok(file) => {
                let key = serde_json::from_reader(file).context("read stored credential")?;
                yubikeys
                    .verify(&key)
                    .with_context(|| format!("validate stored YubiKey for {name}"))?;
                Some(StoredCredential::new(key))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error).context("open stored credential"),
        };
        let token = tokens
            .get(&name)
            .map(|token| -> Result<_> {
                let token = token.trim();
                ensure!(
                    token.len() >= 32 && token.bytes().all(|byte| byte.is_ascii_graphic()),
                    "invalid enrollment token for {name}"
                );
                let digest = token_digest(token);
                ensure!(digests.insert(digest), "duplicate enrollment token");
                Ok(digest)
            })
            .transpose()?;
        accounts.insert(
            name,
            Arc::new(Account {
                file,
                token,
                credential: Mutex::new(credential),
            }),
        );
    }
    ensure!(
        !accounts.is_empty(),
        "configure an enrollment token or restore enrolled credentials"
    );
    Ok(accounts)
}

struct Challenges {
    values: HashMap<Uuid, (Instant, IpAddr, Pending)>,
    expirations: BTreeSet<(Instant, Uuid)>,
    peers: HashMap<IpAddr, usize>,
    limit: usize,
    per_ip: usize,
}

impl Challenges {
    fn new(limits: &Limits) -> Self {
        Self {
            values: HashMap::new(),
            expirations: BTreeSet::new(),
            peers: HashMap::new(),
            limit: limits.pending_challenges,
            per_ip: limits.pending_per_ip,
        }
    }

    fn check_capacity(&mut self, peer: IpAddr) -> Result<(), ApiError> {
        let now = Instant::now();
        while let Some(&(expires, id)) = self.expirations.first() {
            if expires > now {
                break;
            }
            self.remove(id);
        }
        if self.values.len() >= self.limit
            || self.peers.get(&peer).copied().unwrap_or(0) >= self.per_ip
        {
            return Err(ApiError(
                StatusCode::TOO_MANY_REQUESTS,
                "too many pending challenges",
            ));
        }
        Ok(())
    }

    fn insert(&mut self, peer: IpAddr, pending: Pending) -> Result<Uuid, ApiError> {
        self.check_capacity(peer)?;
        let id = Uuid::new_v4();
        let expires = Instant::now() + CHALLENGE_TTL;
        self.values.insert(id, (expires, peer, pending));
        self.expirations.insert((expires, id));
        *self.peers.entry(peer).or_default() += 1;
        Ok(id)
    }

    fn remove(&mut self, id: Uuid) -> Option<(Instant, Pending)> {
        let (expires, peer, pending) = self.values.remove(&id)?;
        self.expirations.remove(&(expires, id));
        if let Some(count) = self.peers.get_mut(&peer) {
            *count -= 1;
            if *count == 0 {
                self.peers.remove(&peer);
            }
        }
        Some((expires, pending))
    }

    fn take(&mut self, id: Uuid) -> Result<Pending, ApiError> {
        self.remove(id)
            .filter(|(expires, _)| *expires > Instant::now())
            .map(|(_, pending)| pending)
            .ok_or(ApiError(
                StatusCode::UNAUTHORIZED,
                "challenge expired or already used",
            ))
    }
}

fn lock<T>(mutex: &Mutex<T>) -> Result<MutexGuard<'_, T>, ApiError> {
    mutex
        .lock()
        .map_err(|_| ApiError::internal("state lock poisoned"))
}

struct YubikeyPolicy {
    roots: AttestationCaList,
    paths: Vec<AttestationPath>,
}

struct AttestationPath {
    issuer: CertificateDer<'static>,
    intermediates: Vec<CertificateDer<'static>>,
}

impl YubikeyPolicy {
    fn new() -> Result<Self> {
        let pem = include_bytes!("../assets/yubico/root-1.pem");
        let root = CertificateDer::from_pem_slice(pem)?;
        let mut roots = AttestationCaListBuilder::new();
        for id in YUBIKEY_5_MODELS {
            roots
                .insert_device_der(
                    root.as_ref(),
                    Uuid::parse_str(id)?,
                    "YubiKey 5".into(),
                    Default::default(),
                )
                .map_err(|error| anyhow::anyhow!("invalid Yubico root: {error:?}"))?;
        }
        let parents = CertificateDer::pem_slice_iter(include_bytes!(
            "../assets/yubico/attestation-intermediates.pem"
        ))
        .collect::<Result<Vec<_>, _>>()?;
        let mut paths = Vec::new();
        for issuer in CertificateDer::pem_slice_iter(include_bytes!(
            "../assets/yubico/fido-intermediates.pem"
        )) {
            let issuer = issuer?;
            let parent = parents
                .iter()
                .find(|parent| issued_by(issuer.as_ref(), parent.as_ref()))
                .context("missing Yubico FIDO issuer parent")?;
            ensure!(
                issued_by(parent.as_ref(), root.as_ref()),
                "untrusted Yubico issuer parent"
            );
            paths.push(AttestationPath {
                issuer: issuer.clone(),
                intermediates: vec![issuer, parent.clone()],
            });
        }
        ensure!(!paths.is_empty(), "missing Yubico FIDO issuers");
        Ok(Self {
            roots: roots.build(),
            paths,
        })
    }

    fn complete_chain(&self, credential: &mut RegisterPublicKeyCredential) -> Result<()> {
        let mut object: Value = serde_cbor_2::from_slice(&credential.response.attestation_object)?;
        let Value::Map(fields) = &mut object else {
            anyhow::bail!("invalid attestation object")
        };
        ensure!(
            fields.get(&Value::Text("fmt".into())) == Some(&Value::Text("packed".into())),
            "packed attestation required"
        );
        let Some(Value::Map(statement)) = fields.get_mut(&Value::Text("attStmt".into())) else {
            anyhow::bail!("missing attestation statement");
        };
        ensure!(
            statement.get(&Value::Text("alg".into())) == Some(&Value::Integer(ES256.into())),
            "ES256 attestation required"
        );
        let Some(Value::Array(chain)) = statement.get_mut(&Value::Text("x5c".into())) else {
            anyhow::bail!("missing attestation chain");
        };
        let Some(Value::Bytes(leaf)) = chain.first() else {
            anyhow::bail!("missing attestation leaf")
        };
        let path = self
            .path_for(leaf)
            .context("unrecognized Yubico FIDO issuer")?;
        chain.truncate(1);
        chain.extend(
            path.intermediates
                .iter()
                .map(|cert| Value::Bytes(cert.to_vec())),
        );
        credential.response.attestation_object = serde_cbor_2::to_vec(&object)?;
        Ok(())
    }

    fn verify(&self, credential: &AttestedPasskey) -> Result<()> {
        ensure!(
            credential.cred_algorithm() == &COSEAlgorithm::ES256,
            "ES256 credential required"
        );
        let attestation = credential.attestation();
        let AttestationMetadata::Packed { aaguid } = attestation.metadata else {
            anyhow::bail!("packed FIDO attestation required");
        };
        let ParsedAttestationData::Basic(chain) = &attestation.data else {
            anyhow::bail!("manufacturer attestation required");
        };
        let root = credential.verify_attestation(&self.roots)?;
        ensure!(
            root.aaguids().contains_key(&aaguid),
            "unrecognized YubiKey model"
        );
        let leaf = chain
            .first()
            .context("missing attestation certificate")?
            .to_der()?;
        ensure!(
            self.path_for(&leaf).is_some(),
            "unrecognized Yubico FIDO issuer"
        );
        Ok(())
    }

    fn path_for(&self, leaf: &[u8]) -> Option<&AttestationPath> {
        self.paths
            .iter()
            .find(|path| issued_by(leaf, path.issuer.as_ref()))
    }
}

fn issued_by(cert: &[u8], issuer: &[u8]) -> bool {
    let (Ok(([], cert)), Ok(([], issuer))) =
        (parse_x509_certificate(cert), parse_x509_certificate(issuer))
    else {
        return false;
    };
    let algorithm = cert.signature_algorithm.algorithm.clone();
    [
        OID_SIG_ECDSA_WITH_SHA256,
        OID_SIG_ECDSA_WITH_SHA384,
        OID_PKCS1_SHA256WITHRSA,
        OID_PKCS1_SHA384WITHRSA,
        OID_PKCS1_SHA512WITHRSA,
    ]
    .contains(&algorithm)
        && cert.issuer() == issuer.subject()
        && cert.verify_signature(Some(issuer.public_key())).is_ok()
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
