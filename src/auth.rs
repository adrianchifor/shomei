mod identity;

pub use identity::{StaticIdentity, prepare_identity};

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use crypto_glue::traits::EncodeDer;
use rcgen::SubjectPublicKeyInfo;
use ring::digest::{SHA256, digest};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use serde::{Deserialize, Serialize};
use serde_cbor_2::Value;
use tokio::sync::watch;
use webauthn_rs::prelude::*;
use x509_parser::{oid_registry::*, parse_x509_certificate};

use crate::config::{Limits, validate_origin};

const CHALLENGE_TTL: Duration = Duration::from_secs(120);
const DEFAULT_ACCOUNT: &str = "operator";
const ES256: i64 = -7;
const MAX_IDENTITIES_BYTES: u64 = 64 * 1024 * 1024;
const UNAUTHORIZED: ApiError = ApiError(StatusCode::UNAUTHORIZED, "YubiKey verification failed");
const NOT_ALLOWED: ApiError = ApiError(StatusCode::FORBIDDEN, "YubiKey account is not allowed");

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
    origin: Url,
    webauthn: Webauthn,
    yubikeys: YubikeyPolicy,
    identities_file: PathBuf,
    counters_dir: PathBuf,
    accounts: RwLock<HashMap<String, Arc<Account>>>,
    last_digest: Mutex<[u8; 32]>,
    generation: AtomicU64,
    changes: watch::Sender<u64>,
    challenges: Mutex<Challenges>,
    _lock: File,
}

struct Account {
    key: AttestedPasskey,
    digest: [u8; 32],
    counter_file: PathBuf,
    counter: Mutex<u32>,
}

struct VerifiedIdentity {
    name: String,
    key: AttestedPasskey,
    fingerprint: [u8; 32],
}

struct Pending {
    account: Arc<Account>,
    authentication: AttestedPasskeyAuthentication,
    grant: Grant,
    generation: u64,
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
        identities_file: &Path,
        limits: &Limits,
    ) -> Result<Self> {
        Self::load(
            origin,
            state_dir,
            identities_file,
            limits,
            YubikeyPolicy::new()?,
        )
    }

    fn load(
        origin: &Url,
        state_dir: &Path,
        identities_file: &Path,
        limits: &Limits,
        yubikeys: YubikeyPolicy,
    ) -> Result<Self> {
        let webauthn = build_webauthn(origin)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(state_dir.join(".lock"))
            .context("open state lock")?;
        lock.try_lock().context("lock state directory")?;
        let counters_dir = state_dir.join("counters");
        fs::create_dir_all(&counters_dir).context("create counter directory")?;
        let (changes, _) = watch::channel(0);
        let mut auth = Self {
            origin: origin.clone(),
            webauthn,
            yubikeys,
            identities_file: identities_file.into(),
            counters_dir,
            accounts: RwLock::new(HashMap::new()),
            last_digest: Mutex::new([0; 32]),
            generation: AtomicU64::new(0),
            changes,
            challenges: Mutex::new(Challenges::new(limits)),
            _lock: lock,
        };
        let bytes = read_identities(identities_file)?;
        let verified = auth.verify_identities(&bytes)?;
        auth.accounts = RwLock::new(auth.load_accounts(verified, &HashMap::new())?);
        auth.last_digest = Mutex::new(sha256(&bytes));
        Ok(auth)
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub fn subscribe_generation(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }

    pub fn reload(&self) -> Result<bool> {
        let mut last = self
            .last_digest
            .lock()
            .map_err(|_| anyhow::anyhow!("identity reload lock poisoned"))?;
        let bytes = read_identities(&self.identities_file)?;
        let checksum = sha256(&bytes);
        if checksum == *last {
            return Ok(false);
        }
        let verified = self
            .verify_identities(&bytes)
            .inspect_err(|_| *last = checksum)?;
        let previous = self
            .accounts
            .read()
            .map_err(|_| anyhow::anyhow!("identity table poisoned"))?
            .clone();
        let next = self.load_accounts(verified, &previous)?;
        let revoked = previous.iter().any(|(name, account)| {
            next.get(name)
                .is_none_or(|retained| !Arc::ptr_eq(account, retained))
        });
        let changed = revoked || previous.len() != next.len();
        if changed {
            let mut accounts = self
                .accounts
                .write()
                .map_err(|_| anyhow::anyhow!("identity table poisoned"))?;
            *accounts = next;
            if revoked {
                let generation = self.generation.fetch_add(1, Ordering::Release) + 1;
                self.changes.send_replace(generation);
            }
        }
        *last = checksum;
        Ok(changed)
    }

    fn verify_identities(&self, contents: &[u8]) -> Result<Vec<VerifiedIdentity>> {
        let records: Vec<StaticIdentity> =
            serde_json::from_slice(contents).context("parse identities JSON array")?;
        let mut names = HashSet::new();
        let mut credential_ids = HashSet::new();
        let mut verified = Vec::with_capacity(records.len());
        for record in records {
            ensure!(
                names.insert(record.account.clone()),
                "duplicate identity account"
            );
            let key = record
                .verify_for(&self.origin, &self.webauthn, &self.yubikeys)
                .with_context(|| format!("verify YubiKey identity for {:?}", record.account))?;
            ensure!(
                credential_ids.insert(key.cred_id().clone()),
                "duplicate YubiKey credential ID"
            );
            let public_key = Credential::from(key.clone()).cred;
            let fingerprint = sha256(&serde_json::to_vec(&(key.cred_id(), public_key))?);
            verified.push(VerifiedIdentity {
                name: record.account,
                key,
                fingerprint,
            });
        }
        Ok(verified)
    }

    fn load_accounts(
        &self,
        verified: Vec<VerifiedIdentity>,
        previous: &HashMap<String, Arc<Account>>,
    ) -> Result<HashMap<String, Arc<Account>>> {
        let mut accounts = HashMap::with_capacity(verified.len());
        for VerifiedIdentity {
            name,
            key,
            fingerprint,
        } in verified
        {
            let account = match previous
                .get(&name)
                .filter(|account| account.digest == fingerprint)
            {
                Some(account) => account.clone(),
                None => Arc::new(Account::load(&self.counters_dir, key, fingerprint)?),
            };
            accounts.insert(name, account);
        }
        Ok(accounts)
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
        let name = name.unwrap_or(DEFAULT_ACCOUNT);
        if !valid_account_name(name) {
            return Err(ApiError(StatusCode::BAD_REQUEST, "invalid account name"));
        }
        let (account, generation) = {
            let accounts = self
                .accounts
                .read()
                .map_err(|_| ApiError::internal("identity table poisoned"))?;
            (
                accounts.get(name).ok_or(NOT_ALLOWED)?.clone(),
                self.generation(),
            )
        };
        let (options, authentication) = self
            .webauthn
            .start_attested_passkey_authentication(std::slice::from_ref(&account.key))
            .map_err(ApiError::internal)?;
        let challenge_id = lock(&self.challenges)?.insert(
            peer,
            Pending {
                account,
                authentication,
                grant,
                generation,
            },
        )?;
        Ok(Challenge {
            challenge_id,
            options,
        })
    }

    pub fn finish_login(
        &self,
        signed: SignedChallenge<PublicKeyCredential>,
    ) -> Result<(Grant, u64), ApiError> {
        let Pending {
            account,
            authentication,
            grant,
            generation,
        } = lock(&self.challenges)?.take(signed.challenge_id)?;
        if self.generation() != generation {
            return Err(UNAUTHORIZED);
        }
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
        let _accounts = self
            .accounts
            .read()
            .map_err(|_| ApiError::internal("identity table poisoned"))?;
        if self.generation() != generation {
            return Err(UNAUTHORIZED);
        }
        account.update_counter(result.counter())?;
        Ok((grant, generation))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientContext {
    #[serde(default)]
    cross_origin: bool,
    top_origin: Option<String>,
}

impl Account {
    fn load(directory: &Path, key: AttestedPasskey, digest: [u8; 32]) -> Result<Self> {
        let counter_file = directory.join(B64.encode(digest));
        let initial = Credential::from(key.clone()).counter;
        let counter = match fs::read_to_string(&counter_file) {
            Ok(stored) => stored
                .trim()
                .parse::<u32>()
                .context("parse YubiKey counter")?
                .max(initial),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => initial,
            Err(error) => return Err(error).context("read YubiKey counter"),
        };
        Ok(Self {
            key,
            digest,
            counter_file,
            counter: Mutex::new(counter),
        })
    }

    fn update_counter(&self, counter: u32) -> Result<(), ApiError> {
        let mut current = lock(&self.counter)?;
        if counter == 0 && *current == 0 {
            return Ok(());
        }
        if counter <= *current {
            return Err(UNAUTHORIZED);
        }
        let mut save = || -> Result<()> {
            let path = self
                .counter_file
                .parent()
                .context("missing counter directory")?;
            let dir = File::open(path)?;
            let mut file = tempfile::NamedTempFile::new_in(path)?;
            write!(file, "{counter}")?;
            file.as_file().sync_all()?;
            file.persist(&self.counter_file)?;
            *current = counter;
            dir.sync_all()?;
            Ok(())
        };
        save().map_err(ApiError::internal)
    }
}

fn build_webauthn(origin: &Url) -> Result<Webauthn> {
    validate_origin(origin)?;
    Ok(
        WebauthnBuilder::new(origin.domain().context("missing WebAuthn RP ID")?, origin)?
            .rp_name("Shomei")
            .timeout(CHALLENGE_TTL)
            .build()?,
    )
}

fn valid_account_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

pub fn provisioning_model(model: Uuid) -> bool {
    YUBIKEY_5_MODELS.contains(&model.to_string().as_str())
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    digest(&SHA256, bytes)
        .as_ref()
        .try_into()
        .expect("SHA-256 has 32 bytes")
}

fn read_identities(path: &Path) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    File::open(path)
        .with_context(|| format!("open identities file {}", path.display()))?
        .take(MAX_IDENTITIES_BYTES + 1)
        .read_to_end(&mut data)
        .context("read identities file")?;
    ensure!(
        data.len() as u64 <= MAX_IDENTITIES_BYTES,
        "identities file exceeds size limit"
    );
    Ok(data)
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
pub(crate) mod tests;
