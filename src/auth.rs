mod identity;
mod identity_list;
mod u2f;

pub use identity::{StaticIdentity, prepare_identity};
pub use identity_list::encode_identity;

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
use webauthn_rs_proto::UserVerificationPolicy;
use x509_parser::{oid_registry::*, parse_x509_certificate};

use crate::config::{Limits, validate_origin};
use u2f::U2fPolicy;

const CHALLENGE_TTL: Duration = Duration::from_secs(120);
pub const ACCOUNT: &str = "shomei";
const ES256: i64 = -7;
const MAX_IDENTITIES_BYTES: u64 = 64 * 1024 * 1024;
const UNAUTHORIZED: ApiError = ApiError(StatusCode::UNAUTHORIZED, "YubiKey verification failed");
const NOT_ALLOWED: ApiError = ApiError(StatusCode::FORBIDDEN, "No YubiKey is enrolled");

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
    devices: RwLock<HashMap<CredentialID, Arc<Device>>>,
    last_digest: Mutex<[u8; 32]>,
    generation: AtomicU64,
    changes: watch::Sender<u64>,
    challenges: Mutex<Challenges>,
    _lock: File,
}

struct Device {
    key: DeviceKey,
    digest: [u8; 32],
    counter_file: PathBuf,
    counter: Mutex<u32>,
}

struct VerifiedIdentity {
    key: DeviceKey,
    fingerprint: [u8; 32],
}

struct Pending {
    authentication: Login,
    grant: Grant,
    generation: u64,
}

enum DeviceKey {
    Fido2(AttestedPasskey),
    U2f(SecurityKey),
}

impl DeviceKey {
    fn cred_id(&self) -> &CredentialID {
        match self {
            Self::Fido2(key) => key.cred_id(),
            Self::U2f(key) => key.cred_id(),
        }
    }

    fn credential(&self) -> Credential {
        match self {
            Self::Fido2(key) => key.clone().into(),
            Self::U2f(key) => key.clone().into(),
        }
    }
}

enum Login {
    Fido2(AttestedPasskeyAuthentication),
    SecurityKeys(SecurityKeyAuthentication),
}

pub enum Grant {
    Http,
    HttpHost(crate::config::Endpoint),
    BrowserLogin {
        host: crate::config::Endpoint,
        next: String,
    },
    BrowserApproval(crate::http::approval::Intent),
    Tcp(SubjectPublicKeyInfo),
    Forward {
        key: SubjectPublicKeyInfo,
        scope: usize,
    },
    ForwardHttp {
        scope: usize,
    },
    Tailscale(crate::tailscale::Device),
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
        allow_yubikey_4: bool,
    ) -> Result<Self> {
        Self::load(
            origin,
            state_dir,
            identities_file,
            limits,
            YubikeyPolicy::new(allow_yubikey_4)?,
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
            devices: RwLock::new(HashMap::new()),
            last_digest: Mutex::new([0; 32]),
            generation: AtomicU64::new(0),
            changes,
            challenges: Mutex::new(Challenges::new(limits)),
            _lock: lock,
        };
        let bytes = read_identities(identities_file)?;
        let verified = auth.verify_identities(&bytes)?;
        auth.devices = RwLock::new(auth.load_devices(verified, &HashMap::new())?);
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
            .devices
            .read()
            .map_err(|_| anyhow::anyhow!("identity table poisoned"))?
            .clone();
        let next = self.load_devices(verified, &previous)?;
        let revoked = previous.iter().any(|(id, device)| {
            next.get(id)
                .is_none_or(|retained| !Arc::ptr_eq(device, retained))
        });
        let changed = revoked || previous.len() != next.len();
        if changed {
            let mut devices = self
                .devices
                .write()
                .map_err(|_| anyhow::anyhow!("identity table poisoned"))?;
            *devices = next;
            if revoked {
                let generation = self.generation.fetch_add(1, Ordering::Release) + 1;
                self.changes.send_replace(generation);
            }
        }
        *last = checksum;
        Ok(changed)
    }

    fn verify_identities(&self, contents: &[u8]) -> Result<Vec<VerifiedIdentity>> {
        let mut credential_ids = HashSet::new();
        let mut verified = Vec::new();
        identity_list::visit_identities(contents, |record| {
            let key = record
                .verify_for(&self.origin, &self.webauthn, &self.yubikeys)
                .context("verify YubiKey identity")?;
            ensure!(
                credential_ids.insert(key.cred_id().clone()),
                "duplicate YubiKey credential ID"
            );
            let public_key = key.credential().cred;
            let fingerprint = sha256(&serde_json::to_vec(&(key.cred_id(), public_key))?);
            verified.push(VerifiedIdentity { key, fingerprint });
            Ok(())
        })?;
        Ok(verified)
    }

    fn load_devices(
        &self,
        verified: Vec<VerifiedIdentity>,
        previous: &HashMap<CredentialID, Arc<Device>>,
    ) -> Result<HashMap<CredentialID, Arc<Device>>> {
        let mut devices = HashMap::with_capacity(verified.len());
        for VerifiedIdentity { key, fingerprint } in verified {
            let id = key.cred_id().clone();
            let device = match previous.get(&id).filter(|device| {
                device.digest == fingerprint
                    && std::mem::discriminant(&device.key) == std::mem::discriminant(&key)
            }) {
                Some(device) => device.clone(),
                None => Arc::new(Device::load(&self.counters_dir, key, fingerprint)?),
            };
            devices.insert(id, device);
        }
        Ok(devices)
    }

    pub fn check_challenge_capacity(&self, peer: IpAddr) -> Result<(), ApiError> {
        lock(&self.challenges)?.check_capacity(peer)
    }

    pub fn start_login(
        &self,
        grant: Grant,
        peer: IpAddr,
    ) -> Result<Challenge<RequestChallengeResponse>, ApiError> {
        let (options, authentication, generation) = {
            let devices = self
                .devices
                .read()
                .map_err(|_| ApiError::internal("identity table poisoned"))?;
            if devices.is_empty() {
                return Err(NOT_ALLOWED);
            }
            let strict: Vec<_> = devices
                .values()
                .filter_map(|device| match &device.key {
                    DeviceKey::Fido2(key) => Some(key.clone()),
                    DeviceKey::U2f(_) => None,
                })
                .collect();
            let (options, authentication) = if strict.len() == devices.len() {
                self.webauthn
                    .start_attested_passkey_authentication(&strict)
                    .map(|(options, login)| (options, Login::Fido2(login)))
            } else {
                let keys: Vec<_> = devices
                    .values()
                    .map(|device| device.key.credential().into())
                    .collect();
                self.webauthn
                    .start_securitykey_authentication(&keys)
                    .map(|(mut options, login)| {
                        if !strict.is_empty() {
                            options.public_key.user_verification =
                                UserVerificationPolicy::Preferred;
                        }
                        (options, Login::SecurityKeys(login))
                    })
            }
            .map_err(ApiError::internal)?;
            (options, authentication, self.generation())
        };
        let challenge_id = lock(&self.challenges)?.insert(
            peer,
            Pending {
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
        let result = match &authentication {
            Login::Fido2(login) => self
                .webauthn
                .finish_attested_passkey_authentication(&signed.credential, login),
            Login::SecurityKeys(login) => self
                .webauthn
                .finish_securitykey_authentication(&signed.credential, login),
        }
        .map_err(|_| UNAUTHORIZED)?;
        let flags = signed.credential.response.authenticator_data.get(32);
        if !flags.is_some_and(|flags| flags & 0x01 == 0x01)
            || result.backup_eligible()
            || result.backup_state()
        {
            return Err(UNAUTHORIZED);
        }
        let devices = self
            .devices
            .read()
            .map_err(|_| ApiError::internal("identity table poisoned"))?;
        if self.generation() != generation {
            return Err(UNAUTHORIZED);
        }
        let device = devices.get(result.cred_id()).ok_or(UNAUTHORIZED)?;
        if matches!(&device.key, DeviceKey::Fido2(_)) && !result.user_verified() {
            return Err(UNAUTHORIZED);
        }
        device.update_counter(result.counter())?;
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

impl Device {
    fn load(directory: &Path, key: DeviceKey, digest: [u8; 32]) -> Result<Self> {
        let counter_file = directory.join(B64.encode(digest));
        let initial = key.credential().counter;
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
            .danger_set_user_presence_only_security_keys(true)
            .build()?,
    )
}

fn valid_attested_label(name: &str) -> bool {
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

struct Challenges<T = Pending> {
    values: HashMap<Uuid, (Instant, IpAddr, T)>,
    expirations: BTreeSet<(Instant, Uuid)>,
    peers: HashMap<IpAddr, BTreeSet<(Instant, Uuid)>>,
    limit: usize,
    per_ip: usize,
}

impl<T> Challenges<T> {
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
        self.reserve(peer).map(drop)
    }

    /// Admits one more challenge for `peer`. When the store is full, returns
    /// the challenge to evict: the oldest one of the peer holding the most.
    /// A peer that already holds the most is refused, so filling the store
    /// only costs a client its own challenges.
    fn reserve(&mut self, peer: IpAddr) -> Result<Option<Uuid>, ApiError> {
        const BUSY: ApiError =
            ApiError(StatusCode::TOO_MANY_REQUESTS, "too many pending challenges");
        let now = Instant::now();
        while let Some(&(expires, id)) = self.expirations.first() {
            if expires > now {
                break;
            }
            self.remove(id);
        }
        let held = self.peers.get(&peer).map_or(0, BTreeSet::len);
        if held >= self.per_ip {
            return Err(BUSY);
        }
        if self.values.len() < self.limit {
            return Ok(None);
        }
        self.peers
            .values()
            .filter(|pending| pending.len() > held)
            .filter_map(|pending| Some((pending.len(), *pending.first()?)))
            .max_by_key(|&(count, (expires, _))| (count, std::cmp::Reverse(expires)))
            .map(|(_, (_, id))| Some(id))
            .ok_or(BUSY)
    }

    fn insert(&mut self, peer: IpAddr, pending: T) -> Result<Uuid, ApiError> {
        if let Some(evicted) = self.reserve(peer)? {
            self.remove(evicted);
        }
        let id = Uuid::new_v4();
        let expires = Instant::now() + CHALLENGE_TTL;
        self.values.insert(id, (expires, peer, pending));
        self.expirations.insert((expires, id));
        self.peers.entry(peer).or_default().insert((expires, id));
        Ok(id)
    }

    fn remove(&mut self, id: Uuid) -> Option<(Instant, T)> {
        let (expires, peer, pending) = self.values.remove(&id)?;
        self.expirations.remove(&(expires, id));
        if let Some(held) = self.peers.get_mut(&peer) {
            held.remove(&(expires, id));
            if held.is_empty() {
                self.peers.remove(&peer);
            }
        }
        Some((expires, pending))
    }

    fn take(&mut self, id: Uuid) -> Result<T, ApiError> {
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
    u2f: Option<U2fPolicy>,
}

struct AttestationPath {
    issuer: CertificateDer<'static>,
    intermediates: Vec<CertificateDer<'static>>,
}

impl YubikeyPolicy {
    fn new(allow_yubikey_4: bool) -> Result<Self> {
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
            u2f: allow_yubikey_4.then(U2fPolicy::new).transpose()?,
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
