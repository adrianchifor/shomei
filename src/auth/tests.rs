use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CustomExtension, DnType, IsCa, Issuer,
    KeyPair, KeyUsagePurpose, PublicKeyData, SigningKey, SubjectPublicKeyInfo,
};
use serde_cbor_2::Value::{self, Array, Bytes, Integer, Map, Text};
use serde_json::json;

use super::identity::IdentitySetup;
use super::*;

const ORIGIN: &str = "https://shomei.example:8443";
const RP: &str = "shomei.example";

#[test]
fn requires_genuine_attestation_and_binds_the_identity_to_account_and_origin() {
    let fixture = Fixture::new();
    let origin = Url::parse(ORIGIN).unwrap();
    let key = p256();
    let (options, setup) =
        IdentitySetup::prepare(&origin, "operator", YubikeyPolicy::new(false).unwrap()).unwrap();
    let untrusted = fixture.registration(&origin, &options, &key);
    assert!(setup.finish(untrusted).is_err());

    let (options, setup) = IdentitySetup::prepare(&origin, "operator", fixture.policy()).unwrap();
    assert!(
        setup
            .finish(registration(
                &origin,
                &options,
                &key,
                fixture.model,
                None,
                false
            ))
            .is_err()
    );

    let (options, setup) = IdentitySetup::prepare(&origin, "operator", fixture.policy()).unwrap();
    let wrong_model = registration(
        &origin,
        &options,
        &key,
        Uuid::nil(),
        Some((&fixture.leaf, &fixture.attestation_key)),
        false,
    );
    assert!(setup.finish(wrong_model).is_err());

    let record = fixture.provision(&origin, "operator", &key);
    let webauthn = build_webauthn(&origin).unwrap();
    let policy = fixture.policy();
    record.verify_for(&origin, &webauthn, &policy).unwrap();
    let mut old = serde_json::to_value(&record).unwrap();
    old["account"] = old
        .as_object_mut()
        .unwrap()
        .remove("attested_label")
        .unwrap();
    assert!(serde_json::from_value::<StaticIdentity>(old).is_err());
    let mut modified = serde_json::to_value(&record).unwrap();
    modified["attested_label"] = json!("other");
    let modified: StaticIdentity = serde_json::from_value(modified).unwrap();
    assert!(modified.verify_for(&origin, &webauthn, &policy).is_err());
    let alternate = Url::parse("https://shomei.example:9443").unwrap();
    let alternate_webauthn = build_webauthn(&alternate).unwrap();
    let mut modified = serde_json::to_value(&record).unwrap();
    modified["origin"] = json!(alternate);
    let modified: StaticIdentity = serde_json::from_value(modified).unwrap();
    assert!(
        modified
            .verify_for(&alternate, &alternate_webauthn, &policy)
            .is_err()
    );
}

#[test]
fn u2f_requires_localhost_a_trusted_yubikey_4_and_a_fresh_touch() {
    let fixture = Fixture::new();
    let (root, leaf, attestation_key) = u2f_fixture(true);
    let (other_root, other_leaf, other_key) = u2f_fixture(false);
    let origin = Url::parse("https://localhost:8443").unwrap();
    let remote = Url::parse(ORIGIN).unwrap();
    assert!(IdentitySetup::prepare(&remote, "operator", u2f_policy(&fixture, &root)).is_err());

    let key = p256();
    for policy in [
        u2f_policy(&fixture, &root),
        u2f_policy(&fixture, &other_root),
    ] {
        let (options, setup) = IdentitySetup::prepare(&origin, "operator", policy).unwrap();
        let response = registration(
            &origin,
            &options,
            &key,
            Uuid::nil(),
            Some((&other_leaf, &other_key)),
            true,
        );
        assert!(setup.finish(response).is_err());
    }
    let (options, setup) =
        IdentitySetup::prepare(&origin, "operator", u2f_policy(&fixture, &root)).unwrap();
    let response = registration(
        &origin,
        &options,
        &key,
        Uuid::nil(),
        Some((&leaf, &attestation_key)),
        true,
    );
    let record = setup.finish(response).unwrap();
    assert!(
        record
            .verify_for(
                &origin,
                &build_webauthn(&origin).unwrap(),
                &fixture.policy()
            )
            .is_err()
    );

    let dir = tempfile::tempdir().unwrap();
    let identities_file = dir.path().join("identities.json");
    write_records(&identities_file, &[&record]);
    let auth = Auth::load(
        &origin,
        dir.path(),
        &identities_file,
        &Limits::default(),
        u2f_policy(&fixture, &root),
    )
    .unwrap();
    let peer = "127.0.0.1".parse().unwrap();
    let challenge = auth.start_login(Grant::Http, peer).unwrap();
    let response = |flags| SignedChallenge {
        challenge_id: challenge.challenge_id,
        credential: assertion_at(
            &origin,
            &challenge.options.public_key.challenge,
            &key,
            flags,
            1,
        ),
    };
    assert!(auth.finish_login(response(0)).is_err());
    assert!(auth.finish_login(response(1)).is_err());

    let fido2 = p256();
    let fido2_record = fixture.provision(&origin, ACCOUNT, &fido2);
    write_records(&identities_file, &[&record, &fido2_record]);
    assert!(auth.reload().unwrap());
    let approve = |key, flags| {
        let challenge = auth.start_login(Grant::Http, peer).unwrap();
        assert_eq!(
            challenge.options.public_key.user_verification,
            UserVerificationPolicy::Preferred
        );
        assert_eq!(challenge.options.public_key.allow_credentials.len(), 2);
        auth.finish_login(SignedChallenge {
            challenge_id: challenge.challenge_id,
            credential: assertion_at(
                &origin,
                &challenge.options.public_key.challenge,
                key,
                flags,
                1,
            ),
        })
    };
    assert!(approve(&fido2, 0x01).is_err());
    assert!(approve(&fido2, 0x05).is_ok());
    assert!(approve(&key, 0x01).is_ok());
}

#[test]
fn reloads_identities_and_consumes_single_use_challenges() {
    let fixture = Fixture::new();
    let dir = tempfile::tempdir().unwrap();
    let allowlist = dir.path().join("identities.json");
    fs::write(&allowlist, "").unwrap();
    let origin = Url::parse(ORIGIN).unwrap();
    let limits = Limits {
        pending_per_ip: 8,
        ..Limits::default()
    };
    let peer = "127.0.0.1".parse().unwrap();
    let auth = Auth::load(&origin, dir.path(), &allowlist, &limits, fixture.policy()).unwrap();
    let mut epoch = auth.subscribe_generation();
    assert!(!auth.reload().unwrap());
    assert!(auth.start_login(Grant::Http, peer).is_err());
    fs::write(&allowlist, "[]").unwrap();
    let (changed, rejected) = auth.reload_identities().unwrap();
    assert!(!changed);
    assert!(format!("{:#}", rejected[0]).contains("expected a shomei-id-v1 token"));

    let operator = p256();
    let alice = p256();
    let operator_record = fixture.provision(&origin, "operator", &operator);
    let alice_record = fixture.provision(&origin, ACCOUNT, &alice);
    write_records(&allowlist, &[&operator_record]);
    assert!(auth.reload().unwrap());
    assert_eq!(auth.generation(), 0);
    assert!(auth.devices.read().unwrap().values().all(|device| matches!(
        device.key.credential().attestation.data,
        ParsedAttestationData::None
    )));

    let operator_token = encode_identity(&operator_record).unwrap();
    let alice_token = encode_identity(&alice_record).unwrap();
    fs::write(
        &allowlist,
        format!("# Deployment keys\r\n\r\n{operator_token} # operator\r\n"),
    )
    .unwrap();
    assert!(!auth.reload().unwrap());
    assert_eq!(auth.generation(), 0);

    let challenge = auth.start_login(Grant::Http, peer).unwrap();
    assert!(
        auth.finish_login(assertion(&challenge, &operator, 0x01, 1))
            .is_err()
    );
    assert!(
        auth.finish_login(assertion(&challenge, &operator, 0x05, 1))
            .is_err()
    );
    let previous = auth.start_login(Grant::Http, peer).unwrap();
    let tcp_key = p256();
    let public_key = SubjectPublicKeyInfo::from_der(&tcp_key.subject_public_key_info()).unwrap();
    let challenge = auth.start_login(Grant::Tcp(public_key), peer).unwrap();
    let (Grant::Tcp(granted), 0) = auth
        .finish_login(assertion(&challenge, &operator, 0x05, 2))
        .unwrap()
    else {
        panic!("expected TCP grant");
    };
    assert_eq!(granted.der_bytes(), tcp_key.der_bytes());
    assert!(
        auth.finish_login(assertion(&previous, &operator, 0x05, 1))
            .is_err()
    );

    let challenge = auth.start_login(Grant::Http, peer).unwrap();
    fs::write(&allowlist, format!("{operator_token}\n{alice_token}\n")).unwrap();
    assert!(auth.reload().unwrap());
    assert_eq!(auth.generation(), 0);
    assert!(matches!(
        auth.finish_login(assertion(&challenge, &operator, 0x05, 3)),
        Ok((Grant::Http, 0))
    ));
    assert!(!epoch.has_changed().unwrap());
    assert!(!auth.reload().unwrap());

    fs::write(
        &allowlist,
        format!("{operator_token}\n{alice_token}\n{operator_token}\n"),
    )
    .unwrap();
    let (changed, rejected) = auth.reload_identities().unwrap();
    assert!(!changed);
    assert_eq!(rejected.len(), 1);
    assert!(
        format!("{:#}", rejected[0])
            .contains("identity on line 3: duplicate YubiKey credential ID")
    );
    assert_eq!(auth.generation(), 0);

    // Only a file that cannot be read at all keeps the last list.
    fs::remove_file(&allowlist).unwrap();
    fs::create_dir(&allowlist).unwrap();
    assert!(auth.reload().is_err());
    assert!(auth.reload().is_err());
    assert_eq!(auth.generation(), 0);
    fs::remove_dir(&allowlist).unwrap();
    fs::write(
        &allowlist,
        [
            operator_token.as_bytes(),
            b"\n\xff\xfe\n",
            alice_token.as_bytes(),
        ]
        .concat(),
    )
    .unwrap();
    let (changed, rejected) = auth.reload_identities().unwrap();
    assert!(!changed);
    assert!(format!("{:#}", rejected[0]).contains("identity on line 2: identity is not UTF-8"));
    assert_eq!(auth.generation(), 0);
    let challenge = auth.start_login(Grant::Http, peer).unwrap();
    assert!(matches!(
        auth.finish_login(assertion(&challenge, &alice, 0x05, 1)),
        Ok((Grant::Http, 0))
    ));

    let challenge = auth.start_login(Grant::Http, peer).unwrap();
    let mut unsigned = serde_json::to_value(&alice_record).unwrap();
    unsigned["attested_label"] = json!("renamed");
    let unsigned: StaticIdentity = serde_json::from_value(unsigned).unwrap();
    let unsigned = encode_identity(&unsigned).unwrap();
    fs::write(&allowlist, format!("{alice_token}\n{unsigned}\n")).unwrap();
    let (changed, rejected) = auth.reload_identities().unwrap();
    assert!(changed);
    assert_eq!(rejected.len(), 1);
    assert!(format!("{:#}", rejected[0]).contains("identity on line 2"));
    assert_eq!(*epoch.borrow_and_update(), 1);
    assert!(
        auth.finish_login(assertion(&challenge, &operator, 0x05, 4))
            .is_err()
    );
    let challenge = auth.start_login(Grant::Http, peer).unwrap();
    assert_eq!(challenge.options.public_key.allow_credentials.len(), 1);
    assert!(
        auth.finish_login(assertion(&challenge, &operator, 0x05, 4))
            .is_err()
    );

    write_records(&allowlist, &[&alice_record, &operator_record]);
    assert!(auth.reload().unwrap());
    assert_eq!(auth.generation(), 1);
    let challenge = auth.start_login(Grant::Http, peer).unwrap();
    assert!(
        auth.finish_login(assertion(&challenge, &operator, 0x05, 3))
            .is_err()
    );

    let challenge = auth.start_login(Grant::Http, peer).unwrap();
    let mut response = assertion(&challenge, &operator, 0x05, 4);
    let client = json!({"type": "webauthn.get", "origin": ORIGIN, "crossOrigin": true,
        "challenge": B64.encode(&challenge.options.public_key.challenge)});
    let client = serde_json::to_vec(&client).unwrap();
    response.credential.response.signature = sign(&operator, &auth_data(RP, 0x05, 4), &client);
    response.credential.response.client_data_json = client;
    assert!(auth.finish_login(response).is_err());

    let challenge = auth.start_login(Grant::Http, peer).unwrap();
    assert!(
        auth.finish_login(assertion(&challenge, &operator, 0x15, 4))
            .is_err()
    );

    for _ in 0..limits.pending_per_ip {
        auth.start_login(Grant::Http, peer).unwrap();
    }
    assert_eq!(
        auth.check_challenge_capacity(peer).unwrap_err().0,
        StatusCode::TOO_MANY_REQUESTS
    );
    auth.check_challenge_capacity("127.0.0.2".parse().unwrap())
        .unwrap();

    // Deleting the allowlist revokes every key.
    let generation = auth.generation();
    fs::remove_file(&allowlist).unwrap();
    let (changed, rejected) = auth.reload_identities().unwrap();
    assert!(changed);
    assert!(format!("{:#}", rejected[0]).contains("is missing"));
    assert_eq!(auth.generation(), generation + 1);
    assert!(auth.devices.read().unwrap().is_empty());
    assert!(!auth.reload().unwrap());
}

#[test]
fn a_full_challenge_store_evicts_from_the_peer_holding_the_most() {
    let limits = Limits {
        pending_challenges: 4,
        pending_per_ip: 3,
        ..Limits::default()
    };
    let mut challenges = Challenges::<()>::new(&limits);
    let [flood, operator, other]: [IpAddr; 3] =
        ["192.0.2.1", "192.0.2.2", "192.0.2.3"].map(|ip| ip.parse().unwrap());
    let oldest = challenges.insert(flood, ()).unwrap();
    let kept = [(); 2].map(|()| challenges.insert(flood, ()).unwrap());
    assert_eq!(
        challenges.check_capacity(flood).unwrap_err().0,
        StatusCode::TOO_MANY_REQUESTS
    );
    let pending = challenges.insert(operator, ()).unwrap();

    challenges.check_capacity(other).unwrap();
    assert_eq!(challenges.values.len(), 4);
    let admitted = challenges.insert(other, ()).unwrap();
    assert_eq!(challenges.values.len(), 4);
    assert!(challenges.take(oldest).is_err());

    assert_eq!(
        challenges.insert(flood, ()).unwrap_err().0,
        StatusCode::TOO_MANY_REQUESTS
    );
    for id in [pending, admitted, kept[0], kept[1]] {
        challenges.take(id).unwrap();
    }
    assert!(challenges.peers.is_empty() && challenges.expirations.is_empty());
}

struct Fixture {
    root: Certificate,
    intermediate: Certificate,
    leaf: Certificate,
    attestation_key: KeyPair,
    model: Uuid,
}

impl Fixture {
    fn new() -> Self {
        let root_key = p256();
        let mut params = certificate("Fixture CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let root = params.self_signed(&root_key).unwrap();
        let root_issuer = Issuer::new(params, root_key);
        let issuer_key = p256();
        let mut params = certificate("Fixture FIDO CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let intermediate = params.signed_by(&issuer_key, &root_issuer).unwrap();
        let issuer = Issuer::new(params, issuer_key);
        let attestation_key = p256();
        let leaf = certificate("Fixture")
            .signed_by(&attestation_key, &issuer)
            .unwrap();
        let model = Uuid::parse_str(YUBIKEY_5_MODELS[0]).unwrap();
        Self {
            root,
            intermediate,
            leaf,
            attestation_key,
            model,
        }
    }

    fn policy(&self) -> YubikeyPolicy {
        let mut roots = AttestationCaListBuilder::new();
        roots
            .insert_device_der(
                self.root.der(),
                self.model,
                "Test key".into(),
                Default::default(),
            )
            .unwrap();
        YubikeyPolicy {
            roots: roots.build(),
            paths: vec![AttestationPath {
                issuer: self.intermediate.der().clone(),
                intermediates: vec![self.intermediate.der().clone()],
            }],
            u2f: None,
        }
    }

    fn registration(
        &self,
        origin: &Url,
        options: &CreationChallengeResponse,
        key: &KeyPair,
    ) -> RegisterPublicKeyCredential {
        registration(
            origin,
            options,
            key,
            self.model,
            Some((&self.leaf, &self.attestation_key)),
            false,
        )
    }

    fn provision(&self, origin: &Url, name: &str, key: &KeyPair) -> StaticIdentity {
        let (options, setup) = IdentitySetup::prepare(origin, name, self.policy()).unwrap();
        setup
            .finish(self.registration(origin, &options, key))
            .unwrap()
    }
}

fn write_records(path: &Path, records: &[&StaticIdentity]) {
    let tokens: Vec<_> = records
        .iter()
        .map(|record| encode_identity(record).unwrap())
        .collect();
    fs::write(path, tokens.join("\n")).unwrap();
}

fn registration(
    origin: &Url,
    challenge: &CreationChallengeResponse,
    key: &KeyPair,
    model: Uuid,
    attestation: Option<(&Certificate, &KeyPair)>,
    u2f: bool,
) -> RegisterPublicKeyCredential {
    let client = client_data(origin, &challenge.public_key.challenge, "webauthn.create");
    let public_key = key.der_bytes();
    let id = hash(public_key);
    let cose = Map([
        (Integer(1), Integer(2)),
        (Integer(3), Integer(ES256.into())),
        (Integer(-1), Integer(1)),
        (Integer(-2), Bytes(public_key[1..33].to_vec())),
        (Integer(-3), Bytes(public_key[33..].to_vec())),
    ]
    .into());
    let mut data = auth_data(origin.domain().unwrap(), if u2f { 0x41 } else { 0x45 }, 0);
    data.extend_from_slice(model.as_bytes());
    data.extend_from_slice(&(id.len() as u16).to_be_bytes());
    data.extend_from_slice(&id);
    data.extend(serde_cbor_2::to_vec(&cose).unwrap());
    let (format, statement) = if let Some((cert, attestation_key)) = attestation.filter(|_| u2f) {
        let message = [&[0], &data[..32], &hash(&client)[..], &id, public_key].concat();
        (
            "fido-u2f",
            object([
                ("sig", Bytes(attestation_key.sign(&message).unwrap())),
                ("x5c", Array(vec![Bytes(cert.der().to_vec())])),
            ]),
        )
    } else if let Some((cert, attestation_key)) = attestation {
        (
            "packed",
            object([
                ("alg", Integer(-7)),
                ("sig", Bytes(sign(attestation_key, &data, &client))),
                ("x5c", Array(vec![Bytes(cert.der().to_vec())])),
            ]),
        )
    } else {
        ("none", object([]))
    };
    let object = object([
        ("fmt", Text(format.into())),
        ("authData", Bytes(data)),
        ("attStmt", statement),
    ]);
    serde_json::from_value(json!({
        "id": B64.encode(id), "rawId": B64.encode(id), "type": "public-key",
        "response": {
            "clientDataJSON": B64.encode(client),
            "attestationObject": B64.encode(serde_cbor_2::to_vec(&object).unwrap()),
        },
    }))
    .unwrap()
}

pub(crate) struct TestSigner {
    origin: Url,
    key: KeyPair,
    flags: u8,
}

impl TestSigner {
    pub(crate) fn sign(&self, challenge: &[u8], counter: u32) -> PublicKeyCredential {
        assertion_at(&self.origin, challenge, &self.key, self.flags, counter)
    }
}

pub(crate) fn test_auth(
    origin: &Url,
    state_dir: &Path,
    identities_file: &Path,
    limits: &Limits,
    u2f: bool,
) -> (Auth, TestSigner) {
    let fixture = Fixture::new();
    let key = p256();
    let (record, policy, flags) = if u2f {
        let (root, leaf, signing_key) = u2f_fixture(true);
        let (options, setup) =
            IdentitySetup::prepare(origin, "operator", u2f_policy(&fixture, &root)).unwrap();
        let record = setup
            .finish(registration(
                origin,
                &options,
                &key,
                Uuid::nil(),
                Some((&leaf, &signing_key)),
                true,
            ))
            .unwrap();
        (record, u2f_policy(&fixture, &root), 0x01)
    } else {
        (
            fixture.provision(origin, "operator", &key),
            fixture.policy(),
            0x05,
        )
    };
    write_records(identities_file, &[&record]);
    let auth = Auth::load(origin, state_dir, identities_file, limits, policy).unwrap();
    (
        auth,
        TestSigner {
            origin: origin.clone(),
            key,
            flags,
        },
    )
}

fn u2f_fixture(yubikey_4: bool) -> (Certificate, Certificate, KeyPair) {
    let root_key = p256();
    let mut root = certificate("Fixture U2F CA");
    root.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    root.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let cert = root.self_signed(&root_key).unwrap();
    let issuer = Issuer::new(root, root_key);
    let signing_key = p256();
    let mut leaf = certificate("Fixture U2F key");
    if yubikey_4 {
        leaf.custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 41482, 2],
                b"1.3.6.1.4.1.41482.1.5".to_vec(),
            ));
    }
    (
        cert,
        leaf.signed_by(&signing_key, &issuer).unwrap(),
        signing_key,
    )
}

fn u2f_policy(fixture: &Fixture, root: &Certificate) -> YubikeyPolicy {
    let mut policy = fixture.policy();
    policy.u2f = Some(U2fPolicy::from_pem(root.pem().as_bytes()).unwrap());
    policy
}

fn assertion(
    challenge: &Challenge<RequestChallengeResponse>,
    key: &KeyPair,
    flags: u8,
    counter: u32,
) -> SignedChallenge<PublicKeyCredential> {
    SignedChallenge {
        challenge_id: challenge.challenge_id,
        credential: assertion_at(
            &Url::parse(ORIGIN).unwrap(),
            &challenge.options.public_key.challenge,
            key,
            flags,
            counter,
        ),
    }
}

fn assertion_at(
    origin: &Url,
    challenge: &[u8],
    key: &KeyPair,
    flags: u8,
    counter: u32,
) -> PublicKeyCredential {
    let client = client_data(origin, challenge, "webauthn.get");
    let data = auth_data(origin.domain().unwrap(), flags, counter);
    let id = hash(key.der_bytes());
    serde_json::from_value(json!({
        "id": B64.encode(id), "rawId": B64.encode(id), "type": "public-key",
        "response": {
            "clientDataJSON": B64.encode(&client),
            "authenticatorData": B64.encode(&data),
            "signature": B64.encode(sign(key, &data, &client)),
        },
    }))
    .unwrap()
}

fn object<const N: usize>(pairs: [(&str, Value); N]) -> Value {
    Map(pairs
        .into_iter()
        .map(|(key, value)| (Text(key.into()), value))
        .collect())
}

fn client_data(origin: &Url, challenge: &[u8], kind: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({"type": kind, "origin": origin.origin().ascii_serialization(), "challenge": B64.encode(challenge)}))
        .unwrap()
}

fn auth_data(rp: &str, flags: u8, counter: u32) -> Vec<u8> {
    [
        hash(rp.as_bytes()).as_slice(),
        &[flags],
        &counter.to_be_bytes(),
    ]
    .concat()
}

fn sign(key: &KeyPair, data: &[u8], client: &[u8]) -> Vec<u8> {
    key.sign(&[data, &hash(client)].concat()).unwrap()
}

fn hash(data: &[u8]) -> [u8; 32] {
    digest(&SHA256, data).as_ref().try_into().unwrap()
}

fn p256() -> KeyPair {
    KeyPair::generate().unwrap()
}

fn certificate(common_name: &str) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CountryName, "SE");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Test");
    params
        .distinguished_name
        .push(DnType::OrganizationalUnitName, "Authenticator Attestation");
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.is_ca = IsCa::ExplicitNoCa;
    params
}
