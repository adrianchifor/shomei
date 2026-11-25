use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PublicKeyData, SigningKey, SubjectPublicKeyInfo,
};
use serde_cbor_2::Value::{self, Array, Bytes, Integer, Map, Text};
use serde_json::json;

use super::*;

const ORIGIN: &str = "https://shomei.example:8443";
const RP: &str = "shomei.example";
const TOKEN: &str = "0123456789abcdef0123456789abcdef";
const SECOND_TOKEN: &str = "fedcba9876543210fedcba9876543210";

#[test]
fn verifies_attestation_and_consumes_challenges() {
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("token");
    fs::write(&token, TOKEN).unwrap();
    let origin = Url::parse(ORIGIN).unwrap();
    let peers = Limits {
        pending_per_ip: 8,
        ..Limits::default()
    };
    let peer = "127.0.0.1".parse().unwrap();
    let tokens = dir.path().join("tokens.toml");
    fs::write(&tokens, format!("alice = {SECOND_TOKEN:?}")).unwrap();
    let mut auth = Auth::new(&origin, dir.path(), Some(&token), Some(&tokens), &peers).unwrap();
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
    let signing_key = p256();
    let model = Uuid::parse_str(YUBIKEY_5_MODELS[0]).unwrap();

    assert!(auth.start_enroll(None, Some("wrong-token"), peer).is_err());
    let challenge = auth.start_enroll(None, Some(TOKEN), peer).unwrap();
    let unsigned = registration(&challenge, &signing_key, model, None);
    assert!(auth.finish_enroll(Some(TOKEN), unsigned).is_err());
    let challenge = auth.start_enroll(None, Some(TOKEN), peer).unwrap();
    let untrusted = registration(
        &challenge,
        &signing_key,
        model,
        Some((&leaf, &attestation_key)),
    );
    assert!(auth.finish_enroll(Some(TOKEN), untrusted).is_err());

    let mut roots = AttestationCaListBuilder::new();
    roots
        .insert_device_der(root.der(), model, "Test key".into(), Default::default())
        .unwrap();
    auth.yubikeys = YubikeyPolicy {
        roots: roots.build(),
        paths: vec![AttestationPath {
            issuer: intermediate.der().clone(),
            intermediates: vec![intermediate.der().clone()],
        }],
    };
    let challenge = auth.start_enroll(None, Some(TOKEN), peer).unwrap();
    let wrong_model = registration(
        &challenge,
        &signing_key,
        Uuid::nil(),
        Some((&leaf, &attestation_key)),
    );
    assert!(auth.finish_enroll(Some(TOKEN), wrong_model).is_err());
    let challenge = auth.start_enroll(None, Some(TOKEN), peer).unwrap();
    let approved = registration(
        &challenge,
        &signing_key,
        model,
        Some((&leaf, &attestation_key)),
    );
    auth.finish_enroll(Some(TOKEN), approved).unwrap();
    assert!(auth.start_enroll(None, Some(TOKEN), peer).is_err());

    let challenge = auth.start_login(None, Grant::Http, peer).unwrap();
    assert!(
        auth.finish_login(assertion(&challenge, &signing_key, 0x01, 1))
            .is_err()
    );
    assert!(
        auth.finish_login(assertion(&challenge, &signing_key, 0x05, 1))
            .is_err()
    );
    let tcp_key = p256();
    let public_key = SubjectPublicKeyInfo::from_der(&tcp_key.subject_public_key_info()).unwrap();
    let older = auth.start_login(None, Grant::Http, peer).unwrap();
    let challenge = auth
        .start_login(None, Grant::Tcp(public_key), peer)
        .unwrap();
    let Grant::Tcp(granted_key) = auth
        .finish_login(assertion(&challenge, &signing_key, 0x05, 2))
        .unwrap()
    else {
        panic!("expected TCP grant");
    };
    assert_eq!(granted_key.der_bytes(), tcp_key.der_bytes());
    assert!(
        auth.finish_login(assertion(&challenge, &signing_key, 0x05, 3))
            .is_err()
    );
    assert!(
        auth.finish_login(assertion(&older, &signing_key, 0x05, 1))
            .is_err()
    );
    let challenge = auth.start_login(None, Grant::Http, peer).unwrap();
    assert!(matches!(
        auth.finish_login(assertion(&challenge, &signing_key, 0x05, 3)),
        Ok(Grant::Http)
    ));
    let saved: AttestedPasskey =
        serde_json::from_reader(File::open(&auth.accounts[DEFAULT_ACCOUNT].file).unwrap()).unwrap();
    assert_eq!(Credential::from(saved).counter, 3);

    let alice_key = p256();
    assert!(auth.start_enroll(Some("alice"), Some(TOKEN), peer).is_err());
    let challenge = auth
        .start_enroll(Some("alice"), Some(SECOND_TOKEN), peer)
        .unwrap();
    let approved = registration(
        &challenge,
        &alice_key,
        model,
        Some((&leaf, &attestation_key)),
    );
    auth.finish_enroll(Some(SECOND_TOKEN), approved).unwrap();
    let challenge = auth.start_login(Some("alice"), Grant::Http, peer).unwrap();
    assert!(matches!(
        auth.finish_login(assertion(&challenge, &alice_key, 0x05, 1)),
        Ok(Grant::Http)
    ));
    assert!(auth.accounts["alice"].file.is_file());

    let challenge = auth.start_login(None, Grant::Http, peer).unwrap();
    let mut response = assertion(&challenge, &signing_key, 0x05, 4);
    let client = json!({"type": "webauthn.get", "origin": ORIGIN, "crossOrigin": true,
        "challenge": B64.encode(&challenge.options.public_key.challenge)});
    let client = serde_json::to_vec(&client).unwrap();
    response.credential.response.signature = sign(&signing_key, &auth_data(0x05, 4), &client);
    response.credential.response.client_data_json = client;
    assert!(auth.finish_login(response).is_err());

    let challenge = auth.start_login(None, Grant::Http, peer).unwrap();
    assert!(
        auth.finish_login(assertion(&challenge, &signing_key, 0x15, 4))
            .is_err()
    );

    for _ in 0..peers.pending_per_ip {
        auth.start_login(None, Grant::Http, peer).unwrap();
    }
    assert_eq!(
        auth.check_challenge_capacity(peer).unwrap_err().0,
        StatusCode::TOO_MANY_REQUESTS
    );
    auth.check_challenge_capacity("127.0.0.2".parse().unwrap())
        .unwrap();
}

fn registration(
    challenge: &Challenge<CreationChallengeResponse>,
    key: &KeyPair,
    model: Uuid,
    attestation: Option<(&Certificate, &KeyPair)>,
) -> SignedChallenge<RegisterPublicKeyCredential> {
    let client = client_data(&challenge.options.public_key.challenge, "webauthn.create");
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
    let mut data = auth_data(0x45, 0);
    data.extend_from_slice(model.as_bytes());
    data.extend_from_slice(&(id.len() as u16).to_be_bytes());
    data.extend_from_slice(&id);
    data.extend(serde_cbor_2::to_vec(&cose).unwrap());
    let (format, statement) = if let Some((cert, attestation_key)) = attestation {
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
    SignedChallenge {
        challenge_id: challenge.challenge_id,
        credential: serde_json::from_value(json!({
            "id": B64.encode(id), "rawId": B64.encode(id), "type": "public-key",
            "response": {
                "clientDataJSON": B64.encode(client),
                "attestationObject": B64.encode(serde_cbor_2::to_vec(&object).unwrap()),
            },
        }))
        .unwrap(),
    }
}

fn assertion(
    challenge: &Challenge<RequestChallengeResponse>,
    key: &KeyPair,
    flags: u8,
    counter: u32,
) -> SignedChallenge<PublicKeyCredential> {
    let client = client_data(&challenge.options.public_key.challenge, "webauthn.get");
    let data = auth_data(flags, counter);
    let id = hash(key.der_bytes());
    SignedChallenge {
        challenge_id: challenge.challenge_id,
        credential: serde_json::from_value(json!({
            "id": B64.encode(id), "rawId": B64.encode(id), "type": "public-key",
            "response": {
                "clientDataJSON": B64.encode(&client),
                "authenticatorData": B64.encode(&data),
                "signature": B64.encode(sign(key, &data, &client)),
            },
        }))
        .unwrap(),
    }
}

fn object<const N: usize>(pairs: [(&str, Value); N]) -> Value {
    Map(pairs
        .into_iter()
        .map(|(key, value)| (Text(key.into()), value))
        .collect())
}

fn client_data(challenge: &[u8], kind: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({"type": kind, "origin": ORIGIN, "challenge": B64.encode(challenge)}))
        .unwrap()
}

fn auth_data(flags: u8, counter: u32) -> Vec<u8> {
    [
        hash(RP.as_bytes()).as_slice(),
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
