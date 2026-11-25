use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::Private,
    sign::Signer,
    x509::{X509Name, extension::BasicConstraints},
};
use serde_cbor_2::Value::{self, Array, Bytes, Integer, Map, Text};
use serde_json::json;

use super::*;

const ORIGIN: &str = "https://shomei.example:8443";
const RP: &str = "shomei.example";
const TOKEN: &str = "0123456789abcdef0123456789abcdef";
const ID: [u8; 32] = [42; 32];

#[test]
fn verifies_attestation_and_consumes_challenges() {
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("token");
    fs::write(&token, TOKEN).unwrap();
    let origin = Url::parse(ORIGIN).unwrap();
    let mut auth = Auth::new(&origin, dir.path(), Some(&token)).unwrap();
    let root_key = p256();
    let root = certificate(&root_key, None);
    let attestation_key = p256();
    let leaf = certificate(&attestation_key, Some((&root, &root_key)));
    let signing_key = p256();
    let model = Uuid::parse_str(YUBIKEY_5_MODELS[0]).unwrap();

    assert!(auth.start_enroll(Some("wrong-token")).is_err());
    let challenge = auth.start_enroll(Some(TOKEN)).unwrap();
    let unsigned = registration(&challenge, &signing_key, model, None);
    assert!(auth.finish_enroll(Some(TOKEN), unsigned).is_err());
    let challenge = auth.start_enroll(Some(TOKEN)).unwrap();
    let untrusted = registration(
        &challenge,
        &signing_key,
        model,
        Some((&leaf, &attestation_key)),
    );
    assert!(auth.finish_enroll(Some(TOKEN), untrusted).is_err());

    let mut roots = AttestationCaListBuilder::new();
    roots
        .insert_device_x509(root.clone(), model, "Test key".into(), Default::default())
        .unwrap();
    auth.yubikeys = YubikeyPolicy {
        roots: roots.build(),
        leaf_issuers: vec![root],
    };
    let challenge = auth.start_enroll(Some(TOKEN)).unwrap();
    let wrong_model = registration(
        &challenge,
        &signing_key,
        Uuid::nil(),
        Some((&leaf, &attestation_key)),
    );
    assert!(auth.finish_enroll(Some(TOKEN), wrong_model).is_err());
    let challenge = auth.start_enroll(Some(TOKEN)).unwrap();
    let approved = registration(
        &challenge,
        &signing_key,
        model,
        Some((&leaf, &attestation_key)),
    );
    auth.finish_enroll(Some(TOKEN), approved).unwrap();
    assert!(auth.start_enroll(Some(TOKEN)).is_err());

    let challenge = auth.start_login(Grant::Http).unwrap();
    assert!(
        auth.finish_login(assertion(&challenge, &signing_key, 0x01, 1))
            .is_err()
    );
    assert!(
        auth.finish_login(assertion(&challenge, &signing_key, 0x05, 1))
            .is_err()
    );
    let tcp_key = p256();
    let public_key = PKey::public_key_from_der(&tcp_key.public_key_to_der().unwrap()).unwrap();
    let older = auth.start_login(Grant::Http).unwrap();
    let challenge = auth.start_login(Grant::Tcp(public_key)).unwrap();
    let Grant::Tcp(granted_key) = auth
        .finish_login(assertion(&challenge, &signing_key, 0x05, 2))
        .unwrap()
    else {
        panic!("expected TCP grant");
    };
    assert!(granted_key.public_eq(&tcp_key));
    assert!(
        auth.finish_login(assertion(&challenge, &signing_key, 0x05, 3))
            .is_err()
    );
    assert!(
        auth.finish_login(assertion(&older, &signing_key, 0x05, 1))
            .is_err()
    );
    let challenge = auth.start_login(Grant::Http).unwrap();
    assert!(matches!(
        auth.finish_login(assertion(&challenge, &signing_key, 0x05, 3)),
        Ok(Grant::Http)
    ));
    let saved: AttestedPasskey =
        serde_json::from_reader(File::open(auth.credential_file).unwrap()).unwrap();
    assert_eq!(Credential::from(saved).counter, 3);
}

fn registration(
    challenge: &Challenge<CreationChallengeResponse>,
    key: &PKey<Private>,
    model: Uuid,
    attestation: Option<(&X509, &PKey<Private>)>,
) -> SignedChallenge<RegisterPublicKeyCredential> {
    let client = client_data(&challenge.options.public_key.challenge, "webauthn.create");
    let key = key.ec_key().unwrap();
    let (mut x, mut y) = (BigNum::new().unwrap(), BigNum::new().unwrap());
    key.public_key()
        .affine_coordinates(
            key.group(),
            &mut x,
            &mut y,
            &mut BigNumContext::new().unwrap(),
        )
        .unwrap();
    let cose = Map([
        (Integer(1), Integer(2)),
        (Integer(3), Integer(-7)),
        (Integer(-1), Integer(1)),
        (Integer(-2), Bytes(x.to_vec_padded(32).unwrap())),
        (Integer(-3), Bytes(y.to_vec_padded(32).unwrap())),
    ]
    .into());
    let mut data = auth_data(0x45, 0);
    data.extend_from_slice(model.as_bytes());
    data.extend_from_slice(&(ID.len() as u16).to_be_bytes());
    data.extend_from_slice(&ID);
    data.extend(serde_cbor_2::to_vec(&cose).unwrap());
    let (format, statement) = if let Some((cert, attestation_key)) = attestation {
        (
            "packed",
            object([
                ("alg", Integer(-7)),
                ("sig", Bytes(sign(attestation_key, &data, &client))),
                ("x5c", Array(vec![Bytes(cert.to_der().unwrap())])),
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
            "id": B64.encode(ID), "rawId": B64.encode(ID), "type": "public-key",
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
    key: &PKey<Private>,
    flags: u8,
    counter: u32,
) -> SignedChallenge<PublicKeyCredential> {
    let client = client_data(&challenge.options.public_key.challenge, "webauthn.get");
    let data = auth_data(flags, counter);
    SignedChallenge {
        challenge_id: challenge.challenge_id,
        credential: serde_json::from_value(json!({
            "id": B64.encode(ID), "rawId": B64.encode(ID), "type": "public-key",
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
        sha256(RP.as_bytes()).as_slice(),
        &[flags],
        &counter.to_be_bytes(),
    ]
    .concat()
}

fn sign(key: &PKey<Private>, data: &[u8], client: &[u8]) -> Vec<u8> {
    let mut signer = Signer::new(MessageDigest::sha256(), key).unwrap();
    signer.update(data).unwrap();
    signer.update(&sha256(client)).unwrap();
    signer.sign_to_vec().unwrap()
}

fn p256() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}

fn certificate(key: &PKey<Private>, issuer: Option<(&X509, &PKey<Private>)>) -> X509 {
    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_text("C", "SE").unwrap();
    name.append_entry_by_text("O", "Test").unwrap();
    name.append_entry_by_text("OU", "Authenticator Attestation")
        .unwrap();
    name.append_entry_by_text(
        "CN",
        if issuer.is_some() {
            "Fixture"
        } else {
            "Fixture CA"
        },
    )
    .unwrap();
    let name = name.build();
    let mut cert = X509::builder().unwrap();
    let serial = BigNum::from_u32(if issuer.is_some() { 2 } else { 1 })
        .unwrap()
        .to_asn1_integer()
        .unwrap();
    cert.set_serial_number(&serial).unwrap();
    cert.set_version(2).unwrap();
    cert.set_subject_name(&name).unwrap();
    cert.set_issuer_name(issuer.map_or(name.as_ref(), |(cert, _)| cert.subject_name()))
        .unwrap();
    cert.set_pubkey(key).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    let constraints = if issuer.is_some() {
        BasicConstraints::new().build()
    } else {
        BasicConstraints::new().critical().ca().build()
    };
    cert.append_extension(constraints.unwrap()).unwrap();
    cert.sign(issuer.map_or(key, |(_, key)| key), MessageDigest::sha256())
        .unwrap();
    cert.build()
}
