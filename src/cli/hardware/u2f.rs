use std::{sync::mpsc, time::Duration};

use anyhow::{Context, Result, ensure};
use authenticator::{
    StatusUpdate,
    authenticatorservice::{AuthenticatorService, RegisterArgs, SignArgs},
    crypto::COSEAlgorithm,
    ctap2::server::{
        PublicKeyCredentialDescriptor, PublicKeyCredentialParameters,
        PublicKeyCredentialUserEntity, RelyingParty, ResidentKeyRequirement, Transport,
        UserVerificationRequirement,
    },
    statecallback::StateCallback,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::digest::{SHA256, digest};
use url::Url;
use webauthn_rs_proto::{
    AuthenticatorAssertionResponseRaw, AuthenticatorAttestationResponseRaw, AuthenticatorTransport,
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};

const TOUCH_TIMEOUT: u64 = 60_000;

pub(super) fn register(
    origin: Url,
    options: CreationChallengeResponse,
) -> Result<RegisterPublicKeyCredential> {
    let options = options.public_key;
    let client_data = client_data(&origin, "webauthn.create", &options.challenge)?;
    let args = RegisterArgs {
        client_data_hash: hash(&client_data),
        origin: origin.origin().ascii_serialization(),
        relying_party: RelyingParty {
            id: options.rp.id,
            name: Some(options.rp.name),
        },
        user: PublicKeyCredentialUserEntity {
            id: options.user.id,
            name: Some(options.user.name),
            display_name: Some(options.user.display_name),
        },
        pub_cred_params: vec![PublicKeyCredentialParameters {
            alg: COSEAlgorithm::ES256,
        }],
        exclude_list: Vec::new(),
        user_verification_req: UserVerificationRequirement::Discouraged,
        resident_key_req: ResidentKeyRequirement::Discouraged,
        pin: None,
        extensions: Default::default(),
        use_ctap1_fallback: true,
    };
    let result =
        run(|service, status, callback| service.register(TOUCH_TIMEOUT, args, status, callback))?;
    let credential = result
        .att_obj
        .auth_data
        .credential_data
        .as_ref()
        .context("missing U2F credential")?;
    let id = &credential.credential_id;
    Ok(RegisterPublicKeyCredential {
        id: URL_SAFE_NO_PAD.encode(id),
        raw_id: id.clone(),
        response: AuthenticatorAttestationResponseRaw {
            attestation_object: serde_cbor_2::to_vec(&result.att_obj)?,
            client_data_json: client_data,
            transports: Some(vec![AuthenticatorTransport::Usb]),
        },
        type_: "public-key".into(),
        extensions: Default::default(),
    })
}

pub(super) fn authenticate(
    origin: Url,
    options: RequestChallengeResponse,
) -> Result<PublicKeyCredential> {
    let options = options.public_key;
    let allowed = options.allow_credentials;
    ensure!(
        !allowed.is_empty(),
        "the U2F challenge must name an enrolled credential"
    );
    let client_data = client_data(&origin, "webauthn.get", &options.challenge)?;
    let args = SignArgs {
        client_data_hash: hash(&client_data),
        origin: origin.origin().ascii_serialization(),
        relying_party_id: options.rp_id,
        allow_list: allowed
            .iter()
            .map(|credential| PublicKeyCredentialDescriptor {
                id: credential.id.clone(),
                transports: vec![Transport::USB],
            })
            .collect(),
        user_verification_req: UserVerificationRequirement::Discouraged,
        user_presence_req: true,
        extensions: Default::default(),
        pin: None,
        use_ctap1_fallback: true,
    };
    let result =
        run(|service, status, callback| service.sign(TOUCH_TIMEOUT, args, status, callback))?;
    let assertion = result.assertion;
    let auth_data = assertion.auth_data.to_vec();
    ensure!(
        auth_data.get(32) == Some(&1),
        "the U2F response must prove touch"
    );
    let id = match (assertion.credentials, allowed.as_slice()) {
        (Some(returned), _)
            if allowed
                .iter()
                .any(|credential| credential.id == returned.id) =>
        {
            returned.id
        }
        (None, [credential]) => credential.id.clone(),
        _ => anyhow::bail!("unexpected U2F credential"),
    };
    Ok(PublicKeyCredential {
        id: URL_SAFE_NO_PAD.encode(&id),
        raw_id: id,
        response: AuthenticatorAssertionResponseRaw {
            authenticator_data: auth_data,
            client_data_json: client_data,
            signature: assertion.signature,
            user_handle: None,
        },
        type_: "public-key".into(),
        extensions: Default::default(),
    })
}

fn client_data(origin: &Url, kind: &str, challenge: &[u8]) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&serde_json::json!({
        "type": kind,
        "challenge": URL_SAFE_NO_PAD.encode(challenge),
        "origin": origin.origin().ascii_serialization(),
        "crossOrigin": false,
    }))?)
}

fn hash(data: &[u8]) -> [u8; 32] {
    let mut hash = [0; 32];
    hash.copy_from_slice(digest(&SHA256, data).as_ref());
    hash
}

fn run<T: Send + 'static>(
    start: impl FnOnce(
        &mut AuthenticatorService,
        mpsc::Sender<StatusUpdate>,
        StateCallback<authenticator::Result<T>>,
    ) -> authenticator::Result<()>,
) -> Result<T> {
    let mut service = AuthenticatorService::new().context("initialize USB U2F")?;
    service.add_u2f_usb_hid_platform_transports();
    let (status, _updates) = mpsc::channel();
    let (complete, result) = mpsc::channel();
    eprintln!("Touch your YubiKey 4.");
    start(
        &mut service,
        status,
        StateCallback::new(Box::new(move |value| {
            let _ = complete.send(value);
        })),
    )
    .context("start USB U2F operation")?;
    result
        .recv_timeout(Duration::from_millis(TOUCH_TIMEOUT + 1_000))?
        .context("YubiKey 4 did not complete the U2F operation")
}
