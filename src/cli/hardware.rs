mod u2f;

use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use tokio::{task::block_in_place, time::timeout};
use url::Url;
use webauthn_authenticator_rs::{
    WebauthnAuthenticator,
    ctap2::CtapAuthenticator,
    transport::Transport,
    types::{CableRequestType, CableState, EnrollSampleStatus},
    ui::UiCallback,
    usb::{USBToken, USBTransport},
};
use webauthn_rs::prelude::{
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};
use webauthn_rs_proto::UserVerificationPolicy;
use zeroize::Zeroizing;

use crate::auth::provisioning_model;

const CONNECT_FIDO2: &str =
    "connect a supported YubiKey 5 over USB with FIDO2 enabled and check USB device permissions";

#[derive(Debug, Default)]
struct Terminal {
    touch_prompted: AtomicBool,
}

impl UiCallback for Terminal {
    fn request_pin(&self) -> Option<String> {
        match rpassword::prompt_password("YubiKey FIDO2 PIN: ") {
            Ok(pin) if !pin.is_empty() => Some(pin),
            Ok(_) => None,
            Err(error) => {
                eprintln!("Cannot read a PIN from the terminal: {error}");
                None
            }
        }
    }

    fn request_touch(&self) {
        if !self.touch_prompted.swap(true, Ordering::Relaxed) {
            eprintln!("Touch your YubiKey.");
        }
    }

    fn processing(&self) {}
    fn fingerprint_enrollment_feedback(&self, _: u32, _: Option<EnrollSampleStatus>) {}
    fn cable_qr_code(&self, _: CableRequestType, _: String) {}
    fn dismiss_qr_code(&self) {}
    fn cable_status_update(&self, _: CableState) {}
}

async fn usb_key(ui: &Terminal) -> Result<Option<CtapAuthenticator<'_, USBToken, Terminal>>> {
    let transport = USBTransport::new()
        .await
        .context("initialize USB FIDO2 transport")?;
    let tokens = transport
        .tokens()
        .await
        .context("enumerate USB FIDO2 devices")?;
    let mut key = None;
    for token in tokens {
        let Ok(Some(candidate)) =
            timeout(Duration::from_secs(3), CtapAuthenticator::new(token, ui)).await
        else {
            continue;
        };
        if candidate.get_info().aaguid.is_some_and(provisioning_model) {
            ensure!(key.is_none(), "connect only one supported YubiKey");
            key = Some(candidate);
        }
    }
    Ok(key)
}

pub async fn register(
    origin: Url,
    options: CreationChallengeResponse,
    set_pin: bool,
    u2f: bool,
) -> Result<RegisterPublicKeyCredential> {
    if u2f {
        return block_in_place(|| u2f::register(origin, options));
    }
    let ui = Terminal::default();
    let mut key = usb_key(&ui).await?.with_context(|| {
        if origin.domain() == Some("localhost") {
            format!("{CONNECT_FIDO2}. For a YubiKey 4 on localhost, run shomei init --u2f")
        } else {
            CONNECT_FIDO2.to_owned()
        }
    })?;
    if key.get_info().get_option("clientPin") == Some(false) {
        ensure!(
            set_pin,
            "this YubiKey has no FIDO2 PIN. Run init with --set-pin to create one"
        );
        let (pin, confirmation) = block_in_place(|| -> std::io::Result<_> {
            let pin = Zeroizing::new(rpassword::prompt_password("New YubiKey FIDO2 PIN: ")?);
            let confirmation =
                Zeroizing::new(rpassword::prompt_password("Confirm the new FIDO2 PIN: ")?);
            Ok((pin, confirmation))
        })?;
        ensure!(pin == confirmation, "FIDO2 PIN confirmation differs");
        key.set_new_pin(&pin)
            .await
            .context("set the YubiKey FIDO2 PIN")?;
    }
    let mut response = block_in_place(|| key.do_registration(origin, options))
        .context("create and attest the YubiKey credential")?;
    response.type_ = "public-key".into();
    Ok(response)
}

pub async fn authenticate(
    origin: Url,
    mut options: RequestChallengeResponse,
) -> Result<PublicKeyCredential> {
    if options.public_key.user_verification == UserVerificationPolicy::Discouraged_DO_NOT_USE {
        ensure!(
            origin.domain() == Some("localhost"),
            "YubiKey 4 support requires localhost HTTPS"
        );
        return block_in_place(|| u2f::authenticate(origin, options));
    }
    ensure!(
        matches!(
            options.public_key.user_verification,
            UserVerificationPolicy::Required | UserVerificationPolicy::Preferred
        ),
        "unexpected WebAuthn user verification policy"
    );
    let ui = Terminal::default();
    let key = usb_key(&ui).await?;
    if key.is_none() && options.public_key.user_verification == UserVerificationPolicy::Preferred {
        ensure!(
            origin.domain() == Some("localhost"),
            "YubiKey 4 support requires localhost HTTPS"
        );
        return block_in_place(|| u2f::authenticate(origin, options));
    }
    let mut key = key.context(CONNECT_FIDO2)?;
    options.public_key.user_verification = UserVerificationPolicy::Required;
    let response = block_in_place(|| key.do_authentication(origin, options))
        .context("sign the gateway challenge with your YubiKey")?;
    let flags = response
        .response
        .authenticator_data
        .get(32)
        .context("incomplete YubiKey response")?;
    ensure!(
        flags & 0x05 == 0x05,
        "the YubiKey response requires presence and user verification"
    );
    Ok(response)
}
