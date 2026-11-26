use super::*;
use ring::rand::{SystemRandom, generate};
use serde::de::DeserializeOwned;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticIdentity {
    #[serde(default, alias = "account", skip_serializing_if = "Option::is_none")]
    pub(super) attested_label: Option<String>,
    pub origin: Url,
    pub(super) nonce: String,
    pub(super) attestation: RegisterPublicKeyCredential,
}

pub struct IdentitySetup {
    origin: Url,
    account: String,
    nonce: [u8; 32],
    webauthn: Webauthn,
    policy: YubikeyPolicy,
}

pub fn prepare_identity(
    origin: &Url,
    u2f: bool,
) -> Result<(CreationChallengeResponse, IdentitySetup)> {
    IdentitySetup::prepare(origin, ACCOUNT, YubikeyPolicy::new(u2f)?)
}

impl IdentitySetup {
    pub(super) fn prepare(
        origin: &Url,
        account: &str,
        policy: YubikeyPolicy,
    ) -> Result<(CreationChallengeResponse, Self)> {
        ensure!(valid_attested_label(account), "invalid attested label");
        let webauthn = build_webauthn(origin)?;
        let nonce = generate::<[u8; 32]>(&SystemRandom::new())
            .map_err(|_| anyhow::anyhow!("generate identity nonce"))?
            .expose();
        let options = if let Some(u2f) = &policy.u2f {
            u2f_registration(&webauthn, u2f, origin, account, &nonce)?.0
        } else {
            registration(&webauthn, &policy, origin, account, &nonce)?.0
        };
        let setup = Self {
            origin: origin.clone(),
            account: account.into(),
            nonce,
            webauthn,
            policy,
        };
        Ok((options, setup))
    }

    pub fn finish(self, attestation: RegisterPublicKeyCredential) -> Result<StaticIdentity> {
        ensure!(
            u2f::is_u2f(&attestation)? == self.policy.u2f.is_some(),
            "unexpected YubiKey attestation format"
        );
        let mut identity = StaticIdentity {
            attested_label: (self.account != ACCOUNT).then_some(self.account),
            origin: self.origin,
            nonce: B64.encode(self.nonce),
            attestation,
        };
        let key = identity.attested_key(&identity.origin, &self.webauthn, &self.policy)?;
        identity.attestation.id = B64.encode(key.cred_id());
        identity.attestation.raw_id = key.cred_id().clone();
        identity.attestation.type_ = "public-key".into();
        Ok(identity)
    }
}

impl StaticIdentity {
    pub fn verify(&self) -> Result<()> {
        let webauthn = build_webauthn(&self.origin)?;
        let policy = YubikeyPolicy::new(u2f::is_u2f(&self.attestation)?)?;
        self.verify_for(&self.origin, &webauthn, &policy)?;
        Ok(())
    }

    pub(super) fn verify_for(
        &self,
        origin: &Url,
        webauthn: &Webauthn,
        policy: &YubikeyPolicy,
    ) -> Result<DeviceKey> {
        let key = self.attested_key(origin, webauthn, policy)?;
        ensure!(
            self.attestation.id == B64.encode(key.cred_id())
                && self.attestation.raw_id == *key.cred_id()
                && self.attestation.type_ == "public-key",
            "credential ID does not match signed attestation"
        );
        Ok(key)
    }

    fn attested_key(
        &self,
        origin: &Url,
        webauthn: &Webauthn,
        policy: &YubikeyPolicy,
    ) -> Result<DeviceKey> {
        ensure!(
            self.origin == *origin,
            "identity belongs to a different HTTPS origin"
        );
        let label = self.attested_label.as_deref().unwrap_or(ACCOUNT);
        ensure!(valid_attested_label(label), "invalid attested label");
        let nonce: [u8; 32] = B64
            .decode(&self.nonce)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid identity nonce"))?;
        if u2f::is_u2f(&self.attestation)? {
            let u2f = policy
                .u2f
                .as_ref()
                .context("YubiKey 4 support is disabled")?;
            let (_, registration) = u2f_registration(webauthn, u2f, origin, label, &nonce)?;
            let key = webauthn
                .finish_securitykey_registration(&self.attestation, &registration)
                .context("verify signed FIDO U2F registration")?;
            u2f.verify(&key)?;
            return Ok(DeviceKey::U2f(key));
        }
        let (_, registration) = registration(webauthn, policy, origin, label, &nonce)?;
        let mut proof = self.attestation.clone();
        policy.complete_chain(&mut proof)?;
        let key = webauthn
            .finish_attested_passkey_registration(&proof, &registration)
            .context("verify signed WebAuthn registration")?;
        policy.verify(&key)?;
        Ok(DeviceKey::Fido2(key))
    }
}

fn registration(
    webauthn: &Webauthn,
    policy: &YubikeyPolicy,
    origin: &Url,
    account: &str,
    nonce: &[u8; 32],
) -> Result<(CreationChallengeResponse, AttestedPasskeyRegistration)> {
    let (options, state) = webauthn.start_attested_passkey_registration(
        Uuid::new_v4(),
        account,
        account,
        None,
        policy.roots.clone(),
        Some(AuthenticatorAttachment::CrossPlatform),
    )?;
    scope_registration(options, state, origin, account, nonce)
}

fn u2f_registration(
    webauthn: &Webauthn,
    policy: &U2fPolicy,
    origin: &Url,
    account: &str,
    nonce: &[u8; 32],
) -> Result<(CreationChallengeResponse, SecurityKeyRegistration)> {
    ensure!(
        origin.domain() == Some("localhost"),
        "YubiKey 4 support requires localhost HTTPS"
    );
    let (options, state) = webauthn.start_securitykey_registration(
        Uuid::new_v4(),
        account,
        account,
        None,
        Some(policy.roots.clone()),
        Some(AuthenticatorAttachment::CrossPlatform),
    )?;
    scope_registration(options, state, origin, account, nonce)
}

fn scope_registration<T: Serialize + DeserializeOwned>(
    mut options: CreationChallengeResponse,
    state: T,
    origin: &Url,
    account: &str,
    nonce: &[u8; 32],
) -> Result<(CreationChallengeResponse, T)> {
    let scope = origin.origin().ascii_serialization();
    let challenge = sha256(
        &[
            b"shomei:static-identity:v1\0",
            scope.as_bytes(),
            b"\0",
            account.as_bytes(),
            b"\0",
            nonce,
        ]
        .concat(),
    );
    options.public_key.challenge = challenge.to_vec();
    options
        .public_key
        .pub_key_cred_params
        .retain(|option| option.alg == ES256);
    // Rebuild trusted policy locally and replace only the challenge.
    let mut state = serde_json::to_value(&state)?;
    let challenge_field = state
        .pointer_mut("/rs/challenge")
        .context("WebAuthn registration state has no challenge")?;
    *challenge_field = serde_json::Value::String(B64.encode(challenge));
    Ok((options, serde_json::from_value(state)?))
}
