use super::*;
use ring::rand::{SystemRandom, generate};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticIdentity {
    pub account: String,
    pub origin: Url,
    nonce: String,
    attestation: RegisterPublicKeyCredential,
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
    account: &str,
) -> Result<(CreationChallengeResponse, IdentitySetup)> {
    IdentitySetup::prepare(origin, account, YubikeyPolicy::new()?)
}

impl IdentitySetup {
    pub(super) fn prepare(
        origin: &Url,
        account: &str,
        policy: YubikeyPolicy,
    ) -> Result<(CreationChallengeResponse, Self)> {
        ensure!(valid_account_name(account), "invalid account name");
        let webauthn = build_webauthn(origin)?;
        let nonce = generate::<[u8; 32]>(&SystemRandom::new())
            .map_err(|_| anyhow::anyhow!("generate identity nonce"))?
            .expose();
        let (options, _) = registration(&webauthn, &policy, origin, account, &nonce)?;
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
        let mut identity = StaticIdentity {
            account: self.account,
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
        self.verify_for(&self.origin, &webauthn, &YubikeyPolicy::new()?)?;
        Ok(())
    }

    pub(super) fn verify_for(
        &self,
        origin: &Url,
        webauthn: &Webauthn,
        policy: &YubikeyPolicy,
    ) -> Result<AttestedPasskey> {
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
    ) -> Result<AttestedPasskey> {
        ensure!(
            self.origin == *origin,
            "identity belongs to a different HTTPS origin"
        );
        ensure!(valid_account_name(&self.account), "invalid account name");
        let nonce: [u8; 32] = B64
            .decode(&self.nonce)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid identity nonce"))?;
        let (_, registration) = registration(webauthn, policy, origin, &self.account, &nonce)?;
        let mut proof = self.attestation.clone();
        policy.complete_chain(&mut proof)?;
        let key = webauthn
            .finish_attested_passkey_registration(&proof, &registration)
            .context("verify signed WebAuthn registration")?;
        policy.verify(&key)?;
        Ok(key)
    }
}

fn registration(
    webauthn: &Webauthn,
    policy: &YubikeyPolicy,
    origin: &Url,
    account: &str,
    nonce: &[u8; 32],
) -> Result<(CreationChallengeResponse, AttestedPasskeyRegistration)> {
    let (mut options, state) = webauthn.start_attested_passkey_registration(
        Uuid::new_v4(),
        account,
        account,
        None,
        policy.roots.clone(),
        Some(AuthenticatorAttachment::CrossPlatform),
    )?;
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
