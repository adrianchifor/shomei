use anyhow::{Context, Result, ensure};
use base64::Engine;
use miniz_oxide::{
    deflate::compress_to_vec_zlib,
    inflate::{
        TINFLStatus,
        core::{
            DecompressorOxide, decompress,
            inflate_flags::{
                TINFL_FLAG_PARSE_ZLIB_HEADER, TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
            },
        },
    },
};
use serde::{Deserialize, Serialize};
use url::Url;
use webauthn_rs_proto::{
    AuthenticatorAttestationResponseRaw, AuthenticatorTransport, RegisterPublicKeyCredential,
    RegistrationExtensionsClientOutputs,
};

use super::{B64, MAX_IDENTITIES_BYTES, StaticIdentity};

const PREFIX: &str = "shomei-id-v1:";
const MAX_RECORD_BYTES: usize = 32 * 1024;
const MAX_TOKEN_BYTES: usize = 64 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompactIdentity {
    #[serde(rename = "o")]
    origin: Url,
    #[serde(rename = "l", default, skip_serializing_if = "Option::is_none")]
    attested_label: Option<String>,
    #[serde(rename = "n", with = "serde_bytes")]
    nonce: Vec<u8>,
    #[serde(rename = "i", with = "serde_bytes")]
    credential_id: Vec<u8>,
    #[serde(rename = "a", with = "serde_bytes")]
    attestation_object: Vec<u8>,
    #[serde(rename = "c", with = "serde_bytes")]
    client_data_json: Vec<u8>,
    #[serde(rename = "t", default, skip_serializing_if = "Option::is_none")]
    transports: Option<Vec<AuthenticatorTransport>>,
    #[serde(rename = "e")]
    extensions: RegistrationExtensionsClientOutputs,
}

pub fn encode_identity(identity: &StaticIdentity) -> Result<String> {
    let registration = &identity.attestation;
    let compact = CompactIdentity {
        origin: identity.origin.clone(),
        attested_label: identity.attested_label.clone(),
        nonce: B64.decode(&identity.nonce)?,
        credential_id: registration.raw_id.clone(),
        attestation_object: registration.response.attestation_object.clone(),
        client_data_json: registration.response.client_data_json.clone(),
        transports: registration.response.transports.clone(),
        extensions: registration.extensions.clone(),
    };
    let bytes = serde_cbor_2::to_vec(&compact)?;
    ensure!(
        bytes.len() <= MAX_RECORD_BYTES,
        "identity exceeds size limit"
    );
    Ok(format!(
        "{PREFIX}{}",
        B64.encode(compress_to_vec_zlib(&bytes, 9))
    ))
}

fn decode_identity(token: &str, buffer: &mut [u8]) -> Result<(StaticIdentity, usize)> {
    ensure!(
        token.len() <= MAX_TOKEN_BYTES,
        "identity token exceeds size limit"
    );
    let payload = token
        .strip_prefix(PREFIX)
        .context("expected a shomei-id-v1 token")?;
    let compressed = B64.decode(payload).context("invalid identity base64url")?;
    let (status, consumed, written) = decompress(
        &mut DecompressorOxide::new(),
        &compressed,
        buffer,
        0,
        TINFL_FLAG_PARSE_ZLIB_HEADER | TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
    );
    ensure!(
        status != TINFLStatus::HasMoreOutput,
        "decoded identities exceed size limit"
    );
    ensure!(
        status == TINFLStatus::Done && consumed == compressed.len(),
        "invalid compressed identity"
    );
    let compact: CompactIdentity =
        serde_cbor_2::from_slice(&buffer[..written]).context("parse compact identity")?;
    let identity = StaticIdentity {
        origin: compact.origin,
        attested_label: compact.attested_label,
        nonce: B64.encode(compact.nonce),
        attestation: RegisterPublicKeyCredential {
            id: B64.encode(&compact.credential_id),
            raw_id: compact.credential_id,
            response: AuthenticatorAttestationResponseRaw {
                attestation_object: compact.attestation_object,
                client_data_json: compact.client_data_json,
                transports: compact.transports,
            },
            type_: "public-key".into(),
            extensions: compact.extensions,
        },
    };
    Ok((identity, written))
}

pub(super) fn visit_identities(
    contents: &[u8],
    mut visit: impl FnMut(StaticIdentity) -> Result<()>,
    mut reject: impl FnMut(anyhow::Error) -> Result<()>,
) -> Result<()> {
    let mut buffer = vec![0; MAX_RECORD_BYTES];
    let mut remaining = MAX_IDENTITIES_BYTES as usize;
    for (index, line) in contents.split(|byte| *byte == b'\n').enumerate() {
        let token = std::str::from_utf8(line)
            .map(|line| line.split_once('#').map_or(line, |(entry, _)| entry).trim());
        if token.is_ok_and(|token| token.is_empty()) {
            continue;
        }
        let limit = remaining.min(buffer.len());
        if let Err(error) = token
            .context("identity is not UTF-8")
            .and_then(|token| decode_identity(token, &mut buffer[..limit]))
            .and_then(|(record, bytes)| {
                remaining -= bytes;
                visit(record)
            })
            .with_context(|| format!("identity on line {}", index + 1))
        {
            reject(error)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_oversized_and_extra_compressed_data() {
        let mut buffer = vec![0; MAX_RECORD_BYTES];
        let oversized = compress_to_vec_zlib(&vec![0; MAX_RECORD_BYTES + 1], 1);
        let token = format!("{PREFIX}{}", B64.encode(oversized));
        assert!(
            matches!(decode_identity(&token, &mut buffer), Err(error) if error.to_string().contains("size limit"))
        );

        let mut trailing = compress_to_vec_zlib(b"test", 1);
        trailing.push(0);
        let token = format!("{PREFIX}{}", B64.encode(trailing));
        assert!(
            matches!(decode_identity(&token, &mut buffer), Err(error) if error.to_string() == "invalid compressed identity")
        );
    }
}
