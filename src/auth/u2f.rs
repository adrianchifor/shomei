use super::*;
use x509_parser::asn1_rs::oid;

pub(super) struct U2fPolicy {
    pub(super) roots: AttestationCaList,
    root: CertificateDer<'static>,
}

impl U2fPolicy {
    pub(super) fn new() -> Result<Self> {
        Self::from_pem(include_bytes!("../../assets/yubico/u2f-root.pem"))
    }

    pub(super) fn from_pem(pem: &[u8]) -> Result<Self> {
        let roots = AttestationCaList::try_from(pem)
            .map_err(|error| anyhow::anyhow!("invalid Yubico U2F root: {error:?}"))?;
        Ok(Self {
            roots,
            root: CertificateDer::from_pem_slice(pem)?,
        })
    }

    pub(super) fn verify(&self, key: &SecurityKey) -> Result<()> {
        ensure!(
            key.cred_algorithm() == &COSEAlgorithm::ES256,
            "ES256 credential required"
        );
        let ParsedAttestationData::Basic(chain) = &key.attestation().data else {
            anyhow::bail!("manufacturer U2F attestation required");
        };
        let [leaf] = chain.as_slice() else {
            anyhow::bail!("expected a single Yubico U2F attestation certificate");
        };
        let der = leaf.to_der()?;
        ensure!(
            issued_by(&der, self.root.as_ref()),
            "unrecognized Yubico U2F issuer"
        );
        let ([], certificate) = parse_x509_certificate(&der)
            .map_err(|_| anyhow::anyhow!("invalid Yubico U2F certificate"))?
        else {
            anyhow::bail!("trailing bytes in Yubico U2F certificate");
        };
        ensure!(
            !certificate.is_ca(),
            "U2F attestation certificate cannot be a CA"
        );
        ensure!(
            certificate.extensions().iter().any(|extension| {
                extension.oid == oid!(1.3.6.1.4.1.41482.1.5)
                    || (extension.oid == oid!(1.3.6.1.4.1.41482.2)
                        && extension.value == b"1.3.6.1.4.1.41482.1.5")
            }),
            "the U2F attestation certificate does not identify a YubiKey 4"
        );
        Ok(())
    }
}

pub(super) fn is_u2f(registration: &RegisterPublicKeyCredential) -> Result<bool> {
    let object: Value = serde_cbor_2::from_slice(&registration.response.attestation_object)?;
    let Value::Map(fields) = object else {
        anyhow::bail!("invalid attestation object");
    };
    Ok(fields.get(&Value::Text("fmt".into())) == Some(&Value::Text("fido-u2f".into())))
}
