use std::{
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer as CertificateIssuer, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256, PublicKeyData, SerialNumber, SubjectPublicKeyInfo,
};
use rustls::{
    RootCertStore, ServerConfig,
    pki_types::{CertificateDer, CertificateSigningRequestDer, PrivateKeyDer, pem::PemObject},
    server::{NoServerSessionStorage, ServerSessionMemoryCache, WebPkiClientVerifier},
};
use serde::Serialize;
use time::OffsetDateTime;
use tokio_rustls::TlsAcceptor;
use x509_parser::{
    certification_request::X509CertificationRequest, oid_registry::OID_SIG_ECDSA_WITH_SHA256,
    parse_x509_certificate, prelude::FromDer,
};

const CLIENT_NAME: &str = "Shomei TCP Client ";

pub struct Identity {
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

impl Identity {
    pub fn load(cert_path: &Path, key_path: &Path) -> Result<Self> {
        let certs = CertificateDer::pem_file_iter(cert_path)
            .with_context(|| format!("open TLS certificate {}", cert_path.display()))?
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| format!("read TLS certificate {}", cert_path.display()))?;
        let key = PrivateKeyDer::from_pem_file(key_path)
            .with_context(|| format!("read TLS private key {}", key_path.display()))?;
        Ok(Self { certs, key })
    }

    pub fn server(&self, issuer: Option<&Issuer>) -> Result<TlsAcceptor> {
        Ok(TlsAcceptor::from(Arc::new(self.server_config(issuer)?)))
    }

    #[cfg(test)]
    pub fn http1_server(&self) -> Result<TlsAcceptor> {
        let mut config = self.server_config(None)?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(TlsAcceptor::from(Arc::new(config)))
    }

    fn server_config(&self, issuer: Option<&Issuer>) -> Result<ServerConfig> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = match issuer {
            Some(issuer) => {
                let mut roots = RootCertStore::empty();
                roots.add(issuer.cert.der().clone())?;
                WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                    .build()?
            }
            None => WebPkiClientVerifier::no_client_auth(),
        };
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_client_cert_verifier(verifier)
            .with_single_cert(self.certs.clone(), self.key.clone_key())?;
        config.max_early_data_size = 0;
        if issuer.is_some() {
            config.send_tls13_tickets = 0;
            config.session_storage = Arc::new(NoServerSessionStorage {});
        } else {
            config.send_tls13_tickets = 1;
            config.session_storage = ServerSessionMemoryCache::new(4096);
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        }
        Ok(config)
    }
}

pub struct Issuer {
    signer: CertificateIssuer<'static, KeyPair>,
    cert: Certificate,
}

#[derive(Serialize)]
pub struct ClientCertificate {
    pub certificate_pem: String,
    pub expires_at: u64,
}

impl Issuer {
    pub fn new() -> Result<Self> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut params = named_certificate("Shomei TCP Client CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let cert = params.self_signed(&key)?;
        let signer = CertificateIssuer::new(params, key);
        Ok(Self { signer, cert })
    }

    pub fn issue(
        &self,
        public_key: &SubjectPublicKeyInfo,
        ttl: u64,
        generation: u64,
        target: usize,
    ) -> Result<ClientCertificate> {
        ensure!(
            public_key.algorithm() == &PKCS_ECDSA_P256_SHA256,
            "client key must use P-256"
        );
        let now = unix_seconds()?;
        let expires_at = now + ttl;
        let mut params = named_certificate(&format!("{CLIENT_NAME}{generation}/{target}"));
        let serial = ring::rand::generate::<[u8; 16]>(&ring::rand::SystemRandom::new())
            .map_err(|_| anyhow::anyhow!("cannot generate certificate serial number"))?
            .expose();
        params.serial_number = Some(SerialNumber::from_slice(&serial));
        params.not_before = OffsetDateTime::from_unix_timestamp(now.try_into()?)?;
        params.not_after = OffsetDateTime::from_unix_timestamp(expires_at.try_into()?)?;
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let certificate_pem = params.signed_by(public_key, &self.signer)?.pem();
        Ok(ClientCertificate {
            certificate_pem,
            expires_at,
        })
    }
}

fn named_certificate(name: &str) -> CertificateParams {
    let mut subject = DistinguishedName::new();
    subject.push(DnType::CommonName, name);
    let mut params = CertificateParams::default();
    params.distinguished_name = subject;
    params
}

pub fn csr_key(pem: &str) -> Result<SubjectPublicKeyInfo> {
    ensure!(pem.len() <= 4096, "CSR exceeds 4096 bytes");
    let der = CertificateSigningRequestDer::from_pem_slice(pem.as_bytes())?;
    let (rest, request) = X509CertificationRequest::from_der(der.as_ref())
        .map_err(|_| anyhow::anyhow!("invalid CSR DER"))?;
    ensure!(rest.is_empty(), "unexpected data after CSR");
    let key = SubjectPublicKeyInfo::from_der(request.certification_request_info.subject_pki.raw)?;
    ensure!(
        key.algorithm() == &PKCS_ECDSA_P256_SHA256
            && request.signature_algorithm.algorithm == OID_SIG_ECDSA_WITH_SHA256,
        "CSR must use P-256 and SHA-256"
    );
    request
        .verify_signature()
        .context("invalid CSR signature")?;
    Ok(key)
}

pub fn unix_seconds() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

pub(crate) fn client_grant(cert: &CertificateDer<'_>) -> Result<(u64, usize, Duration)> {
    let (_, cert) = parse_x509_certificate(cert.as_ref())
        .map_err(|_| anyhow::anyhow!("invalid client certificate"))?;
    let (generation, target) = cert
        .subject()
        .iter_common_name()
        .next()
        .context("missing client grant")?
        .as_str()?
        .strip_prefix(CLIENT_NAME)
        .context("invalid client grant")?
        .split_once('/')
        .context("missing client grant target")?;
    let expires_at =
        UNIX_EPOCH + Duration::from_secs(cert.validity().not_after.timestamp().try_into()?);
    Ok((
        generation.parse()?,
        target.parse()?,
        expires_at.duration_since(SystemTime::now())?,
    ))
}

#[cfg(test)]
pub(crate) mod tests;
