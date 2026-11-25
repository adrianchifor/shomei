use std::{
    fs::File,
    io::BufReader,
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::{BigNum, MsbOption},
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, PKeyRef, Private, Public},
    x509::{
        X509, X509Name, X509Req,
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage},
    },
};
use rustls::{
    RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
    server::{NoServerSessionStorage, WebPkiClientVerifier},
};
use serde::Serialize;
use tokio::{io::copy_bidirectional, net::TcpStream, time::timeout};
use tokio_rustls::TlsAcceptor;

use crate::HANDSHAKE_TIMEOUT;

pub struct Identity {
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

impl Identity {
    pub fn load(cert_path: &Path, key_path: &Path) -> Result<Self> {
        let mut cert_file = BufReader::new(File::open(cert_path).context("open TLS certificate")?);
        let certs = rustls_pemfile::certs(&mut cert_file).collect::<Result<Vec<_>, _>>()?;
        let mut key_file = BufReader::new(File::open(key_path).context("open TLS key")?);
        let key = rustls_pemfile::private_key(&mut key_file)?.context("TLS key PEM is empty")?;
        Ok(Self { certs, key })
    }

    pub fn server(&self, issuer: Option<&Issuer>) -> Result<TlsAcceptor> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = match issuer {
            Some(issuer) => {
                let mut roots = RootCertStore::empty();
                roots.add(CertificateDer::from(issuer.cert.to_der()?))?;
                WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                    .build()?
            }
            None => WebPkiClientVerifier::no_client_auth(),
        };
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_client_cert_verifier(verifier)
            .with_single_cert(self.certs.clone(), self.key.clone_key())?;
        config.send_tls13_tickets = 0;
        config.session_storage = Arc::new(NoServerSessionStorage {});
        if issuer.is_none() {
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
        }
        Ok(TlsAcceptor::from(Arc::new(config)))
    }
}

pub struct Issuer {
    key: PKey<Private>,
    cert: X509,
}

#[derive(Serialize)]
pub struct ClientCertificate {
    pub certificate_pem: String,
    pub expires_at: u64,
}

impl Issuer {
    pub fn new() -> Result<Self> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let key = PKey::from_ec_key(EcKey::generate(&group)?)?;
        let mut name = X509Name::builder()?;
        name.append_entry_by_text("CN", "Shomei TCP Client CA")?;
        let name = name.build();
        let mut cert = X509::builder()?;
        cert.set_version(2)?;
        cert.set_serial_number(&*serial_number()?)?;
        cert.set_subject_name(&name)?;
        cert.set_issuer_name(&name)?;
        cert.set_pubkey(&key)?;
        cert.set_not_before(&*Asn1Time::days_from_now(0)?)?;
        cert.set_not_after(&*Asn1Time::days_from_now(3650)?)?;
        cert.append_extension(BasicConstraints::new().critical().ca().pathlen(0).build()?)?;
        cert.append_extension(KeyUsage::new().critical().key_cert_sign().build()?)?;
        cert.sign(&key, MessageDigest::sha256())?;
        Ok(Self {
            key,
            cert: cert.build(),
        })
    }

    pub fn issue(&self, public_key: &PKeyRef<Public>, ttl: u64) -> Result<ClientCertificate> {
        let now = unix_seconds()?;
        let expires_at = now + ttl;
        let mut name = X509Name::builder()?;
        name.append_entry_by_text("CN", "Shomei TCP Client")?;
        let mut cert = X509::builder()?;
        cert.set_version(2)?;
        cert.set_serial_number(&*serial_number()?)?;
        cert.set_subject_name(&name.build())?;
        cert.set_issuer_name(self.cert.subject_name())?;
        cert.set_pubkey(public_key)?;
        cert.set_not_before(&*Asn1Time::from_unix(now.try_into()?)?)?;
        cert.set_not_after(&*Asn1Time::from_unix(expires_at.try_into()?)?)?;
        cert.append_extension(BasicConstraints::new().critical().build()?)?;
        cert.append_extension(KeyUsage::new().critical().digital_signature().build()?)?;
        cert.append_extension(ExtendedKeyUsage::new().critical().client_auth().build()?)?;
        cert.sign(&self.key, MessageDigest::sha256())?;
        let certificate_pem = String::from_utf8(cert.build().to_pem()?)?;
        Ok(ClientCertificate {
            certificate_pem,
            expires_at,
        })
    }
}

pub fn csr_key(pem: &str) -> Result<PKey<Public>> {
    ensure!(pem.len() <= 4096, "CSR exceeds 4096 bytes");
    let request = X509Req::from_pem(pem.as_bytes())?;
    let key = request.public_key()?;
    let ec_key = key.ec_key()?;
    ensure!(
        ec_key.group().curve_name() == Some(Nid::X9_62_PRIME256V1),
        "CSR must use P-256"
    );
    ec_key.check_key()?;
    ensure!(request.verify(&key)?, "invalid CSR signature");
    Ok(key)
}

pub fn unix_seconds() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn serial_number() -> Result<Asn1Integer> {
    let mut random = BigNum::new()?;
    random.rand(128, MsbOption::ONE, false)?;
    Ok(random.to_asn1_integer()?)
}

pub async fn relay(socket: TcpStream, tls: TlsAcceptor, upstream: String) {
    let Ok(Ok(mut downstream)) = timeout(HANDSHAKE_TIMEOUT, tls.accept(socket)).await else {
        return;
    };
    let Some(cert) = downstream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|chain| chain.first())
    else {
        return;
    };
    let Ok(lifetime) = remaining_lifetime(cert) else {
        return;
    };
    let _ = timeout(lifetime, async {
        match timeout(Duration::from_secs(5), TcpStream::connect(upstream)).await {
            Ok(Ok(mut upstream)) => {
                let _ = copy_bidirectional(&mut downstream, &mut upstream).await;
            }
            Ok(Err(error)) => eprintln!("TCP upstream connection failed: {error}"),
            Err(_) => eprintln!("TCP upstream connection timed out"),
        }
    })
    .await;
}

fn remaining_lifetime(cert: &CertificateDer<'_>) -> Result<Duration> {
    let cert = X509::from_der(cert.as_ref())?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let remaining = Asn1Time::from_unix(now.as_secs().try_into()?)?.diff(cert.not_after())?;
    let seconds = i64::from(remaining.days) * 86_400 + i64::from(remaining.secs);
    ensure!(seconds > 0, "client certificate expired");
    Ok(Duration::from_secs(seconds.try_into()?) - Duration::from_nanos(now.subsec_nanos().into()))
}

#[cfg(test)]
mod tests;
