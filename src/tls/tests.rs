use openssl::x509::extension::SubjectAlternativeName;
use rustls::{
    ClientConfig,
    pki_types::{PrivatePkcs8KeyDer, ServerName},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::TlsConnector;

use super::*;

#[tokio::test]
async fn tcp_requires_the_issued_client_key_and_closes_at_expiry() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap().to_string();
    let echo = tokio::spawn(async move {
        let (mut socket, _) = upstream.accept().await.unwrap();
        let mut message = [0; 4];
        socket.read_exact(&mut message).await.unwrap();
        socket.write_all(&message).await.unwrap();
        assert_eq!(socket.read(&mut message).await.unwrap(), 0);
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let issuer = Issuer::new().unwrap();
    let identity = server_identity();
    let mut roots = RootCertStore::empty();
    roots.add(identity.certs[0].clone()).unwrap();
    let tls = identity.server(Some(&issuer)).unwrap();
    let gateway = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            tokio::spawn(relay(socket, tls.clone(), upstream_addr.clone()));
        }
    });
    let builder = || ClientConfig::builder().with_root_certificates(roots.clone());
    let connect = |config| async move {
        let socket = TcpStream::connect(addr).await.unwrap();
        TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from("localhost").unwrap(), socket)
            .await
    };
    if let Ok(mut unverified) = connect(builder().with_no_client_auth()).await {
        assert!(
            timeout(Duration::from_secs(1), unverified.read(&mut [0; 1]))
                .await
                .unwrap()
                .is_err()
        );
    }

    let client_key = p256();
    let mut req = X509Req::builder().unwrap();
    req.set_pubkey(&client_key).unwrap();
    req.sign(&client_key, MessageDigest::sha256()).unwrap();
    let csr = String::from_utf8(req.build().to_pem().unwrap()).unwrap();
    let key = csr_key(&csr).unwrap();
    let granted = issuer.issue(&key, 3).unwrap();
    let cert = X509::from_pem(granted.certificate_pem.as_bytes()).unwrap();
    assert!(cert.public_key().unwrap().public_eq(&client_key));
    let chain = vec![CertificateDer::from(cert.to_der().unwrap())];
    assert!(
        builder()
            .with_client_auth_cert(chain.clone(), private_key(&p256()))
            .is_err()
    );
    let mut verified = connect(
        builder()
            .with_client_auth_cert(chain.clone(), private_key(&client_key))
            .unwrap(),
    )
    .await
    .unwrap();
    verified.write_all(b"ping").await.unwrap();
    let mut payload = [0; 4];
    timeout(Duration::from_secs(1), verified.read_exact(&mut payload))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&payload, b"ping");
    let eof = timeout(Duration::from_secs(5), verified.read(&mut payload))
        .await
        .unwrap();
    assert!(matches!(eof, Ok(0) | Err(_)));
    assert!(unix_seconds().unwrap() >= granted.expires_at);
    echo.await.unwrap();
    gateway.abort();
}

fn server_identity() -> Identity {
    let key = p256();
    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_text("CN", "localhost").unwrap();
    let name = name.build();
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_serial_number(&serial_number().unwrap()).unwrap();
    cert.set_subject_name(&name).unwrap();
    cert.set_issuer_name(&name).unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    let name = SubjectAlternativeName::new()
        .dns("localhost")
        .build(&cert.x509v3_context(None, None))
        .unwrap();
    cert.append_extension(name).unwrap();
    cert.sign(&key, MessageDigest::sha256()).unwrap();
    Identity {
        certs: vec![CertificateDer::from(cert.build().to_der().unwrap())],
        key: private_key(&key),
    }
}

fn private_key(key: &PKey<Private>) -> PrivateKeyDer<'static> {
    PrivatePkcs8KeyDer::from(key.private_key_to_pkcs8().unwrap()).into()
}

fn p256() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}
