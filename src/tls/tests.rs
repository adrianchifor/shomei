use rcgen::{PKCS_ECDSA_P384_SHA384, generate_simple_self_signed};
use rustls::{
    ClientConfig,
    pki_types::{PrivatePkcs8KeyDer, ServerName},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Semaphore, watch},
    time::timeout,
};
use tokio_rustls::TlsConnector;

use super::*;
use crate::forward::{self, FIXED_TCP_GRANT, Gateway};

#[tokio::test]
async fn tcp_requires_the_issued_client_key_and_closes_at_expiry() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap().to_string();
    let echo = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut socket, _) = upstream.accept().await.unwrap();
            let mut message = [0; 4];
            socket.read_exact(&mut message).await.unwrap();
            socket.write_all(&message).await.unwrap();
            assert_eq!(socket.read(&mut message).await.unwrap(), 0);
        }
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let proxy = Arc::new(
        Gateway::new(
            crate::config::TcpConfig {
                upstream: Some(upstream_addr),
                ..Default::default()
            },
            Default::default(),
            32,
        )
        .unwrap(),
    );
    let issuing_proxy = proxy.clone();
    let identity = server_identity();
    let mut roots = RootCertStore::empty();
    roots.add(identity.certs[0].clone()).unwrap();
    let tls = identity.server(Some(&proxy.issuer)).unwrap();
    let handshakes = Arc::new(Semaphore::new(32));
    let (generation, allowed) = watch::channel(0);
    let gateway = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            tokio::spawn(forward::serve(
                socket,
                tls.clone(),
                proxy.clone(),
                handshakes.clone(),
                allowed.clone(),
            ));
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

    let client_key = KeyPair::generate().unwrap();
    let req = named_certificate("Fixture Client")
        .serialize_request(&client_key)
        .unwrap();
    let key = csr_key(&req.pem().unwrap()).unwrap();
    let wrong_curve = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
    let wrong_csr = named_certificate("Fixture Client")
        .serialize_request(&wrong_curve)
        .unwrap();
    assert!(csr_key(&wrong_csr.pem().unwrap()).is_err());
    let granted = issuing_proxy
        .issuer
        .issue(&key, 3, 0, FIXED_TCP_GRANT)
        .unwrap();
    let cert = CertificateDer::from_pem_slice(granted.certificate_pem.as_bytes()).unwrap();
    let (_, parsed) = parse_x509_certificate(cert.as_ref()).unwrap();
    assert_eq!(
        parsed.public_key().raw,
        client_key.subject_public_key_info()
    );
    let chain = vec![cert];
    assert!(
        builder()
            .with_client_auth_cert(chain.clone(), private_key(&KeyPair::generate().unwrap()))
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

    let granted = issuing_proxy
        .issuer
        .issue(&key, 30, 0, FIXED_TCP_GRANT)
        .unwrap();
    let cert = CertificateDer::from_pem_slice(granted.certificate_pem.as_bytes()).unwrap();
    let mut verified = connect(
        builder()
            .with_client_auth_cert(vec![cert], private_key(&client_key))
            .unwrap(),
    )
    .await
    .unwrap();
    verified.write_all(b"ping").await.unwrap();
    timeout(Duration::from_secs(1), verified.read_exact(&mut payload))
        .await
        .unwrap()
        .unwrap();
    generation.send_replace(1);
    let eof = timeout(Duration::from_secs(1), verified.read(&mut payload))
        .await
        .unwrap();
    assert!(matches!(eof, Ok(0) | Err(_)));
    assert!(unix_seconds().unwrap() < granted.expires_at);
    echo.await.unwrap();
    gateway.abort();
}

fn server_identity() -> Identity {
    let signed = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    Identity {
        certs: vec![signed.cert.der().clone()],
        key: private_key(&signed.signing_key),
    }
}

pub(crate) fn server_fixture() -> (Identity, RootCertStore) {
    let identity = server_identity();
    let mut roots = RootCertStore::empty();
    roots.add(identity.certs[0].clone()).unwrap();
    (identity, roots)
}

fn private_key(key: &KeyPair) -> PrivateKeyDer<'static> {
    PrivatePkcs8KeyDer::from(key.serialize_der()).into()
}
