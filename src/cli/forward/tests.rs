use std::convert::Infallible;

use http_body_util::{BodyExt, Full};
use hyper::{StatusCode, body::Incoming, service::service_fn};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{Semaphore, watch},
};

use super::*;
use crate::{
    forward,
    tls::{csr_key, tests::server_fixture},
};

#[tokio::test]
async fn fixed_named_and_scoped_tcp_share_an_mtls_listener() {
    let (identity, roots) = server_fixture();
    let https = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let named_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let named_backend = named_listener.local_addr().unwrap().to_string();
    let fixed_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fixed_backend = fixed_listener.local_addr().unwrap().to_string();
    let https_addr = https.local_addr().unwrap();
    let addr = listener.local_addr().unwrap();
    let proxy = Arc::new(
        forward::Gateway::new(
            crate::config::TcpConfig {
                upstream: Some(fixed_backend.clone()),
                ..Default::default()
            },
            toml::from_str(&format!(
                r#"
        [fleet]
        cidrs = ["127.0.0.1/32"]
        ports = [{}]
    "#,
                https_addr.port()
            ))
            .unwrap(),
            8,
        )
        .unwrap()
        .with_tcp_upstreams(
            [
                ("ops.example.test:22".into(), named_backend.clone()),
                ("jobs.example.test:22".into(), named_backend),
            ]
            .into(),
        )
        .unwrap(),
    );
    forward::validate_scopes(&proxy.scopes).unwrap();
    let (generation, allowed) = watch::channel(0);
    let tls = identity.server(Some(&proxy.issuer)).unwrap();
    let handshakes = Arc::new(Semaphore::new(8));
    let proxy_for_server = proxy.clone();
    let gateway = tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            tokio::spawn(forward::serve(
                socket,
                tls.clone(),
                proxy_for_server.clone(),
                handshakes.clone(),
                allowed.clone(),
            ));
        }
    });
    let origin_tls = identity.server(None).unwrap();
    let https_server = tokio::spawn(async move {
        let (socket, _) = https.accept().await.unwrap();
        let stream = origin_tls.accept(socket).await.unwrap();
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(
                TokioIo::new(stream),
                service_fn(|request: Request<Incoming>| async move {
                    assert_eq!(request.uri(), "/check");
                    Ok::<_, Infallible>(hyper::Response::new(Full::new(Bytes::from_static(
                        b"https ok",
                    ))))
                }),
            )
            .await;
    });

    let no_auth = TlsConnector::from(Arc::new(
        tls_client(roots.clone()).unwrap().with_no_client_auth(),
    ));
    if let Ok(mut stream) = no_auth
        .connect(
            ServerName::try_from("localhost").unwrap(),
            TcpStream::connect(addr).await.unwrap(),
        )
        .await
    {
        assert!(
            timeout(Duration::from_secs(2), stream.read(&mut [0]))
                .await
                .unwrap()
                .is_err()
        );
    }
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let csr = CertificateParams::default()
        .serialize_request(&key)
        .unwrap()
        .pem()
        .unwrap();
    let issued = proxy
        .issuer
        .issue(&csr_key(&csr).unwrap(), 30, 0, 0)
        .unwrap();
    let credentials = Credentials {
        metadata: CredentialMetadata {
            origin: https_origin("https://localhost:8443").unwrap(),
            endpoint: format!("localhost:{}", addr.port()),
            expires_at: issued.expires_at,
            direct: false,
        },
        certificate: issued.certificate_pem,
        key: Zeroizing::new(key.serialize_pem()),
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("creds");
    credentials.write(&path).unwrap();
    assert!(credentials.write(&path).is_err());
    let tunnel = Tunnel::new(Credentials::read(&path).unwrap(), roots.clone()).unwrap();
    let named_target = destination("ops.example.test:22").unwrap();
    assert!(
        tunnel
            .open(named_target.clone())
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("403")
    );
    let id = proxy
        .tcp_id(&crate::config::Endpoint::from_authority(&named_target, None).unwrap())
        .unwrap();
    let issued = proxy
        .issuer
        .issue(&csr_key(&csr).unwrap(), 30, 0, id)
        .unwrap();
    let mut named_creds = Credentials::read(&path).unwrap();
    named_creds.metadata.expires_at = issued.expires_at;
    named_creds.certificate = issued.certificate_pem;
    let named_tunnel = Tunnel::new(named_creds, roots.clone()).unwrap();
    assert!(
        named_tunnel
            .open(destination("jobs.example.test:22").unwrap())
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("403")
    );
    let echo = tokio::spawn(async move {
        let (mut socket, _) = named_listener.accept().await.unwrap();
        socket.write_all(b"named").await.unwrap();
    });
    let mut named = named_tunnel.open(named_target).await.unwrap();
    let mut reply = [0; 5];
    named.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"named");
    echo.await.unwrap();
    let fixed_target = destination(&fixed_backend).unwrap();
    assert!(
        tunnel
            .open(fixed_target.clone())
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("403")
    );
    let issued = proxy
        .issuer
        .issue(&csr_key(&csr).unwrap(), 30, 0, forward::FIXED_TCP_GRANT)
        .unwrap();
    let mut fixed_creds = Credentials::read(&path).unwrap();
    fixed_creds.metadata.expires_at = issued.expires_at;
    fixed_creds.metadata.direct = true;
    fixed_creds.certificate = issued.certificate_pem;
    let fixed = Tunnel::new(fixed_creds, roots.clone()).unwrap();
    let echo = tokio::spawn(async move {
        let (mut socket, _) = fixed_listener.accept().await.unwrap();
        socket.write_all(b"fixed").await.unwrap();
    });
    let mut stream = fixed.open(fixed_target).await.unwrap();
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"fixed");
    echo.await.unwrap();
    let client = tunnel
        .tls
        .connect(
            ServerName::try_from("localhost").unwrap(),
            TcpStream::connect(addr).await.unwrap(),
        )
        .await
        .unwrap();
    let (mut http, conn) = hyper::client::conn::http1::handshake(TokioIo::new(client))
        .await
        .unwrap();
    tokio::spawn(conn);
    let req = |uri: String| {
        Request::post(uri)
            .header(HOST, "other.invalid")
            .header(hyper::header::PROXY_AUTHORIZATION, "discard")
            .body(Full::new(Bytes::from_static(b"hello")))
            .unwrap()
    };
    let response = http
        .send_request(req(format!("http://{https_addr}/status?q=1")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);

    let disallowed_port = if https_addr.port() == 22 { 23 } else { 22 };
    let denied = tunnel
        .open(destination(&format!("127.0.0.1:{disallowed_port}")).unwrap())
        .await;
    assert!(denied.err().unwrap().to_string().contains("403"));
    let stream = tunnel
        .open(destination(&https_addr.to_string()).unwrap())
        .await
        .unwrap();
    let inner = TlsConnector::from(Arc::new(tls_client(roots).unwrap().with_no_client_auth()))
        .connect(ServerName::try_from("localhost").unwrap(), stream)
        .await
        .unwrap();
    let (mut https, conn) = hyper::client::conn::http1::handshake(TokioIo::new(inner))
        .await
        .unwrap();
    let mut relayed = tokio::spawn(conn);
    let response = https
        .send_request(
            Request::get("/check")
                .header(HOST, "localhost")
                .body(Empty::<Bytes>::new())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "https ok"
    );
    assert!(!relayed.is_finished());
    generation.send_replace(1);
    timeout(Duration::from_secs(2), &mut relayed)
        .await
        .unwrap()
        .unwrap()
        .ok();
    gateway.abort();
    https_server.abort();
}

#[test]
fn mtls_export_checks_the_output_parent_before_approval() {
    let dir = tempfile::tempdir().unwrap();
    assert!(check_output_dir(&dir.path().join("creds")).is_ok());
    assert!(check_output_dir(Path::new("creds-that-do-not-exist")).is_ok());
    assert!(check_output_dir(dir.path()).is_err());
    let missing = check_output_dir(&dir.path().join("missing/creds")).unwrap_err();
    assert!(missing.to_string().contains("parent directory"));
    let file = dir.path().join("file");
    fs::write(&file, b"").unwrap();
    assert!(check_output_dir(&file.join("creds")).is_err());
}
