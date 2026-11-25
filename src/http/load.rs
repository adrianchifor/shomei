use std::time::Instant;

use http_body_util::Empty;
use rcgen::{KeyPair, PublicKeyData, SubjectPublicKeyInfo, generate_simple_self_signed};
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, pem::PemObject},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinSet,
    time::{Instant as Deadline, sleep_until},
};
use tokio_rustls::TlsConnector;

use super::*;
use crate::{
    listen,
    tls::{self, Identity},
};

const CLIENTS: usize = 2_000;
const ROUNDS: usize = 6;
const INTERVAL_MS: u64 = 500;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "loopback load test"]
async fn relay_load() {
    let dir = tempfile::tempdir().unwrap();
    let server = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    std::fs::write(&cert, server.cert.pem()).unwrap();
    std::fs::write(&key, server.signing_key.serialize_pem()).unwrap();
    let identity = Identity::load(&cert, &key).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(server.cert.der().clone()).unwrap();

    http_load(&identity, roots.clone(), dir.path()).await;
    tcp_load(&identity, roots).await;
}

async fn http_load(identity: &Identity, roots: RootCertStore, dir: &std::path::Path) {
    let upstream = listen("127.0.0.1:0".parse().unwrap()).unwrap();
    let upstream_name = format!("http://{}", upstream.local_addr().unwrap());
    let backend = tokio::spawn(async move {
        axum::serve(upstream, Router::new().fallback(|| async { "pong" }))
            .await
            .unwrap();
    });
    let listener = listen("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    let origin = format!("https://localhost:{}", addr.port());
    let token = dir.join("token");
    std::fs::write(&token, "2afb18754686de93bc41fb0be433826c").unwrap();
    let config = Config {
        origin: origin.parse().unwrap(),
        https_bind: addr,
        tls_cert: dir.join("cert.pem"),
        tls_key: dir.join("key.pem"),
        state_dir: dir.into(),
        enrollment_token_file: Some(token),
        enrollment_tokens_file: None,
        http_upstream: Some(upstream_name.parse().unwrap()),
        session_ttl_seconds: 600,
        tcp: None,
        limits: Default::default(),
    };
    let limit = config.limits.https_connections;
    let handshakes = Arc::new(Semaphore::new(config.limits.tls_handshakes));
    let state = super::state(config, None).unwrap();
    let router = routes(state.clone());
    let tls = identity.server(None).unwrap();
    let gateway = tokio::spawn(crate::serve(listener, limit, move |socket, peer| {
        super::serve(
            socket,
            peer,
            tls.clone(),
            router.clone(),
            handshakes.clone(),
        )
    }));
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(config));
    let uri: Uri = format!("{origin}/resource").parse().unwrap();

    let startup = Instant::now();
    let opening = Arc::new(Semaphore::new(128));
    let mut clients = JoinSet::new();
    for _ in 0..CLIENTS {
        let opening = opening.clone();
        let connector = connector.clone();
        let (cookie, _) = state.sessions.issue().unwrap();
        let cookie =
            HeaderValue::from_str(cookie.to_str().unwrap().split_once(';').unwrap().0).unwrap();
        let uri = uri.clone();
        clients.spawn(async move {
            let _slot = opening.acquire_owned().await.unwrap();
            let tls = connect(addr, connector).await;
            assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
            let (mut client, driving) =
                hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
                    .await
                    .unwrap();
            let connection = tokio::spawn(driving);
            http_exchange(&mut client, uri, &cookie).await;
            (client, cookie, connection)
        });
    }
    let clients = clients.join_all().await;
    println!(
        "HTTPS connected {CLIENTS} clients in {:.2?}",
        startup.elapsed()
    );
    let mut jobs = JoinSet::new();
    let start = Deadline::now() + Duration::from_millis(50);
    for (index, (mut client, cookie, connection)) in clients.into_iter().enumerate() {
        let uri = uri.clone();
        jobs.spawn(async move {
            let mut latencies = Vec::with_capacity(ROUNDS);
            for round in 0..ROUNDS {
                sleep_until(slot(start, index, round)).await;
                let request_start = Instant::now();
                http_exchange(&mut client, uri.clone(), &cookie).await;
                latencies.push(request_start.elapsed());
            }
            connection.abort();
            latencies
        });
    }
    report("HTTPS HTTP/2", start, jobs.join_all().await);
    gateway.abort();
    backend.abort();
}

async fn http_exchange(
    client: &mut hyper::client::conn::http2::SendRequest<Empty<Bytes>>,
    uri: Uri,
    cookie: &HeaderValue,
) {
    let request = hyper::Request::get(uri)
        .header(COOKIE, cookie)
        .body(Empty::new())
        .unwrap();
    let response = client.send_request(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "pong"
    );
}

async fn tcp_load(identity: &Identity, roots: RootCertStore) {
    let upstream = listen("127.0.0.1:0".parse().unwrap()).unwrap();
    let upstream_addr: Arc<str> = upstream.local_addr().unwrap().to_string().into();
    let backend = tokio::spawn(crate::serve(upstream, 4096, |mut socket, _| async move {
        socket.set_nodelay(true).unwrap();
        let mut bytes = [0; 4];
        while socket.read_exact(&mut bytes).await.is_ok() {
            if socket.write_all(&bytes).await.is_err() {
                break;
            }
        }
    }));
    let listener = listen("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    let issuer = Issuer::new().unwrap();
    let handshakes = Arc::new(Semaphore::new(512));
    let tls = identity.server(Some(&issuer)).unwrap();
    let gateway = tokio::spawn(crate::serve(listener, 4096, move |socket, _| {
        tls::relay(
            socket,
            tls.clone(),
            upstream_addr.clone(),
            handshakes.clone(),
        )
    }));

    let client_key = KeyPair::generate().unwrap();
    let public = SubjectPublicKeyInfo::from_der(&client_key.subject_public_key_info()).unwrap();
    let cert = issuer.issue(&public, 300).unwrap();
    let cert = CertificateDer::from_pem_slice(cert.certificate_pem.as_bytes()).unwrap();
    let private = PrivatePkcs8KeyDer::from(client_key.serialize_der()).into();
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(vec![cert], private)
        .unwrap();
    let connector = TlsConnector::from(Arc::new(config));
    let startup = Instant::now();
    let opening = Arc::new(Semaphore::new(128));
    let mut clients = JoinSet::new();
    for _ in 0..CLIENTS {
        let connector = connector.clone();
        let opening = opening.clone();
        clients.spawn(async move {
            let _slot = opening.acquire_owned().await.unwrap();
            let mut client = connect(addr, connector).await;
            tcp_exchange(&mut client).await;
            client
        });
    }
    let clients = clients.join_all().await;
    println!(
        "mTLS connected {CLIENTS} clients in {:.2?}",
        startup.elapsed()
    );
    let mut jobs = JoinSet::new();
    let start = Deadline::now() + Duration::from_millis(50);
    for (index, mut client) in clients.into_iter().enumerate() {
        jobs.spawn(async move {
            let mut latencies = Vec::with_capacity(ROUNDS);
            for round in 0..ROUNDS {
                sleep_until(slot(start, index, round)).await;
                let request_start = Instant::now();
                tcp_exchange(&mut client).await;
                latencies.push(request_start.elapsed());
            }
            latencies
        });
    }
    report("TCP mTLS", start, jobs.join_all().await);
    gateway.abort();
    backend.abort();
}

async fn connect(
    addr: SocketAddr,
    connector: TlsConnector,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let connection = TcpStream::connect(addr).await.unwrap();
    connection.set_nodelay(true).unwrap();
    connector
        .connect(ServerName::try_from("localhost").unwrap(), connection)
        .await
        .unwrap()
}

async fn tcp_exchange(client: &mut tokio_rustls::client::TlsStream<TcpStream>) {
    client.write_all(b"ping").await.unwrap();
    let mut response = [0; 4];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"ping");
}

fn slot(start: Deadline, index: usize, round: usize) -> Deadline {
    start + Duration::from_millis((index as u64 % INTERVAL_MS) + round as u64 * INTERVAL_MS)
}

fn report(label: &str, start: Deadline, batches: Vec<Vec<Duration>>) {
    let mut values: Vec<_> = batches.into_iter().flatten().collect();
    values.sort_unstable();
    assert_eq!(values.len(), CLIENTS * ROUNDS);
    let percentile = |p| values[(values.len() - 1) * p / 100];
    println!(
        "{label}: {CLIENTS} clients, {:.0} ops/s, p50 {:?}, p95 {:?}, p99 {:?}",
        values.len() as f64 / start.elapsed().as_secs_f64(),
        percentile(50),
        percentile(95),
        percentile(99)
    );
}
