use std::{
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll},
};

use axum::{Router, routing::get};
use http_body_util::Empty;
use rustls::pki_types::ServerName;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket},
    sync::mpsc,
    task::JoinHandle,
    time::{sleep, timeout},
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use tower::ServiceExt;

use super::{super::*, STALL, Stalls, watch};
use crate::{
    auth::tests::test_auth,
    config::{Limits, TcpConfig},
    tls::tests::server_fixture,
};

const CHUNK: usize = 16 * 1024;

struct Endless(Arc<AtomicBool>);

impl http_body::Body for Endless {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        Poll::Ready(Some(Ok(Frame::data(Bytes::from(vec![b'x'; CHUNK])))))
    }
}

impl Drop for Endless {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

struct Chunks(usize);

impl http_body::Body for Chunks {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        if self.0 == 0 {
            return Poll::Ready(None);
        }
        self.0 -= 1;
        Poll::Ready(Some(Ok(Frame::data(Bytes::from(vec![b'x'; CHUNK])))))
    }
}

struct Fed(mpsc::Receiver<Bytes>);

impl http_body::Body for Fed {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        self.0
            .poll_recv(cx)
            .map(|chunk| chunk.map(|chunk| Ok(Frame::data(chunk))))
    }
}

struct Gateway {
    addr: SocketAddr,
    state: Arc<App>,
    roots: rustls::RootCertStore,
    tasks: [JoinHandle<()>; 2],
    _dir: tempfile::TempDir,
}

impl Drop for Gateway {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn gateway(upstream: Router, limits: Limits) -> Gateway {
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", upstream_listener.local_addr().unwrap());
    let upstream = tokio::spawn(async move {
        axum::serve(upstream_listener, upstream).await.unwrap();
    });
    let listener = crate::listen("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let config = Config {
        origin: format!("https://localhost:{}", addr.port())
            .parse()
            .unwrap(),
        https_bind: "127.0.0.1:0".parse().unwrap(),
        tls_cert: "unused".into(),
        tls_key: "unused".into(),
        state_dir: dir.path().into(),
        identities_file: dir.path().join("identities"),
        allow_yubikey_4: false,
        http_upstream: Some(origin.parse().unwrap()),
        forwarding: false,
        http_forwarding: true,
        scopes: Default::default(),
        hostnames: Default::default(),
        http_upstreams: Default::default(),
        tcp_upstreams: Default::default(),
        protected_paths: Some(vec![ProtectedPath::Path("/api/deploy".into())]),
        protected_session_ttl_seconds: 0,
        session_ttl_seconds: 60,
        tcp: TcpConfig::default(),
        tailscale_ssh: None,
        limits,
    };
    let (auth, _) = test_auth(
        &config.origin,
        &config.state_dir,
        &config.identities_file,
        &config.limits,
        false,
    );
    let state = state_with_auth(config, auth, None).unwrap();
    let router = routes(state.clone());
    let (identity, roots) = server_fixture();
    let tls = identity.server(None).unwrap();
    let handshakes = Arc::new(Semaphore::new(16));
    let app = state.clone();
    let server = tokio::spawn(async move {
        crate::serve(listener, app.connections.clone(), move |socket, peer| {
            super::super::serve(
                socket,
                peer,
                tls.clone(),
                router.clone(),
                app.clone(),
                handshakes.clone(),
            )
        })
        .await
        .unwrap();
    });
    Gateway {
        addr,
        state,
        roots,
        tasks: [server, upstream],
        _dir: dir,
    }
}

impl Gateway {
    async fn connect(&self, alpn: &[u8], receive_buffer: Option<u32>) -> TlsStream<TcpStream> {
        let socket = TcpSocket::new_v4().unwrap();
        if let Some(size) = receive_buffer {
            socket.set_recv_buffer_size(size).unwrap();
        }
        let socket = socket.connect(self.addr).await.unwrap();
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(self.roots.clone())
            .with_no_client_auth();
        config.alpn_protocols = vec![alpn.to_vec()];
        TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from("localhost").unwrap(), socket)
            .await
            .unwrap()
    }

    fn url(&self, path: &str) -> String {
        format!("https://localhost:{}{path}", self.addr.port())
    }

    async fn released(&self) {
        let limits = Limits::default();
        let state = &self.state;
        timeout(STALL * 2, async {
            while state.connections.available() != limits.https_connections - 1
                || state.connections.clients() != 0
                || state.http_requests.available() != limits.http_requests
                || state.http_requests.clients() != 0
            {
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("a closed connection kept its slots");
    }
}

fn upstream(dropped: Arc<AtomicBool>, events: Option<mpsc::Receiver<Bytes>>) -> Router {
    let events = Arc::new(std::sync::Mutex::new(events));
    Router::new()
        .route(
            "/endless",
            get(move || {
                let dropped = dropped.clone();
                async move { Body::new(Endless(dropped)) }
            }),
        )
        .route(
            "/chunks/{count}",
            get(
                |axum::extract::Path(count): axum::extract::Path<usize>| async move {
                    Body::new(Chunks(count))
                },
            ),
        )
        .route(
            "/events",
            get(move || {
                let events = events.lock().unwrap().take().unwrap();
                async move { Body::new(Fed(events)) }
            }),
        )
}

async fn h2(
    stream: TlsStream<TcpStream>,
    window: u32,
) -> (
    hyper::client::conn::http2::SendRequest<Empty<Bytes>>,
    JoinHandle<()>,
) {
    let (client, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .initial_stream_window_size(window)
        .initial_connection_window_size(window.max(65_535))
        .handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let connection = tokio::spawn(async move {
        let _ = connection.await;
    });
    (client, connection)
}

#[tokio::test]
async fn an_http2_client_that_grants_no_window_is_disconnected() {
    let dropped = Arc::new(AtomicBool::new(false));
    let gateway = gateway(upstream(dropped.clone(), None), Limits::default()).await;
    let (mut client, mut connection) = h2(gateway.connect(b"h2", None).await, 0).await;
    let mut held = Vec::new();
    for path in ["/endless", "/_shomei/login"] {
        let request = hyper::Request::get(gateway.url(path))
            .body(Empty::new())
            .unwrap();
        let response = client.send_request(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        held.push(response);
    }
    assert_eq!(gateway.state.http_requests.clients(), 1);
    assert!(!dropped.load(Ordering::SeqCst));
    timeout(STALL * 3, &mut connection)
        .await
        .expect("a client that took no data kept its connection")
        .unwrap();
    gateway.released().await;
    timeout(Duration::from_secs(2), async {
        while !dropped.load(Ordering::SeqCst) {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the upstream response stayed open");
}

#[tokio::test]
async fn http2_data_held_behind_a_tiny_window_closes_after_shutdown() {
    let dropped = Arc::new(AtomicBool::new(false));
    let gateway = gateway(upstream(dropped, None), Limits::default()).await;
    // hyper hands the whole font to h2 once the stream has one byte of
    // window, and the body ends while its data still waits on the client.
    let (mut client, mut connection) = h2(gateway.connect(b"h2", None).await, 1).await;
    let request = hyper::Request::get(gateway.url("/_shomei/geist.woff2"))
        .body(Empty::new())
        .unwrap();
    let _held = client.send_request(request).await.unwrap();
    sleep(STALL / 2).await;
    assert!(!connection.is_finished());
    timeout(HTTP2_IDLE + STALL * 3, &mut connection)
        .await
        .expect("a stream held behind the window kept its connection")
        .unwrap();
    gateway.released().await;
}

#[tokio::test]
async fn an_http1_client_that_stops_reading_is_disconnected() {
    let dropped = Arc::new(AtomicBool::new(false));
    let gateway = gateway(upstream(dropped.clone(), None), Limits::default()).await;
    let host = format!("localhost:{}", gateway.addr.port());
    let mut fonts = gateway.connect(b"http/1.1", None).await;
    let font = format!("GET /_shomei/geist.woff2 HTTP/1.1\r\nHost: {host}\r\n\r\n");
    fonts.write_all(font.repeat(64).as_bytes()).await.unwrap();
    // Small responses end before the socket backs up, so hyper waits to flush
    // between them with no body alive.
    let mut pages = gateway.connect(b"http/1.1", None).await;
    let page = format!("GET /_shomei/auth.css HTTP/1.1\r\nHost: {host}\r\n\r\n");
    let pipelined = page.repeat(2048);
    let _ = timeout(
        Duration::from_millis(500),
        pages.write_all(pipelined.as_bytes()),
    )
    .await;
    let mut endless = gateway.connect(b"http/1.1", None).await;
    let request = format!("GET /endless HTTP/1.1\r\nHost: {host}\r\n\r\n");
    endless.write_all(request.as_bytes()).await.unwrap();
    sleep(Duration::from_millis(200)).await;
    assert_eq!(gateway.state.connections.clients(), 1);
    assert_eq!(
        gateway.state.http_requests.available(),
        Limits::default().http_requests - 1
    );
    gateway.released().await;
    assert!(dropped.load(Ordering::SeqCst));
    for mut stream in [fonts, pages, endless] {
        let mut rest = Vec::new();
        let read = timeout(Duration::from_secs(5), stream.read_to_end(&mut rest)).await;
        assert!(read.is_ok(), "the gateway left a stalled connection open");
    }
}

#[tokio::test]
async fn a_tunnel_keeps_its_connection_through_the_idle_shutdown() {
    // An HTTP/2 CONNECT tunnel is a stream of the connection that carries it.
    // Its response body is gone as soon as the tunnel opens, so only the
    // tunnel itself shows that the connection still has work in flight.
    let stalls = Stalls::new();
    let requests = AtomicU64::new(0);
    let tunnel = stalls.begin();
    let mut watched = std::pin::pin!(watch(
        std::future::pending::<()>(),
        &stalls,
        Some(&requests),
        |_| {},
    ));
    let open = timeout(HTTP2_IDLE + STALL * 3, watched.as_mut()).await;
    assert!(open.is_err(), "a connection with a live tunnel was closed");
    drop(tunnel);
    timeout(STALL * 3, watched)
        .await
        .expect("a drained connection stayed open");
}

#[tokio::test]
async fn an_idle_event_stream_stays_open() {
    let (events, received) = mpsc::channel(1);
    let dropped = Arc::new(AtomicBool::new(false));
    let gateway = gateway(upstream(dropped, Some(received)), Limits::default()).await;
    let (mut client, connection) = h2(gateway.connect(b"h2", None).await, 65_535).await;
    let request = hyper::Request::get(gateway.url("/events"))
        .body(Empty::new())
        .unwrap();
    events.send(Bytes::from_static(b"first")).await.unwrap();
    let mut body = client.send_request(request).await.unwrap().into_body();
    let first = body.frame().await.unwrap().unwrap().into_data().unwrap();
    assert_eq!(first, "first");
    sleep(STALL * 3 + HTTP2_IDLE).await;
    assert!(!connection.is_finished());
    events.send(Bytes::from_static(b"last")).await.unwrap();
    drop(events);
    assert_eq!(body.collect().await.unwrap().to_bytes(), "last");
}

#[tokio::test]
async fn a_slow_download_that_keeps_moving_stays_open() {
    let dropped = Arc::new(AtomicBool::new(false));
    let gateway = gateway(upstream(dropped, None), Limits::default()).await;

    let (mut client, _connection) = h2(gateway.connect(b"h2", None).await, 2 * CHUNK as u32).await;
    let chunks = 16;
    let request = hyper::Request::get(gateway.url(&format!("/chunks/{chunks}")))
        .body(Empty::new())
        .unwrap();
    let mut body = client.send_request(request).await.unwrap().into_body();
    let started = Instant::now();
    let (mut total, mut pause_at) = (0, CHUNK);
    while let Some(frame) = body.frame().await {
        total += frame.unwrap().into_data().unwrap().len();
        if total >= pause_at {
            pause_at += CHUNK;
            sleep(STALL / 4).await;
        }
    }
    assert_eq!(total, chunks * CHUNK);
    assert!(started.elapsed() > STALL * 3);

    let mut stream = gateway.connect(b"http/1.1", Some(64 * 1024)).await;
    let chunks = 128;
    let request = format!(
        "GET /chunks/{chunks} HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
        gateway.addr.port()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let started = Instant::now();
    let (mut total, mut pause_at) = (0, 64 * 1024);
    let mut buffer = vec![0; 64 * 1024];
    loop {
        let read = stream.read(&mut buffer).await.unwrap();
        if read == 0 {
            break;
        }
        total += read;
        if total >= pause_at {
            pause_at += 64 * 1024;
            sleep(STALL / 10).await;
        }
    }
    assert!(total > chunks * CHUNK, "{total}");
    assert!(started.elapsed() > STALL * 2);
}

#[tokio::test]
async fn one_client_address_holds_at_most_its_share_of_proxied_requests() {
    let release = Arc::new(Semaphore::new(0));
    let hold = release.clone();
    let upstream = Router::new()
        .route(
            "/hold",
            get(move || {
                let hold = hold.clone();
                async move {
                    hold.acquire().await.unwrap().forget();
                    "held"
                }
            }),
        )
        .route("/", get(|| async { "ok" }));
    let limits = Limits {
        http_requests: 4,
        per_ip_percent: 50,
        ..Limits::default()
    };
    let gateway = gateway(upstream, limits).await;
    let router = routes(gateway.state.clone());
    let send = |client: &str, path: &str| {
        let request = axum::http::Request::get(path)
            .header(HOST, "localhost")
            .extension(Peer(client.parse().unwrap()))
            .body(Body::empty())
            .unwrap();
        let router = router.clone();
        tokio::spawn(async move {
            let response = router.oneshot(request).await.unwrap();
            let status = response.status();
            (
                status,
                response.into_body().collect().await.unwrap().to_bytes(),
            )
        })
    };
    let held = [send("2001:db8::1", "/hold"), send("2001:db8::2", "/hold")];
    timeout(Duration::from_secs(2), async {
        while gateway.state.http_requests.available() != 2 {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let over = send("2001:db8::3", "/").await.unwrap();
    assert_eq!(over.0, StatusCode::SERVICE_UNAVAILABLE);
    let other = send("2001:db8:0:1::1", "/").await.unwrap();
    assert_eq!(other, (StatusCode::OK, Bytes::from_static(b"ok")));
    release.add_permits(2);
    for request in held {
        assert_eq!(request.await.unwrap().0, StatusCode::OK);
    }
    assert_eq!(gateway.state.http_requests.clients(), 0);
    assert_eq!(gateway.state.http_requests.available(), 4);
}
