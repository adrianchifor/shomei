use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use axum::http;
use http_body_util::{Empty, Full};
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
use serde_json::{Value, json};
use tokio::net::{TcpListener, UnixListener};
use tokio_rustls::TlsConnector;
use tower::ServiceExt;

use super::*;
use crate::{
    auth::tests::{TestSigner, test_auth},
    config::{TailscaleSshConfig, TcpConfig},
    forward,
    tls::tests::server_fixture,
};

#[tokio::test]
async fn approves_one_deploy_and_allows_only_reads_with_its_cookie() {
    approves_one_deploy(false).await;
}

#[tokio::test]
async fn attested_yubikey_4_approves_deploy_and_tcp_grants() {
    approves_one_deploy(true).await;
}

#[tokio::test]
async fn http_forward_requires_signed_approvals_or_scoped_sessions() {
    let dir = tempfile::tempdir().unwrap();
    let origin = "https://localhost:8443".parse().unwrap();
    let identities_file = dir.path().join("identities");
    let config = Config {
        origin,
        https_bind: "127.0.0.1:0".parse().unwrap(),
        tls_cert: "unused".into(),
        tls_key: "unused".into(),
        state_dir: dir.path().into(),
        identities_file: identities_file.clone(),
        allow_yubikey_4: false,
        http_upstream: None,
        browser_action: None,
        session_ttl_seconds: 60,
        tcp: None,
        forward: None,
        tailscale_ssh: None,
        limits: Default::default(),
    };
    let (auth, signer) = test_auth(
        &config.origin,
        &config.state_dir,
        &identities_file,
        &config.limits,
        false,
    );
    let plain = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let secure = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let plain_addr = plain.local_addr().unwrap();
    let secure_addr = secure.local_addr().unwrap();
    let addr = listener.local_addr().unwrap();
    let gateway = Arc::new(
        forward::Gateway::new(
            toml::from_str(&format!(
                r#"
        http_bind = "{addr}"
        [scopes.web]
        cidrs = ["127.0.0.1/32"]
        ports = [{}, {}]
        http_ports = [{}]
        https_ports = [{}]
    "#,
                plain_addr.port(),
                secure_addr.port(),
                plain_addr.port(),
                secure_addr.port(),
            ))
            .unwrap(),
            16,
        )
        .unwrap(),
    );
    let state = state_with_auth(config, None, auth, Some(gateway.clone())).unwrap();
    let router = routes(state.clone());
    let (identity, roots) = server_fixture();
    let tls = identity.http1_server().unwrap();
    let app = state.clone();
    let proxy = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        forward::serve_http(socket, tls, gateway, Arc::new(Semaphore::new(16)), app).await;
    });
    let http_server = tokio::spawn(async move {
        let app = Router::new().fallback(move |request: Request| async move {
            assert_eq!(request.uri(), "/path?q=1");
            assert_eq!(request.headers()[HOST], plain_addr.to_string());
            assert_eq!(request.headers()[AUTHORIZATION], "Bearer upstream");
            assert!(!request.headers().contains_key(PROXY_AUTHORIZATION));
            "forwarded"
        });
        axum::serve(plain, app).await.unwrap();
    });
    let tls = identity.http1_server().unwrap();
    let https_server = tokio::spawn(async move {
        let (socket, _) = secure.accept().await.unwrap();
        let tls = tls.accept(socket).await.unwrap();
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(
                TokioIo::new(tls),
                service_fn(|request: hyper::Request<Incoming>| async move {
                    assert_eq!(request.uri(), "/tls");
                    assert!(!request.headers().contains_key(PROXY_AUTHORIZATION));
                    Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(
                        Bytes::from_static(b"tunneled"),
                    )))
                }),
            )
            .await;
    });
    let tls = TlsConnector::from(Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));
    let host = ServerName::try_from("localhost").unwrap();
    let socket = tls
        .connect(host.clone(), TcpStream::connect(addr).await.unwrap())
        .await
        .unwrap();
    let (mut client, connection) = hyper::client::conn::http1::handshake(TokioIo::new(socket))
        .await
        .unwrap();
    tokio::spawn(connection.with_upgrades());
    let request = |authorization: &str| {
        hyper::Request::get(format!("http://{plain_addr}/path?q=1"))
            .header(HOST, "replaced.test")
            .header(AUTHORIZATION, "Bearer upstream")
            .header(PROXY_AUTHORIZATION, authorization)
            .body(Empty::<Bytes>::new())
            .unwrap()
    };
    let unauthorized = client.send_request(request("")).await.unwrap();
    assert_eq!(
        unauthorized.status(),
        StatusCode::PROXY_AUTHENTICATION_REQUIRED
    );
    assert_eq!(unauthorized.headers()[PROXY_AUTHENTICATE], "Shomei");
    let challenge = async |counter| {
        let start = send(
            &router,
            post_json("/_shomei/api/auth/start", json!({ "forward": true })),
        )
        .await;
        assert_eq!(start.status(), StatusCode::OK);
        signed_answer(&signer, &json_body(start).await, counter)
    };
    let answer = challenge(1).await;
    let assertion = format!("Shomei {}", URL_SAFE_NO_PAD.encode(answer.to_string()));
    let approved = client.send_request(request(&assertion)).await.unwrap();
    assert_eq!(
        approved.into_body().collect().await.unwrap().to_bytes(),
        "forwarded"
    );
    assert_eq!(
        client
            .send_request(request(&assertion))
            .await
            .unwrap()
            .status(),
        StatusCode::PROXY_AUTHENTICATION_REQUIRED
    );

    let issued = send(
        &router,
        post_json("/_shomei/api/auth/finish", challenge(2).await),
    )
    .await;
    assert_eq!(issued.status(), StatusCode::OK);
    assert!(!issued.headers().contains_key(SET_COOKIE));
    let issued = json_body(issued).await;
    let token = issued["proxy_session"].as_str().unwrap();
    assert!(token.starts_with("web."));
    let authorization = format!("Shomei-Session {token}");
    let tampered = authorization.replace(" web.", " other.");
    assert_eq!(
        client
            .send_request(request(&tampered))
            .await
            .unwrap()
            .status(),
        StatusCode::PROXY_AUTHENTICATION_REQUIRED
    );
    let approved = client.send_request(request(&authorization)).await.unwrap();
    assert_eq!(
        approved.into_body().collect().await.unwrap().to_bytes(),
        "forwarded"
    );

    let csr = CertificateParams::default()
        .serialize_request(&KeyPair::generate().unwrap())
        .unwrap()
        .pem()
        .unwrap();
    let start = send(
        &router,
        post_json(
            "/_shomei/api/auth/start",
            json!({ "forward": true, "client_csr_pem": csr }),
        ),
    )
    .await;
    assert_eq!(start.status(), StatusCode::OK);
    let answer = signed_answer(&signer, &json_body(start).await, 3);
    let issued = send(&router, post_json("/_shomei/api/auth/finish", answer)).await;
    assert_eq!(issued.status(), StatusCode::OK);
    let issued = json_body(issued).await;
    let leaf =
        CertificateDer::from_pem_slice(issued["certificate_pem"].as_str().unwrap().as_bytes())
            .unwrap();
    assert_eq!(crate::tls::client_grant(&leaf).unwrap().1, 0);

    let connect = |addr: SocketAddr| {
        hyper::Request::builder()
            .method(Method::CONNECT)
            .uri(Uri::builder().authority(addr.to_string()).build().unwrap())
            .header(HOST, addr.to_string())
            .header(PROXY_AUTHORIZATION, &authorization)
            .body(Empty::<Bytes>::new())
            .unwrap()
    };
    assert_eq!(
        client
            .send_request(connect(plain_addr))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let response = client.send_request(connect(secure_addr)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let tunnel = TokioIo::new(hyper::upgrade::on(response).await.unwrap());
    let inner = tls.connect(host, tunnel).await.unwrap();
    let (mut client, conn) = hyper::client::conn::http1::handshake(TokioIo::new(inner))
        .await
        .unwrap();
    let mut connected = tokio::spawn(conn);
    let response = client
        .send_request(
            hyper::Request::get("/tls")
                .header(HOST, "localhost")
                .body(Empty::<Bytes>::new())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "tunneled"
    );
    assert!(!connected.is_finished());
    std::fs::write(identities_file, "[]").unwrap();
    assert!(state.auth.reload().unwrap());
    timeout(Duration::from_secs(2), &mut connected)
        .await
        .unwrap()
        .unwrap()
        .ok();
    proxy.abort();
    http_server.abort();
    https_server.abort();
}

#[tokio::test]
async fn tailscale_approval_is_single_use_and_bound_to_the_calling_device() {
    const LOCAL: &str = "fd7a:115c:a1e0::51";
    const OTHER: &str = "fd7a:115c:a1e0::52";
    const TARGET: &str = "deploy.example.ts.net";
    const START: &str = "/_shomei/api/auth/tailscale/start";
    const FINISH: &str = "/_shomei/api/auth/tailscale/finish";
    let dir = tempfile::Builder::new()
        .prefix("shomei-")
        .tempdir_in("/tmp")
        .unwrap();
    let socket = dir.path().join("tailscale.sock");
    let secret = dir.path().join("secret");
    std::fs::write(&secret, "test-secret\n").unwrap();
    let local = UnixListener::bind(&socket).unwrap();
    let local_server = tokio::spawn(async move {
        while let Ok((connection, _)) = local.accept().await {
            tokio::spawn(async move {
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(connection), service_fn(|request: hyper::Request<Incoming>| async move {
                        assert_eq!(request.headers()[HOST], "local-tailscaled.sock");
                        assert_eq!(request.uri().path(), "/localapi/v0/whois");
                        let query = request.uri().query().unwrap();
                        let (id, address) = match query {
                            "addr=fd7a%3A115c%3Aa1e0%3A%3A51" => ("nFirst", format!("{LOCAL}/128")),
                            "addr=fd7a%3A115c%3Aa1e0%3A%3A52" => ("nSecond", format!("{OTHER}/128")),
                            _ => panic!("unexpected WhoIs query {query}"),
                        };
                        let body = json!({"Node": { "StableID": id, "Addresses": [address], "User": 123 }, "UserProfile": { "ID": 123 }});
                        Ok::<_, std::convert::Infallible>(hyper::Response::new(http_body_util::Full::new(Bytes::from(body.to_string()))))
                    }))
                    .await
                    .unwrap();
            });
        }
    });
    let api_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api_origin = format!("http://{}", api_listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let (writes, mut written) = tokio::sync::mpsc::unbounded_channel();
    let revoked = Arc::new(AtomicBool::new(false));
    let token_requests = Arc::new(AtomicUsize::new(0));
    let api_revoked = revoked.clone();
    let api_token_requests = token_requests.clone();
    let api_server = tokio::spawn(async move {
        let api = Router::new()
            .route("/api/v2/oauth/token", post(move |body: String| async move {
                assert_eq!(body, "grant_type=client_credentials&client_id=test-client&client_secret=test-secret&scope=devices%3Aposture_attributes");
                let sequence = api_token_requests.fetch_add(1, Ordering::SeqCst) + 1;
                Json(json!({ "access_token": format!("test-token-{sequence}"), "expires_in": 3600 }))
            }))
            .route("/api/v2/device/nFirst/attributes/custom:shomei_ssh", post(move |headers: HeaderMap, Json(body): Json<Value>| async move {
                let token = headers[AUTHORIZATION].to_str().unwrap();
                if token == "Bearer test-token-1" && api_revoked.load(Ordering::SeqCst) {
                    return StatusCode::UNAUTHORIZED;
                }
                assert!(matches!(token, "Bearer test-token-1" | "Bearer test-token-2"));
                writes.send(body).unwrap();
                StatusCode::NO_CONTENT
            }));
        axum::serve(api_listener, api).await.unwrap();
    });
    let config = Config {
        origin: "https://localhost:8443".parse().unwrap(),
        https_bind: "100.64.0.1:8443".parse().unwrap(),
        tls_cert: "unused".into(),
        tls_key: "unused".into(),
        state_dir: dir.path().into(),
        identities_file: dir.path().join("identities.json"),
        allow_yubikey_4: false,
        http_upstream: None,
        browser_action: None,
        session_ttl_seconds: 60,
        tcp: None,
        forward: None,
        tailscale_ssh: Some(TailscaleSshConfig {
            target: TARGET.into(),
            posture_attribute: "custom:shomei_ssh".into(),
            oauth_client_id: "test-client".into(),
            oauth_client_secret_file: secret,
            socket,
            ttl_seconds: 300,
        }),
        limits: crate::config::Limits {
            pending_per_ip: 1,
            ..Default::default()
        },
    };
    let (auth, signer) = test_auth(
        &config.origin,
        &config.state_dir,
        &config.identities_file,
        &config.limits,
        false,
    );
    let mut state = state_with_auth(config, None, auth, None).unwrap();
    Arc::get_mut(&mut state)
        .unwrap()
        .tailscale
        .as_mut()
        .unwrap()
        .use_test_api(api_origin);
    let router = routes(state);
    let send_as = |path, body, ip: &str| {
        let mut request = post_json(path, body);
        request.extensions_mut().insert(Peer(ip.parse().unwrap()));
        request
            .headers_mut()
            .insert("x-forwarded-for", HeaderValue::from_static(LOCAL));
        send(&router, request)
    };
    let begin = || send_as(START, json!({ "target": TARGET }), LOCAL);

    assert_eq!(
        send_as(START, json!({ "target": TARGET }), "127.0.0.1")
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send_as(START, json!({ "target": "other.example.ts.net" }), LOCAL)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );

    assert_eq!(
        send_as(START, json!({ "target": TARGET }), OTHER)
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        send_as(START, json!({ "target": TARGET }), OTHER)
            .await
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    let start = begin().await;
    assert_eq!(start.status(), StatusCode::OK);
    let answer = signed_answer(&signer, &json_body(start).await, 1);
    assert_eq!(
        send_as(FINISH, answer, OTHER).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let mut invalid = signed_answer(&signer, &json_body(begin().await).await, 2);
    invalid["credential"]["response"]["signature"] = json!("AA");
    assert_eq!(
        send_as(FINISH, invalid, LOCAL).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert!(written.try_recv().is_err());

    let answer = signed_answer(&signer, &json_body(begin().await).await, 3);
    let now = crate::tls::unix_seconds().unwrap();
    let approved = send_as(FINISH, answer.clone(), LOCAL).await;
    assert_eq!(approved.status(), StatusCode::OK);
    assert!(!approved.headers().contains_key(SET_COOKIE));
    let expiry = json_body(approved).await["expires_at"].as_u64().unwrap();
    assert!((now + 300..=now + 305).contains(&expiry));
    let update = written.try_recv().unwrap();
    assert_eq!(update["value"], true);
    let expected = time::OffsetDateTime::from_unix_timestamp(expiry.try_into().unwrap())
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    assert!(
        update["expiry"]
            .as_str()
            .unwrap()
            .starts_with(&expected[..19])
    );
    assert_eq!(
        send_as(FINISH, answer, LOCAL).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert!(written.try_recv().is_err());
    assert_eq!(token_requests.load(Ordering::SeqCst), 1);

    revoked.store(true, Ordering::SeqCst);
    let answer = signed_answer(&signer, &json_body(begin().await).await, 4);
    assert_eq!(
        send_as(FINISH, answer, LOCAL).await.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert!(written.try_recv().is_err());
    assert_eq!(token_requests.load(Ordering::SeqCst), 1);

    let answer = signed_answer(&signer, &json_body(begin().await).await, 5);
    assert_eq!(
        send_as(FINISH, answer, LOCAL).await.status(),
        StatusCode::OK
    );
    assert!(written.try_recv().is_ok());
    assert_eq!(token_requests.load(Ordering::SeqCst), 2);
    api_server.abort();
    local_server.abort();
}

async fn approves_one_deploy(u2f: bool) {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let identities_file = dir.path().join("identities.json");
    let config = Config {
        origin: "https://localhost:8443".parse().unwrap(),
        https_bind: "127.0.0.1:0".parse().unwrap(),
        tls_cert: "unused".into(),
        tls_key: "unused".into(),
        state_dir: dir.path().into(),
        identities_file: identities_file.clone(),
        allow_yubikey_4: u2f,
        http_upstream: Some(
            format!("http://{}", upstream.local_addr().unwrap())
                .parse()
                .unwrap(),
        ),
        browser_action: Some(BrowserAction {
            path: "/deploy".into(),
            label: "Deploy service".into(),
        }),
        session_ttl_seconds: 60,
        tcp: Some(TcpConfig {
            bind: "127.0.0.1:9443".parse().unwrap(),
            upstream: "ssh-fixture:2222".into(),
            ssh_host: Some("deploy".into()),
            public_port: Some(9553),
            cert_ttl_seconds: 120,
        }),
        forward: None,
        tailscale_ssh: None,
        limits: Default::default(),
    };
    let (auth, signer) = test_auth(
        &config.origin,
        &config.state_dir,
        &identities_file,
        &config.limits,
        u2f,
    );
    let forward = Arc::new(
        crate::forward::Gateway::new(
            toml::from_str(
                r#"
            public_port = 9777
            [scopes.api]
            cidrs = ["10.1.0.0/16"]
            ports = [443]
            [scopes.fleet]
            cidrs = ["10.2.0.0/16"]
            ports = [22]
        "#,
            )
            .unwrap(),
            16,
        )
        .unwrap(),
    );
    let state = state_with_auth(config, Some(Issuer::new().unwrap()), auth, Some(forward)).unwrap();
    let router = routes(state.clone());
    let server = tokio::spawn(async move {
        let upstream_app = Router::new().fallback(|request: Request| async move {
            match *request.method() {
                Method::POST => assert_eq!(request.uri(), "/deploy?q=1"),
                Method::GET => assert_eq!(request.uri(), "/status"),
                _ => panic!("unexpected upstream request"),
            }
            assert_eq!(request.headers()[COOKIE], "app=123");
            assert_eq!(request.headers()["x-forwarded-proto"], "https");
            assert_eq!(request.headers()["x-forwarded-host"], "localhost:8443");
            assert!(!request.headers().contains_key("x-forwarded-for"));
            assert!(!request.headers().contains_key("x-local"));
            if let Some(value) = request.headers().get(AUTHORIZATION) {
                assert_eq!(value, "Bearer app");
            }
            let body = axum::body::to_bytes(request.into_body(), 1024)
                .await
                .unwrap();
            (
                [
                    (SET_COOKIE, "__Host-shomei=blocked; Secure"),
                    (SET_COOKIE, "app=new"),
                ],
                body,
            )
        });
        axum::serve(upstream, upstream_app).await.unwrap();
    });

    let denied = send(&router, request("/deploy").body(Body::empty()).unwrap()).await;
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    let redirect = send(
        &router,
        request("/deploy?q=1")
            .header(ACCEPT, "text/html")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(redirect.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        redirect.headers()[LOCATION],
        "/_shomei/login?next=%2Fdeploy%3Fq%3D1"
    );
    let external = send(
        &router,
        request("/_shomei/api/auth/start")
            .method(Method::POST)
            .header(CONTENT_TYPE, "application/json")
            .header(ORIGIN, "https://elsewhere.example")
            .body(Body::from("{}"))
            .unwrap(),
    )
    .await;
    assert_eq!(external.status(), StatusCode::FORBIDDEN);
    let account = send(
        &router,
        post_json("/_shomei/api/auth/start", json!({"account":"other"})),
    )
    .await;
    assert_eq!(account.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let login = send(
        &router,
        request("/_shomei/login").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(login.status(), StatusCode::OK);
    let html = login.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&html).unwrap();
    assert!(html.contains("Tap your YubiKey to continue."));
    assert!(!html.contains("<button"));

    let page = send(
        &router,
        request("/_shomei/action").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(page.status(), StatusCode::OK);
    let details = send(
        &router,
        request("/_shomei/api/action").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(
        json_body(details).await,
        json!({"label": "Deploy service", "path": "/deploy"})
    );

    let start = send(&router, post_json("/_shomei/api/auth/start", json!({}))).await;
    assert_eq!(start.status(), StatusCode::OK);
    let assertion = signed_answer(&signer, &json_body(start).await, 1);
    let signature = format!(
        "Shomei {}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&assertion).unwrap())
    );
    let deploy = || {
        request("/deploy?q=1")
            .method(Method::POST)
            .header(CONNECTION, "keep-alive, x-local")
            .header("x-local", "hop")
            .header("x-forwarded-for", "127.0.0.1")
    };
    let allowed = send(
        &router,
        deploy()
            .header(AUTHORIZATION, &signature)
            .header(COOKIE, "app=123")
            .body(Body::from("hello"))
            .unwrap(),
    )
    .await;
    assert_eq!(allowed.status(), StatusCode::OK);
    let cookies: Vec<_> = allowed
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect();
    assert!(cookies.contains(&"app=new"));
    assert_eq!(cookies.len(), 2);
    let session = cookies
        .iter()
        .find(|value| value.starts_with("__Host-shomei="))
        .unwrap();
    assert!(session.contains("Max-Age=60"));
    assert!(session.contains("HttpOnly"));
    let cookie = session.split_once(';').unwrap().0.to_owned();
    assert_eq!(
        axum::body::to_bytes(allowed.into_body(), 1024)
            .await
            .unwrap(),
        "hello"
    );

    let replay = send(
        &router,
        deploy()
            .header(AUTHORIZATION, &signature)
            .header(COOKIE, "app=123")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
    let cookie_only = send(
        &router,
        deploy()
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(cookie_only.status(), StatusCode::UNAUTHORIZED);
    let bad_framing = send(
        &router,
        request("/deploy")
            .header(COOKIE, &cookie)
            .header(CONNECTION, "content-length")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(bad_framing.status(), StatusCode::BAD_REQUEST);
    let reuse = || {
        request("/status")
            .header(COOKIE, format!("app=123; {cookie}"))
            .header(AUTHORIZATION, "Bearer app")
            .body(Body::empty())
            .unwrap()
    };
    assert_eq!(send(&router, reuse()).await.status(), StatusCode::OK);

    let params = CertificateParams::default();
    let csr = params
        .serialize_request(&KeyPair::generate().unwrap())
        .unwrap()
        .pem()
        .unwrap();
    let unlisted = send(
        &router,
        post_json(
            "/_shomei/api/auth/start",
            json!({
                "client_csr_pem": csr, "tcp_target": "other"
            }),
        ),
    )
    .await;
    assert_eq!(unlisted.status(), StatusCode::FORBIDDEN);
    let start = send(
        &router,
        post_json(
            "/_shomei/api/auth/start",
            json!({
                "client_csr_pem": csr, "tcp_target": "deploy"
            }),
        ),
    )
    .await;
    assert_eq!(start.status(), StatusCode::OK);
    let answer = signed_answer(&signer, &json_body(start).await, 2);
    let issued = send(&router, post_json("/_shomei/api/auth/finish", answer)).await;
    assert_eq!(issued.status(), StatusCode::OK);
    let certificate = json_body(issued).await;
    assert_eq!(certificate["tcp_endpoint"], "localhost:9553");
    assert!(
        certificate["certificate_pem"]
            .as_str()
            .unwrap()
            .starts_with("-----BEGIN CERTIFICATE-----")
    );

    let ambiguous = send(
        &router,
        post_json("/_shomei/api/auth/start", json!({ "forward": true })),
    )
    .await;
    assert_eq!(ambiguous.status(), StatusCode::BAD_REQUEST);

    for (scope, expected) in [
        ("unknown", StatusCode::FORBIDDEN),
        ("fleet", StatusCode::OK),
    ] {
        let start = send(
            &router,
            post_json(
                "/_shomei/api/auth/start",
                json!({ "client_csr_pem": csr, "forward_scope": scope }),
            ),
        )
        .await;
        assert_eq!(start.status(), expected);
        if expected == StatusCode::OK {
            let answer = signed_answer(&signer, &json_body(start).await, 3);
            let issued = send(&router, post_json("/_shomei/api/auth/finish", answer)).await;
            assert_eq!(issued.status(), StatusCode::OK);
            assert!(!issued.headers().contains_key(SET_COOKIE));
            let certificate = json_body(issued).await;
            assert_eq!(certificate["forward_endpoint"], "localhost:9777");
            let leaf = CertificateDer::from_pem_slice(
                certificate["certificate_pem"].as_str().unwrap().as_bytes(),
            )
            .unwrap();
            assert_eq!(crate::tls::client_grant(&leaf).unwrap().1, 1);
        }
    }

    std::fs::write(identities_file, "[]").unwrap();
    assert!(state.auth.reload().unwrap());
    assert_eq!(
        send(&router, reuse()).await.status(),
        StatusCode::UNAUTHORIZED
    );
    server.abort();
}

fn request(path: &str) -> http::request::Builder {
    http::Request::builder()
        .uri(path)
        .header(HOST, "localhost:8443")
        .extension(Peer("127.0.0.1".parse().unwrap()))
}

fn post_json(path: &str, body: Value) -> Request {
    request(path)
        .method(Method::POST)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn send(router: &Router, request: Request) -> Response {
    router.clone().oneshot(request).await.unwrap()
}

async fn json_body(response: Response) -> Value {
    serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 32 * 1024)
            .await
            .unwrap(),
    )
    .unwrap()
}

fn signed_answer(signer: &TestSigner, start: &Value, counter: u32) -> Value {
    let challenge = URL_SAFE_NO_PAD
        .decode(start["publicKey"]["challenge"].as_str().unwrap())
        .unwrap();
    json!({ "challenge_id": start["challenge_id"], "credential": signer.sign(&challenge, counter) })
}
