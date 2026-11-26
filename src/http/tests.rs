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
async fn approves_one_request_and_issues_a_reusable_site_session() {
    approves_one_request(false).await;
}

#[tokio::test]
async fn attested_yubikey_4_approves_deploy_and_tcp_grants() {
    approves_one_request(true).await;
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
        forwarding: None,
        hostnames: Default::default(),
        http_upstreams: Default::default(),
        tcp_upstreams: Default::default(),
        protected_paths: None,
        browser_approval_ttl_seconds: 0,
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
    let proxy_router = router.clone();
    let proxy = tokio::spawn(async move {
        let (socket, peer) = listener.accept().await.unwrap();
        super::serve(
            socket,
            peer,
            tls,
            proxy_router,
            app,
            Arc::new(Semaphore::new(16)),
        )
        .await;
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
            post_json(
                "/_shomei/api/auth/start",
                json!({ "http_destination": format!("http://{plain_addr}/path?q=1") }),
            ),
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
            json!({ "tcp_destination": secure_addr.to_string(), "client_csr_pem": csr }),
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
async fn selective_paths_require_fresh_approval_and_other_paths_are_public() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let config = Config {
        origin: "https://localhost:8443".parse().unwrap(),
        https_bind: "127.0.0.1:0".parse().unwrap(),
        tls_cert: "unused".into(),
        tls_key: "unused".into(),
        state_dir: dir.path().into(),
        identities_file: dir.path().join("identities.json"),
        allow_yubikey_4: false,
        http_upstream: Some(
            format!("http://{}", upstream.local_addr().unwrap())
                .parse()
                .unwrap(),
        ),
        forwarding: Some(false),
        hostnames: Default::default(),
        http_upstreams: Default::default(),
        tcp_upstreams: Default::default(),
        protected_paths: Some(vec![ProtectedPath::Path("/api/deploy".into())]),
        browser_approval_ttl_seconds: 0,
        session_ttl_seconds: 60,
        tcp: None,
        forward: None,
        tailscale_ssh: None,
        limits: Default::default(),
    };
    let (auth, signer) = test_auth(
        &config.origin,
        &config.state_dir,
        &config.identities_file,
        &config.limits,
        false,
    );
    let state = state_with_auth(config, None, auth, None).unwrap();
    let (cookie, _) = state.upstreams[&state.canonical]
        .sessions
        .issue(state.auth.generation())
        .unwrap();
    let cookie = cookie.to_str().unwrap().split(';').next().unwrap();
    let router = routes(state);
    let server = tokio::spawn(async move {
        let app = Router::new().fallback(|request: Request| async move {
            assert!(!request.headers().contains_key("x-original-url"));
            assert!(!request.headers().contains_key(AUTHORIZATION));
            format!("{} {}", request.method(), request.uri())
        });
        axum::serve(upstream, app).await.unwrap();
    });
    let mut unlisted = request("/").body(Body::empty()).unwrap();
    unlisted
        .headers_mut()
        .insert(HOST, HeaderValue::from_static("site.example.test"));
    let response = send(&router, unlisted).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "GET /"
    );
    for (method, path) in [
        (Method::GET, "/"),
        (Method::GET, "/assets/%6dain.js"),
        (Method::POST, "/api/deployments"),
    ] {
        let response = send(
            &router,
            request(path)
                .method(method.clone())
                .header(ACCEPT, "text/html")
                .header("x-original-url", "/api/deploy")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            format!("{method} {path}")
        );
    }
    for path in [
        "/api/deploy",
        "/API/DEPLOY",
        "/api/deploy/",
        "/api/deploy/jobs",
        "/api/deploy.json",
        "/api/%64eploy",
        "/api%2Fdeploy",
        "/api/public/../deploy",
        "/api/deploy;v=1",
    ] {
        let response = send(
            &router,
            request(path)
                .header(COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
    }
    let start = send(&router, post_json("/_shomei/api/auth/start", json!({}))).await;
    assert_eq!(start.status(), StatusCode::OK);
    let signed = signed_answer(&signer, &json_body(start).await, 1);
    let approval = format!("Shomei {}", URL_SAFE_NO_PAD.encode(signed.to_string()));
    let deploy = || {
        request("/api/deploy?env=staging")
            .method(Method::POST)
            .header(AUTHORIZATION, &approval)
            .body(Body::empty())
            .unwrap()
    };
    let approved = send(&router, deploy()).await;
    assert_eq!(approved.status(), StatusCode::OK);
    assert_eq!(
        approved.into_body().collect().await.unwrap().to_bytes(),
        "POST /api/deploy?env=staging"
    );
    assert_eq!(
        send(&router, deploy()).await.status(),
        StatusCode::UNAUTHORIZED
    );
    server.abort();
}

#[tokio::test]
async fn browser_approvals_are_scoped_and_follow_per_path_ttls() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let identities = dir.path().join("identities");
    let file = dir.path().join("shomei.toml");
    let config = format!(
        r#"
        origin = "https://localhost:8443"
        hostnames = ["jobs.example.test"]
        tls_cert = "unused"
        tls_key = "unused"
        state_dir = {:?}
        identities_file = {identities:?}
        http_upstream = "http://{}"
        browser_approval_ttl_seconds = 60
        protected_paths = [
          "/api/jobs",
          {{ path = "/api/jobs/production", browser_approval_ttl_seconds = 0 }},
        ]
    "#,
        dir.path(),
        upstream.local_addr().unwrap()
    );
    std::fs::write(&file, config).unwrap();
    let config = Config::load(&file).unwrap();
    let (auth, signer) = test_auth(
        &config.origin,
        &config.state_dir,
        &identities,
        &config.limits,
        false,
    );
    let state = state_with_auth(config, None, auth, None).unwrap();
    let router = routes(state.clone());
    let server = tokio::spawn(async move {
        axum::serve(
            upstream,
            Router::new().fallback(|req: Request| async move {
                assert!(!req.headers().contains_key(approval::HEADER));
                axum::body::to_bytes(req.into_body(), 4096).await.unwrap()
            }),
        )
        .await
        .unwrap();
    });
    let site = "jobs.example.test:8443";
    let site_origin = "https://jobs.example.test:8443";
    let gateway = "https://localhost:8443";
    let context = |mut request: Request, origin: &str| {
        request
            .headers_mut()
            .insert(ORIGIN, HeaderValue::from_str(origin).unwrap());
        request
            .headers_mut()
            .insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
        request
    };
    let browser_post = |path, value| context(post_json(path, value), gateway);
    let approve = async |path, counter| {
        let start = send(&router, browser_post("/_shomei/api/auth/start", json!({
            "browser_approval": { "host": site, "request": { "method": "POST", "path": path } }
        }))).await;
        assert_eq!(start.status(), StatusCode::OK);
        let signed = signed_answer(&signer, &json_body(start).await, counter);
        let issued = send(&router, browser_post("/_shomei/api/auth/finish", signed)).await;
        assert_eq!(issued.status(), StatusCode::OK);
        assert!(!issued.headers().contains_key(SET_COOKIE));
        json_body(issued).await
    };
    let deploy = |method: Method, host: &str, path: &str, token: &str| {
        let req = request(path)
            .method(method)
            .header(approval::HEADER, token)
            .body(Body::from("job payload"))
            .unwrap();
        let mut req = context(req, &format!("https://{host}"));
        req.headers_mut()
            .insert(HOST, HeaderValue::from_str(host).unwrap());
        req
    };

    let path = "/api/jobs/example/run";
    let mut probe = post_json(
        "/_shomei/api/auth/browser/check",
        json!({
            "request": { "method": "POST", "path": path }
        }),
    );
    probe
        .headers_mut()
        .insert(HOST, HeaderValue::from_static("jobs.example.test:8443"));
    let denied = send(&router, context(probe, gateway)).await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let reusable = approve(path, 1).await;
    assert_eq!(reusable["reusable"], true);
    assert_eq!(reusable["site_origin"], site_origin);
    let token = reusable["approval"].as_str().unwrap();
    let mut probe = post_json(
        "/_shomei/api/auth/browser/check",
        json!({
            "request": { "method": "POST", "path": path }, "approval": token
        }),
    );
    probe
        .headers_mut()
        .insert(HOST, HeaderValue::from_static("jobs.example.test:8443"));
    let ready = send(&router, context(probe, site_origin)).await;
    assert_eq!(ready.status(), StatusCode::OK);
    assert_eq!(json_body(ready).await["ready"], true);

    for path in [path, "/api/jobs/another/run"] {
        let res = send(&router, deploy(Method::POST, site, path, token)).await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.into_body().collect().await.unwrap().to_bytes(),
            "job payload"
        );
    }
    for (method, host, path) in [
        (Method::GET, site, path),
        (Method::POST, "localhost:8443", path),
        (Method::POST, site, "/api/jobs/production"),
        (Method::POST, site, "/api/jobs/%2e/production"),
    ] {
        assert_eq!(
            send(&router, deploy(method, host, path, token))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let mut raw = deploy(Method::POST, site, path, token);
    raw.headers_mut().remove("sec-fetch-site");
    assert_eq!(send(&router, raw).await.status(), StatusCode::UNAUTHORIZED);

    let production = "/api/jobs/production?region=eu";
    let one_use = approve(production, 2).await;
    assert_eq!(one_use["reusable"], false);
    let one_use = one_use["approval"].as_str().unwrap();
    assert_eq!(
        send(
            &router,
            deploy(
                Method::POST,
                site,
                "/api/jobs/production?region=us",
                one_use
            )
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(&router, deploy(Method::POST, site, production, one_use))
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        send(&router, deploy(Method::POST, site, production, one_use))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let start = send(&router, post_json("/_shomei/api/auth/start", json!({}))).await;
    let signed = signed_answer(&signer, &json_body(start).await, 3);
    let assertion = format!("Shomei {}", URL_SAFE_NO_PAD.encode(signed.to_string()));
    let cli = || {
        request(production)
            .method(Method::POST)
            .header(AUTHORIZATION, &assertion)
            .body(Body::from("job payload"))
            .unwrap()
    };
    assert_eq!(send(&router, cli()).await.status(), StatusCode::OK);
    assert_eq!(
        send(&router, cli()).await.status(),
        StatusCode::UNAUTHORIZED
    );

    std::fs::write(identities, "[]").unwrap();
    assert!(state.auth.reload().unwrap());
    assert_eq!(
        send(&router, deploy(Method::POST, site, path, token))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    server.abort();
}

#[tokio::test]
async fn routes_sites_by_authority_and_keeps_their_approvals_separate() {
    let public = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let private = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let config = format!(
        r#"
        origin = "https://localhost:8443"
        tls_cert = "unused"
        tls_key = "unused"
        state_dir = {:?}
        identities_file = {:?}
        hostnames = ["app.example.test"]

        [[http_upstreams]]
        hostname = "app.example.test"
        upstream = "http://{}"
        protected_paths = ["/api/deploy"]

        [[http_upstreams]]
        hostname = "app.example.test:9447"
        upstream = "http://{}"
    "#,
        dir.path(),
        dir.path().join("identities"),
        public.local_addr().unwrap(),
        private.local_addr().unwrap()
    );
    let config_file = dir.path().join("shomei.toml");
    std::fs::write(&config_file, config).unwrap();
    let config = Config::load(&config_file).unwrap();
    let (auth, signer) = test_auth(
        &config.origin,
        &config.state_dir,
        &config.identities_file,
        &config.limits,
        false,
    );
    let gateway = Arc::new(
        forward::Gateway::new(
            toml::from_str("[scopes.web]\ncidrs = [\"127.0.0.1/32\"]\nports = [443]").unwrap(),
            16,
        )
        .unwrap(),
    );
    let state = state_with_auth(config, None, auth, Some(gateway)).unwrap();
    let router = routes(state.clone());
    let servers = [(public, "public"), (private, "private")].map(|(listener, name)| {
        tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().fallback(move |req: Request| async move {
                    format!("{name} {} {}", req.method(), req.uri())
                }),
            )
            .await
            .unwrap();
        })
    });
    let hosted = |host: &str, path: &str| {
        http::Request::builder()
            .uri(path)
            .header(HOST, host)
            .extension(Peer("127.0.0.1".parse().unwrap()))
    };
    let public_host = "app.example.test:8443";
    let private_host = "app.example.test:9447";
    let payload = "https://app.example.test:8443/api/deploy";
    let resp = send(
        &router,
        hosted(public_host, "/status").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(
        resp.into_body().collect().await.unwrap().to_bytes(),
        "public GET /status"
    );
    let resp = send(
        &router,
        hosted(public_host, payload).body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let resp = send(
        &router,
        hosted(private_host, "/status?q=1")
            .header(ACCEPT, "text/html")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(
        resp.headers()[LOCATION]
            .to_str()
            .unwrap()
            .starts_with("https://localhost:8443/_shomei/login?app=")
    );

    let start = async |body, counter| {
        let response = send(&router, post_json("/_shomei/api/auth/start", body)).await;
        assert_eq!(response.status(), StatusCode::OK);
        signed_answer(&signer, &json_body(response).await, counter)
    };
    let reverse = start(json!({ "http_destination": payload }), 1).await;
    let approval = format!("Shomei {}", URL_SAFE_NO_PAD.encode(reverse.to_string()));
    let crossed = send(
        &router,
        hosted(private_host, "/status")
            .header(AUTHORIZATION, approval)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(crossed.status(), StatusCode::UNAUTHORIZED);

    let action = start(json!({ "http_destination": payload }), 2).await;
    let approval = format!("Shomei {}", URL_SAFE_NO_PAD.encode(action.to_string()));
    let resp = send(
        &router,
        hosted(public_host, "/api/deploy")
            .method(Method::POST)
            .header(AUTHORIZATION, approval)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.into_body().collect().await.unwrap().to_bytes(),
        "public POST /api/deploy"
    );

    let login = start(
        json!({ "browser_login": { "app": private_host, "next": "/status?q=1" } }),
        3,
    )
    .await;
    let response = send(&router, post_json("/_shomei/api/auth/finish", login)).await;
    let reply = json_body(response).await;
    let target = url::Url::parse(reply["redirect"].as_str().unwrap()).unwrap();
    assert_eq!(target.port(), Some(9447));
    let path = &target[url::Position::BeforePath..];
    assert_eq!(
        send(
            &router,
            hosted(public_host, path).body(Body::empty()).unwrap()
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    let complete = send(
        &router,
        hosted(private_host, path).body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(complete.headers()[LOCATION], "/status?q=1");
    let cookie = complete.headers()[SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let resp = send(
        &router,
        hosted(private_host, "/status?q=1")
            .header(COOKIE, cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(
        resp.into_body().collect().await.unwrap().to_bytes(),
        "private GET /status?q=1"
    );
    assert_eq!(
        send(
            &router,
            hosted(private_host, path).body(Body::empty()).unwrap()
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (identity, roots) = server_fixture();
    let incoming_tls = identity.http1_server().unwrap();
    let tls = TlsConnector::from(Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));
    let proxy = tokio::spawn(async move {
        let (socket, peer) = listener.accept().await.unwrap();
        super::serve(
            socket,
            peer,
            incoming_tls,
            router,
            state,
            Arc::new(Semaphore::new(16)),
        )
        .await;
    });
    let server_name = ServerName::try_from("localhost").unwrap();
    let encrypted = tls
        .connect(server_name.clone(), TcpStream::connect(addr).await.unwrap())
        .await
        .unwrap();
    let (mut client, connection) = hyper::client::conn::http1::handshake(TokioIo::new(encrypted))
        .await
        .unwrap();
    tokio::spawn(connection.with_upgrades());
    let response = client
        .send_request(
            hyper::Request::builder()
                .method(Method::CONNECT)
                .uri(Uri::builder().authority(public_host).build().unwrap())
                .header(HOST, public_host)
                .body(Empty::<Bytes>::new())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let inner = tls
        .connect(
            server_name,
            TokioIo::new(hyper::upgrade::on(response).await.unwrap()),
        )
        .await
        .unwrap();
    let (mut client, connection) = hyper::client::conn::http1::handshake(TokioIo::new(inner))
        .await
        .unwrap();
    let connection = tokio::spawn(connection);
    for (host, path, status) in [
        (public_host, "/status", StatusCode::OK),
        (public_host, "/api/deploy", StatusCode::UNAUTHORIZED),
        (private_host, "/status", StatusCode::MISDIRECTED_REQUEST),
    ] {
        let response = client
            .send_request(
                hyper::Request::get(path)
                    .header(HOST, host)
                    .body(Empty::<Bytes>::new())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        response.into_body().collect().await.unwrap();
    }
    connection.abort();
    proxy.abort();
    for server in servers {
        server.abort();
    }
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
        forwarding: None,
        hostnames: Default::default(),
        http_upstreams: Default::default(),
        tcp_upstreams: Default::default(),
        protected_paths: None,
        browser_approval_ttl_seconds: 0,
        session_ttl_seconds: 60,
        tcp: None,
        forward: None,
        tailscale_ssh: Some(TailscaleSshConfig {
            target: None,
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
        send_as(START, json!({ "target": "other.example.org" }), LOCAL)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );

    assert_eq!(
        send_as(START, json!({ "target": "other.example.ts.net" }), OTHER)
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

async fn approves_one_request(u2f: bool) {
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
        forwarding: None,
        hostnames: Default::default(),
        http_upstreams: Default::default(),
        tcp_upstreams: Default::default(),
        protected_paths: None,
        browser_approval_ttl_seconds: 0,
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

    let approval_script = send(
        &router,
        request("/_shomei/webauthn.js").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(approval_script.status(), StatusCode::OK);
    assert_eq!(
        approval_script.headers()[CONTENT_TYPE],
        "text/javascript; charset=utf-8"
    );
    let page = send(
        &router,
        request("/_shomei/action").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(page.status(), StatusCode::NOT_FOUND);

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
            .header(COOKIE, format!("app=123; {cookie}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(cookie_only.status(), StatusCode::OK);
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
