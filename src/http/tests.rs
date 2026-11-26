use axum::http;
use rcgen::{CertificateParams, KeyPair};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tower::ServiceExt;

use super::*;
use crate::{
    auth::tests::{TestSigner, test_auth},
    config::TcpConfig,
};

#[tokio::test]
async fn approves_one_deploy_and_allows_only_reads_with_its_cookie() {
    approves_one_deploy(false).await;
}

#[tokio::test]
async fn attested_yubikey_4_approves_deploy_and_tcp_grants() {
    approves_one_deploy(true).await;
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
        limits: Default::default(),
    };
    let (auth, signer) = test_auth(
        &config.origin,
        &config.state_dir,
        &identities_file,
        &config.limits,
        u2f,
    );
    let state = state_with_auth(config, Some(Issuer::new().unwrap()), auth).unwrap();
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
