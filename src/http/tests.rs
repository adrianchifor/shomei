use axum::http;
use tokio::net::TcpListener;
use tower::ServiceExt;

use super::*;

#[tokio::test]
async fn gates_http_and_preserves_upstream_requests() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("token");
    std::fs::write(&token, "0123456789abcdef0123456789abcdef").unwrap();
    let state = state(
        Config {
            origin: "https://localhost:8443".parse().unwrap(),
            https_bind: "127.0.0.1:0".parse().unwrap(),
            tls_cert: "unused".into(),
            tls_key: "unused".into(),
            state_dir: dir.path().into(),
            enrollment_token_file: Some(token),
            http_upstream: Some(
                format!("http://{}", upstream.local_addr().unwrap())
                    .parse()
                    .unwrap(),
            ),
            session_ttl_seconds: 60,
            tcp: None,
        },
        None,
    )
    .unwrap();
    let router = routes(state.clone());
    let server = tokio::spawn(async move {
        let upstream_app = Router::new().fallback(|request: Request| async move {
            assert_eq!(request.method(), Method::POST);
            assert_eq!(request.uri(), "/resource?q=1");
            assert_eq!(request.headers()[COOKIE], "app=123");
            assert_eq!(request.headers()["x-forwarded-proto"], "https");
            assert_eq!(request.headers()["x-forwarded-host"], "localhost:8443");
            assert!(!request.headers().contains_key("x-forwarded-for"));
            assert!(!request.headers().contains_key("x-local"));
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

    let request = |uri| {
        http::Request::builder()
            .uri(uri)
            .header(HOST, "localhost:8443")
    };
    let denied = router
        .clone()
        .oneshot(request("/resource").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    let redirect = router
        .clone()
        .oneshot(
            request("/resource?q=1")
                .header(ACCEPT, "text/html")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(redirect.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        redirect.headers()[LOCATION],
        "/_shomei/login?next=%2Fresource%3Fq%3D1"
    );
    let external = router
        .clone()
        .oneshot(
            request("/_shomei/api/enroll/start")
                .method(Method::POST)
                .header(ORIGIN, "https://example.com")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(external.status(), StatusCode::FORBIDDEN);

    let (cookie, _) = state.sessions.issue().unwrap();
    let (cookie, _) = cookie.to_str().unwrap().split_once(';').unwrap();
    let (name, value) = cookie.split_once('=').unwrap();
    let first = if value.starts_with('A') { 'B' } else { 'A' };
    let invalid = router
        .clone()
        .oneshot(
            request("/resource")
                .header(COOKIE, format!("{name}={first}{}", &value[1..]))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
    let allowed = router
        .oneshot(
            request("/resource?q=1")
                .method(Method::POST)
                .header(COOKIE, format!("app=123; {cookie}"))
                .header(CONNECTION, "keep-alive, x-local")
                .header("x-local", "hop")
                .header("x-forwarded-for", "127.0.0.1")
                .body(Body::from("hello"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(allowed.status(), StatusCode::OK);
    assert_eq!(
        allowed
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .collect::<Vec<_>>(),
        vec!["app=new"]
    );
    assert_eq!(
        axum::body::to_bytes(allowed.into_body(), 1024)
            .await
            .unwrap(),
        "hello"
    );
    server.abort();
}
