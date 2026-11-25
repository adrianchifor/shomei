use std::{sync::Arc, time::Duration};

use anyhow::Result;
use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, Request, State},
    http::{
        HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri,
        header::{self, *},
    },
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use http_body::Frame;
use http_body_util::BodyExt;
use hyper::server::conn::http1;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use serde::Deserialize;
use tokio::{net::TcpStream, time::timeout};
use tokio_rustls::TlsAcceptor;
use url::Position;
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

use crate::{
    HANDSHAKE_TIMEOUT,
    auth::{ApiError, Auth, Grant, SignedChallenge},
    config::Config,
    session::{Sessions, session_value},
    tls::{Issuer, csr_key},
};

const PREFIX: &str = "/_shomei";
const NO_STORE: HeaderValue = HeaderValue::from_static("private, no-store");

pub struct App {
    auth: Auth,
    origin: String,
    host: HeaderValue,
    sessions: Sessions,
    upstream: Option<HttpUpstream>,
    tcp: Option<(Issuer, u64)>,
}

struct HttpUpstream {
    origin: Uri,
    client: Client<HttpsConnector<HttpConnector>, Body>,
}

pub fn app(config: Config, issuer: Option<Issuer>) -> Result<Router> {
    Ok(routes(state(config, issuer)?))
}

fn state(config: Config, issuer: Option<Issuer>) -> Result<Arc<App>> {
    let upstream = config
        .http_upstream
        .map(|origin| -> Result<_> {
            let mut transport = HttpConnector::new();
            transport.enforce_http(false);
            transport.set_connect_timeout(Some(Duration::from_secs(5)));
            let connector = HttpsConnectorBuilder::new()
                .with_webpki_roots()
                .https_or_http()
                .enable_http1()
                .wrap_connector(transport);
            let client = Client::builder(TokioExecutor::new())
                .pool_timer(TokioTimer::new())
                .pool_max_idle_per_host(16)
                .build(connector);
            Ok(HttpUpstream {
                origin: origin.as_str().parse()?,
                client,
            })
        })
        .transpose()?;
    let host = HeaderValue::from_str(&config.origin[Position::BeforeHost..Position::AfterPort])?;
    Ok(Arc::new(App {
        auth: Auth::new(
            &config.origin,
            &config.state_dir,
            config.enrollment_token_file.as_deref(),
        )?,
        origin: config.origin.origin().ascii_serialization(),
        host,
        sessions: Sessions::new(config.session_ttl_seconds)?,
        upstream,
        tcp: issuer.zip(config.tcp.map(|tcp| tcp.cert_ttl_seconds)),
    }))
}

fn routes(state: Arc<App>) -> Router {
    let reserved = Router::new()
        .route("/login", get(page))
        .route("/enroll", get(page))
        .route("/auth.js", get(script))
        .route("/auth.css", get(styles))
        .route("/api/enroll/start", post(enroll_start))
        .route("/api/enroll/finish", post(enroll_finish))
        .route("/api/auth/start", post(login_start))
        .route("/api/auth/finish", post(login_finish))
        .fallback(|| async { StatusCode::NOT_FOUND })
        .layer(DefaultBodyLimit::max(32 * 1024))
        .layer(middleware::from_fn_with_state(state.clone(), protect_auth));
    Router::new()
        .nest(PREFIX, reserved)
        .fallback(forward)
        .layer(middleware::from_fn_with_state(state.clone(), check_host))
        .with_state(state)
}

pub async fn serve(socket: TcpStream, tls: TlsAcceptor, app: Router) {
    let Ok(Ok(stream)) = timeout(HANDSHAKE_TIMEOUT, tls.accept(socket)).await else {
        return;
    };
    let _ = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(10))
        .max_buf_size(32 * 1024)
        .serve_connection(TokioIo::new(stream), TowerToHyperService::new(app))
        .await;
}

async fn check_host(State(app): State<Arc<App>>, request: Request, next: Next) -> Response {
    let mut hosts = request.headers().get_all(HOST).iter();
    let same_host = hosts.next().is_some_and(|host| {
        host.as_bytes().eq_ignore_ascii_case(app.host.as_bytes())
            || (!app.host.as_bytes().contains(&b':')
                && host
                    .as_bytes()
                    .strip_suffix(b":443")
                    .is_some_and(|host| host.eq_ignore_ascii_case(app.host.as_bytes())))
    });
    if !same_host || hosts.next().is_some() || request.uri().authority().is_some() {
        return StatusCode::MISDIRECTED_REQUEST.into_response();
    }
    next.run(request).await
}

async fn protect_auth(State(app): State<Arc<App>>, request: Request, next: Next) -> Response {
    let mut origins = request.headers().get_all(ORIGIN).iter();
    let wrong_origin = origins
        .next()
        .is_some_and(|origin| origin.as_bytes() != app.origin.as_bytes())
        || origins.next().is_some();
    let mut response = if wrong_origin {
        ApiError(StatusCode::FORBIDDEN, "origin mismatch").into_response()
    } else {
        timeout(Duration::from_secs(10), next.run(request))
            .await
            .unwrap_or_else(|_| {
                ApiError(StatusCode::REQUEST_TIMEOUT, "request timed out").into_response()
            })
    };
    let headers = response.headers_mut();
    headers.insert(CACHE_CONTROL, NO_STORE);
    headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
    ));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

async fn page() -> Html<&'static str> {
    Html(include_str!("../assets/auth.html"))
}

async fn script() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../assets/auth.js"),
    )
}

async fn styles() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../assets/auth.css"),
    )
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let (scheme, token) = headers.get(AUTHORIZATION)?.to_str().ok()?.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then_some(token)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

async fn enroll_start(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(_): Json<Empty>,
) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(app.auth.start_enroll(bearer(&headers))?))
}

async fn enroll_finish(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(body): Json<SignedChallenge<RegisterPublicKeyCredential>>,
) -> Result<StatusCode, ApiError> {
    app.auth.finish_enroll(bearer(&headers), body)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginStart {
    client_csr_pem: Option<String>,
}

async fn login_start(
    State(app): State<Arc<App>>,
    Json(body): Json<LoginStart>,
) -> Result<impl IntoResponse, ApiError> {
    let grant = match body.client_csr_pem {
        Some(_csr) if app.tcp.is_none() => {
            return Err(ApiError(StatusCode::BAD_REQUEST, "TCP relay is disabled"));
        }
        Some(csr) => Grant::Tcp(
            csr_key(&csr)
                .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid P-256 client CSR"))?,
        ),
        None if app.upstream.is_none() => {
            return Err(ApiError(StatusCode::BAD_REQUEST, "HTTP relay is disabled"));
        }
        None => Grant::Http,
    };
    Ok(Json(app.auth.start_login(grant)?))
}

async fn login_finish(
    State(app): State<Arc<App>>,
    Json(body): Json<SignedChallenge<PublicKeyCredential>>,
) -> Result<Response, ApiError> {
    match app.auth.finish_login(body)? {
        Grant::Http => {
            let (cookie, expires_at) = app.sessions.issue().map_err(ApiError::internal)?;
            Ok((
                [(SET_COOKIE, cookie)],
                Json(serde_json::json!({ "expires_at": expires_at })),
            )
                .into_response())
        }
        Grant::Tcp(key) => {
            let (issuer, ttl) = app
                .tcp
                .as_ref()
                .ok_or_else(|| ApiError::internal("missing TCP issuer"))?;
            Ok(Json(issuer.issue(&key, *ttl).map_err(ApiError::internal)?).into_response())
        }
    }
}

async fn forward(State(app): State<Arc<App>>, mut request: Request) -> Response {
    let Some(upstream) = &app.upstream else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if request.method() == Method::CONNECT || request.headers().contains_key(UPGRADE) {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    if !app.sessions.verify(request.headers()) {
        let mut response = if wants_login(&request) {
            let target = request
                .uri()
                .path_and_query()
                .map_or("/", |value| value.as_str());
            let query = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("next", target)
                .finish();
            Redirect::to(&format!("{PREFIX}/login?{query}")).into_response()
        } else {
            ApiError(StatusCode::UNAUTHORIZED, "YubiKey sign-in required").into_response()
        };
        response.headers_mut().insert(CACHE_CONTROL, NO_STORE);
        return response;
    }
    let mut parts = upstream.origin.clone().into_parts();
    parts.path_and_query = request.uri().path_and_query().cloned();
    let Ok(uri) = Uri::from_parts(parts) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    *request.uri_mut() = uri;
    *request.version_mut() = axum::http::Version::HTTP_11;
    let headers = request.headers_mut();
    strip_hop_headers(headers);
    headers.remove(HOST);
    headers.remove("forwarded");
    headers.remove("x-real-ip");
    let spoofed: Vec<_> = headers
        .keys()
        .filter(|name| name.as_str().starts_with("x-forwarded-"))
        .cloned()
        .collect();
    for name in spoofed {
        headers.remove(name);
    }
    headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
    headers.insert("x-forwarded-host", app.host.clone());
    filter_cookies(headers, COOKIE);

    let request = request.map(without_trailers);
    let mut response =
        match timeout(Duration::from_secs(30), upstream.client.request(request)).await {
            Ok(Ok(response)) if response.status() == StatusCode::SWITCHING_PROTOCOLS => {
                StatusCode::BAD_GATEWAY.into_response()
            }
            Ok(Ok(response)) => response.map(|body| without_trailers(Body::new(body))),
            Ok(Err(error)) => {
                eprintln!("HTTP upstream request failed: {error}");
                StatusCode::BAD_GATEWAY.into_response()
            }
            Err(_) => StatusCode::GATEWAY_TIMEOUT.into_response(),
        };
    strip_hop_headers(response.headers_mut());
    filter_cookies(response.headers_mut(), SET_COOKIE);
    response.headers_mut().insert(CACHE_CONTROL, NO_STORE);
    response
}

fn wants_login(request: &Request) -> bool {
    let path = request.uri().path();
    request.method() == Method::GET
        && path.starts_with('/')
        && !path.starts_with("//")
        && !path.contains('\\')
        && request
            .headers()
            .get(ACCEPT)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(',')
                    .any(|media| media.trim().starts_with("text/html"))
            })
}

fn strip_hop_headers(headers: &mut HeaderMap) {
    let nominated: Vec<_> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|value| HeaderName::from_bytes(value.trim().as_bytes()).ok())
        .collect();
    for name in nominated {
        headers.remove(name);
    }
    for name in [
        CONNECTION,
        HeaderName::from_static("keep-alive"),
        HeaderName::from_static("proxy-connection"),
        PROXY_AUTHENTICATE,
        PROXY_AUTHORIZATION,
        TE,
        TRAILER,
        TRANSFER_ENCODING,
        UPGRADE,
    ] {
        headers.remove(name);
    }
}

fn filter_cookies(headers: &mut HeaderMap, name: HeaderName) {
    let entries: Vec<_> = headers
        .get_all(&name)
        .iter()
        .filter_map(|header| {
            let line = header.to_str().ok()?;
            if name == COOKIE {
                let cookies = line
                    .split(';')
                    .map(str::trim)
                    .filter(|pair| !pair.is_empty() && session_value(pair).is_none())
                    .collect::<Vec<_>>()
                    .join("; ");
                return (!cookies.is_empty())
                    .then(|| HeaderValue::from_str(&cookies).ok())
                    .flatten();
            }
            let pair = line.split_once(';').map_or(line, |(pair, _)| pair);
            session_value(pair).is_none().then(|| header.clone())
        })
        .collect();
    headers.remove(&name);
    for entry in entries {
        headers.append(&name, entry);
    }
}

fn without_trailers(body: Body) -> Body {
    Body::new(body.map_frame(|frame| {
        if frame.is_trailers() {
            Frame::data(Bytes::new())
        } else {
            frame
        }
    }))
}

#[cfg(test)]
mod tests;
