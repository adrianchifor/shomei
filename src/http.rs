use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use axum::{
    Extension, Json, Router,
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, Request, State},
    http::{
        HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, Version,
        header::{self, *},
    },
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http_body::Frame;
use http_body_util::BodyExt;
use hyper::{
    body::Incoming,
    service::{Service, service_fn},
};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto,
    service::TowerToHyperService,
};
use serde::Deserialize;
use tokio::{
    net::TcpStream,
    sync::{OwnedSemaphorePermit, Semaphore},
    time::timeout,
};
use tokio_rustls::TlsAcceptor;
use url::Position;
use webauthn_rs::prelude::PublicKeyCredential;

use crate::{
    accept_tls,
    auth::{ApiError, Auth, Grant, SignedChallenge},
    config::{Config, http_path_is_unambiguous, http_path_matches},
    session::{Sessions, session_value},
    tailscale::TailscaleSsh,
    tls::{Issuer, csr_key},
};

const PREFIX: &str = "/_shomei";
const NO_STORE: HeaderValue = HeaderValue::from_static("private, no-store");

pub struct App {
    pub(crate) auth: Arc<Auth>,
    origin: String,
    host: HeaderValue,
    sessions: Sessions,
    upstream: Option<HttpUpstream>,
    protected_paths: Option<Vec<String>>,
    tcp: Option<TcpAccess>,
    forward: Option<ForwardAccess>,
    tailscale: Option<TailscaleSsh>,
    auth_workers: Arc<Semaphore>,
    http_requests: Arc<Semaphore>,
}

struct TcpAccess {
    issuer: Issuer,
    ttl: u64,
    endpoint: String,
    ssh_host: Option<String>,
}

struct ForwardAccess {
    gateway: Arc<crate::forward::Gateway>,
    endpoint: String,
    http_sessions: Vec<Sessions>,
    http_ttl: u64,
}

#[derive(Clone, Copy)]
struct Peer(IpAddr);

impl Peer {
    fn challenge_key(self) -> IpAddr {
        match self.0 {
            IpAddr::V6(ip) => IpAddr::V6(Ipv6Addr::from(u128::from(ip) & (u128::MAX << 64))),
            ip => ip,
        }
    }
}

struct HttpUpstream {
    origin: Uri,
    client: Client<HttpsConnector<HttpConnector>, Body>,
}

pub fn app(
    config: Config,
    issuer: Option<Issuer>,
    forward: Option<Arc<crate::forward::Gateway>>,
) -> Result<(Router, Arc<App>)> {
    let state = state(config, issuer, forward)?;
    Ok((routes(state.clone()), state))
}

fn state(
    config: Config,
    issuer: Option<Issuer>,
    forward: Option<Arc<crate::forward::Gateway>>,
) -> Result<Arc<App>> {
    let auth = Auth::new(
        &config.origin,
        &config.state_dir,
        &config.identities_file,
        &config.limits,
        config.allow_yubikey_4,
    )?;
    state_with_auth(config, issuer, auth, forward)
}

fn state_with_auth(
    config: Config,
    issuer: Option<Issuer>,
    auth: Auth,
    forward: Option<Arc<crate::forward::Gateway>>,
) -> Result<Arc<App>> {
    let upstream = config
        .http_upstream
        .map(|origin| -> Result<_> {
            let mut transport = HttpConnector::new();
            transport.enforce_http(false);
            transport.set_connect_timeout(Some(Duration::from_secs(5)));
            transport.set_nodelay(true);
            let connector = HttpsConnectorBuilder::new()
                .with_webpki_roots()
                .https_or_http()
                .enable_http1()
                .enable_http2()
                .wrap_connector(transport);
            let client = Client::builder(TokioExecutor::new())
                .pool_timer(TokioTimer::new())
                .pool_idle_timeout(Duration::from_secs(30))
                .pool_max_idle_per_host(config.limits.http_requests.min(4096))
                .http1_max_buf_size(32 * 1024)
                .http2_max_header_list_size(32 * 1024)
                .build(connector);
            Ok(HttpUpstream {
                origin: origin.as_str().parse()?,
                client,
            })
        })
        .transpose()?;
    let host = HeaderValue::from_str(&config.origin[Position::BeforeHost..Position::AfterPort])?;
    let hostname = config.origin.domain().context("missing proxy hostname")?;
    let tcp = issuer.zip(config.tcp).map(|(issuer, tcp)| TcpAccess {
        issuer,
        ttl: tcp.cert_ttl_seconds,
        endpoint: format!("{hostname}:{}", tcp.public_port.unwrap_or(tcp.bind.port())),
        ssh_host: tcp.ssh_host,
    });
    Ok(Arc::new(App {
        auth: Arc::new(auth),
        origin: config.origin.origin().ascii_serialization(),
        host,
        sessions: Sessions::new(config.session_ttl_seconds)?,
        upstream,
        protected_paths: config.protected_paths,
        tcp,
        forward: forward
            .map(|gateway| -> Result<_> {
                let http_sessions = if gateway.config.http_bind.is_some() {
                    gateway
                        .config
                        .scopes
                        .keys()
                        .map(|_| Sessions::new(config.session_ttl_seconds))
                        .collect::<Result<Vec<_>>>()?
                } else {
                    Vec::new()
                };
                Ok(ForwardAccess {
                    endpoint: format!(
                        "{hostname}:{}",
                        gateway
                            .config
                            .public_port
                            .unwrap_or(gateway.config.bind.port())
                    ),
                    gateway,
                    http_sessions,
                    http_ttl: config.session_ttl_seconds,
                })
            })
            .transpose()?,
        tailscale: config
            .tailscale_ssh
            .map(|tailscale| TailscaleSsh::new(tailscale, config.limits.auth_workers))
            .transpose()?,
        auth_workers: Arc::new(Semaphore::new(config.limits.auth_workers)),
        http_requests: Arc::new(Semaphore::new(config.limits.http_requests)),
    }))
}

fn routes(state: Arc<App>) -> Router {
    let reserved = Router::new()
        .route("/login", get(page))
        .route("/auth.js", get(script))
        .route("/webauthn.js", get(webauthn_script))
        .route("/auth.css", get(styles))
        .route("/seal.png", get(seal))
        .route("/geist.woff2", get(font))
        .route("/api/auth/start", post(login_start))
        .route("/api/auth/finish", post(login_finish))
        .route("/api/auth/tailscale/start", post(tailscale_start))
        .route("/api/auth/tailscale/finish", post(tailscale_finish))
        .fallback(|| async { StatusCode::NOT_FOUND })
        .layer(DefaultBodyLimit::max(32 * 1024))
        .layer(middleware::from_fn_with_state(state.clone(), protect_auth));
    Router::new()
        .nest(PREFIX, reserved)
        .fallback(forward)
        .layer(middleware::from_fn_with_state(state.clone(), check_host))
        .with_state(state)
}

pub async fn serve(
    socket: TcpStream,
    peer: SocketAddr,
    tls: TlsAcceptor,
    app: Router,
    handshakes: Arc<Semaphore>,
) {
    let Some(stream) = accept_tls(socket, tls, &handshakes).await else {
        return;
    };
    let app = TowerToHyperService::new(app);
    let peer = peer.ip().to_canonical();
    let service = service_fn(move |mut request: hyper::Request<Incoming>| {
        request.extensions_mut().insert(Peer(peer));
        app.call(request)
    });
    let builder = auto::Builder::new(TokioExecutor::new());
    let mut builder = if stream.get_ref().1.alpn_protocol() == Some(b"h2") {
        builder.http2_only()
    } else {
        builder.http1_only()
    };
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(10))
        .max_buf_size(32 * 1024);
    builder
        .http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(64)
        .max_pending_accept_reset_streams(64)
        .max_header_list_size(32 * 1024)
        .max_send_buf_size(64 * 1024)
        .keep_alive_interval(Duration::from_secs(30))
        .keep_alive_timeout(Duration::from_secs(10));
    let _ = builder
        .serve_connection(TokioIo::new(stream), service)
        .await;
}

async fn check_host(State(app): State<Arc<App>>, request: Request, next: Next) -> Response {
    let mut hosts = request.headers().get_all(HOST).iter();
    let host = hosts.next();
    let same_host = match request.version() {
        Version::HTTP_2 => {
            request.uri().scheme_str() == Some("https")
                && request.uri().authority().is_some_and(|authority| {
                    matches_host(authority.as_str().as_bytes(), app.host.as_bytes())
                })
                && host.is_none_or(|host| matches_host(host.as_bytes(), app.host.as_bytes()))
        }
        _ => {
            request.uri().authority().is_none()
                && host.is_some_and(|host| matches_host(host.as_bytes(), app.host.as_bytes()))
        }
    };
    if !same_host || hosts.next().is_some() {
        return StatusCode::MISDIRECTED_REQUEST.into_response();
    }
    next.run(request).await
}

fn matches_host(host: &[u8], expected: &[u8]) -> bool {
    host.eq_ignore_ascii_case(expected)
        || (!expected.contains(&b':')
            && host
                .strip_suffix(b":443")
                .is_some_and(|host| host.eq_ignore_ascii_case(expected)))
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
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
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

async fn webauthn_script() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../assets/webauthn.js"),
    )
}

async fn styles() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../assets/auth.css"),
    )
}

async fn seal() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "image/png")],
        include_bytes!("../assets/seal.png").as_slice(),
    )
}

async fn font() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "font/woff2")],
        include_bytes!("../assets/geist.woff2").as_slice(),
    )
}

async fn auth_work<T: Send + 'static>(
    app: Arc<App>,
    operation: impl FnOnce(&App) -> Result<T, ApiError> + Send + 'static,
) -> Result<T, ApiError> {
    let permit = app.auth_workers.clone().try_acquire_owned().map_err(|_| {
        ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication service busy",
        )
    })?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        operation(&app)
    })
    .await
    .map_err(ApiError::internal)?
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginStart {
    client_csr_pem: Option<String>,
    tcp_target: Option<String>,
    #[serde(default)]
    forward: bool,
    forward_scope: Option<String>,
}

async fn login_start(
    State(app): State<Arc<App>>,
    Extension(peer): Extension<Peer>,
    Json(body): Json<LoginStart>,
) -> Result<impl IntoResponse, ApiError> {
    auth_work(app, move |app| {
        let peer = peer.challenge_key();
        app.auth.check_challenge_capacity(peer)?;
        if body.forward || body.forward_scope.is_some() {
            let forward = app.forward.as_ref().ok_or(ApiError(
                StatusCode::BAD_REQUEST,
                "forward proxy is disabled",
            ))?;
            let scope = match body.forward_scope {
                Some(scope) => forward.gateway.scope_id(&scope).ok_or(ApiError(
                    StatusCode::FORBIDDEN,
                    "forward proxy scope is not configured",
                ))?,
                None if forward.gateway.config.scopes.len() == 1 => 0,
                None => {
                    return Err(ApiError(
                        StatusCode::BAD_REQUEST,
                        "multiple forward scopes configured, specify --scope",
                    ));
                }
            };
            if body.tcp_target.is_some() {
                return Err(ApiError(
                    StatusCode::BAD_REQUEST,
                    "forward scope cannot include a TCP target",
                ));
            }
            let grant = if let Some(csr) = body.client_csr_pem {
                let key = csr_key(&csr)
                    .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid P-256 client CSR"))?;
                Grant::Forward { key, scope }
            } else if forward.http_sessions.get(scope).is_some() {
                Grant::ForwardHttp { scope }
            } else {
                return Err(ApiError(
                    StatusCode::BAD_REQUEST,
                    "HTTP forward proxy is disabled",
                ));
            };
            return Ok(Json(app.auth.start_login(grant, peer)?));
        }
        let grant =
            match body.client_csr_pem {
                Some(csr) => {
                    let tcp = app
                        .tcp
                        .as_ref()
                        .ok_or(ApiError(StatusCode::BAD_REQUEST, "TCP relay is disabled"))?;
                    if let Some(host) = body.tcp_target
                        && !tcp
                            .ssh_host
                            .as_deref()
                            .is_some_and(|allowed| allowed.eq_ignore_ascii_case(&host))
                    {
                        return Err(ApiError(
                            StatusCode::FORBIDDEN,
                            "SSH host is not allowed by this proxy",
                        ));
                    }
                    Grant::Tcp(csr_key(&csr).map_err(|_| {
                        ApiError(StatusCode::BAD_REQUEST, "invalid P-256 client CSR")
                    })?)
                }
                None if body.tcp_target.is_some() => {
                    return Err(ApiError(
                        StatusCode::BAD_REQUEST,
                        "TCP target requires a client CSR",
                    ));
                }
                None if app.upstream.is_none() => {
                    return Err(ApiError(StatusCode::BAD_REQUEST, "HTTP relay is disabled"));
                }
                None => Grant::Http,
            };
        Ok(Json(app.auth.start_login(grant, peer)?))
    })
    .await
}

async fn login_finish(
    State(app): State<Arc<App>>,
    Json(body): Json<SignedChallenge<PublicKeyCredential>>,
) -> Result<Response, ApiError> {
    auth_work(app, move |app| {
        let (grant, generation) = app.auth.finish_login(body)?;
        check_generation(app, generation)?;
        match grant {
            Grant::Http => {
                let (cookie, expires_at) =
                    app.sessions.issue(generation).map_err(ApiError::internal)?;
                Ok((
                    [(SET_COOKIE, cookie)],
                    Json(serde_json::json!({ "expires_at": expires_at })),
                )
                    .into_response())
            }
            Grant::Tcp(key) => {
                let tcp = app
                    .tcp
                    .as_ref()
                    .ok_or_else(|| ApiError::internal("missing TCP issuer"))?;
                let certificate = tcp
                    .issuer
                    .issue(&key, tcp.ttl, generation, 0)
                    .map_err(ApiError::internal)?;
                Ok(Json(serde_json::json!({
                    "certificate_pem": certificate.certificate_pem,
                    "expires_at": certificate.expires_at,
                    "tcp_endpoint": tcp.endpoint,
                }))
                .into_response())
            }
            Grant::Tailscale(_) => Err(ApiError(
                StatusCode::UNAUTHORIZED,
                "wrong approval endpoint",
            )),
            Grant::Forward { key, scope } => {
                let forward = app
                    .forward
                    .as_ref()
                    .ok_or_else(|| ApiError::internal("missing forward issuer"))?;
                let certificate = forward
                    .gateway
                    .issuer
                    .issue(
                        &key,
                        forward.gateway.config.cert_ttl_seconds,
                        generation,
                        scope,
                    )
                    .map_err(ApiError::internal)?;
                Ok(Json(serde_json::json!({
                    "certificate_pem": certificate.certificate_pem,
                    "expires_at": certificate.expires_at,
                    "forward_endpoint": forward.endpoint,
                }))
                .into_response())
            }
            Grant::ForwardHttp { scope } => {
                let forward = app
                    .forward
                    .as_ref()
                    .ok_or_else(|| ApiError::internal("missing forward proxy"))?;
                let name = forward
                    .gateway
                    .scope_name(scope)
                    .ok_or_else(|| ApiError::internal("missing forward scope"))?;
                let sessions = forward
                    .http_sessions
                    .get(scope)
                    .ok_or_else(|| ApiError::internal("missing forward sessions"))?;
                let (token, expires_at) = sessions
                    .issue_token(generation)
                    .map_err(ApiError::internal)?;
                Ok(Json(serde_json::json!({
                    "proxy_session": format!("{name}.{token}"),
                    "expires_at": expires_at,
                }))
                .into_response())
            }
        }
    })
    .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TailscaleStart {
    target: String,
}

async fn tailscale_start(
    State(app): State<Arc<App>>,
    Extension(peer): Extension<Peer>,
    Json(body): Json<TailscaleStart>,
) -> Result<impl IntoResponse, ApiError> {
    let tailscale = app.tailscale.as_ref().ok_or(TAILSCALE_DISABLED)?;
    if !crate::config::is_tailscale_target(&body.target)
        || tailscale
            .target
            .as_ref()
            .is_some_and(|target| !target.eq_ignore_ascii_case(&body.target))
    {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "Tailscale SSH target is not allowed",
        ));
    }
    let _permit = tailscale
        .requests
        .try_acquire()
        .map_err(|_| TAILSCALE_BUSY)?;
    let device = tailscale
        .device(peer.0)
        .await
        .map_err(ApiError::internal)?
        .ok_or(TAILSCALE_PEER_REQUIRED)?;
    let challenge = auth_work(app.clone(), move |app| {
        app.auth.check_challenge_capacity(peer.0)?;
        app.auth.start_login(Grant::Tailscale(device), peer.0)
    })
    .await?;
    Ok(Json(challenge))
}

async fn tailscale_finish(
    State(app): State<Arc<App>>,
    Extension(peer): Extension<Peer>,
    Json(signed): Json<SignedChallenge<PublicKeyCredential>>,
) -> Result<impl IntoResponse, ApiError> {
    let tailscale = app.tailscale.as_ref().ok_or(TAILSCALE_DISABLED)?;
    let _permit = tailscale
        .requests
        .try_acquire()
        .map_err(|_| TAILSCALE_BUSY)?;
    let device = tailscale
        .device(peer.0)
        .await
        .map_err(ApiError::internal)?
        .ok_or(TAILSCALE_PEER_REQUIRED)?;
    let (generation, device) = auth_work(app.clone(), move |app| {
        let (grant, generation) = app.auth.finish_login(signed)?;
        if !matches!(grant, Grant::Tailscale(approved) if approved == device) {
            return Err(ApiError(
                StatusCode::UNAUTHORIZED,
                "approval must match the requesting Tailscale device",
            ));
        }
        Ok((generation, device))
    })
    .await?;
    let authorization = tailscale
        .authorization()
        .await
        .map_err(ApiError::internal)?;
    check_generation(&app, generation)?;
    let expires_at = tailscale
        .approve(&device, authorization)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(serde_json::json!({ "expires_at": expires_at })))
}

const TAILSCALE_DISABLED: ApiError = ApiError(StatusCode::NOT_FOUND, "Tailscale SSH is disabled");
const TAILSCALE_BUSY: ApiError =
    ApiError(StatusCode::SERVICE_UNAVAILABLE, "Tailscale approvals busy");
const TAILSCALE_PEER_REQUIRED: ApiError = ApiError(
    StatusCode::FORBIDDEN,
    "a user-owned Tailscale device is required",
);

fn check_generation(app: &App, generation: u64) -> Result<(), ApiError> {
    if app.auth.generation() == generation {
        Ok(())
    } else {
        Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "YubiKey permissions changed",
        ))
    }
}

fn signed_header(
    headers: &HeaderMap,
) -> Result<Option<SignedChallenge<PublicKeyCredential>>, ApiError> {
    let entries = headers.get_all(AUTHORIZATION);
    for value in entries.iter().filter_map(|value| value.to_str().ok()) {
        let (scheme, token) = value.split_once(' ').unwrap_or((value, ""));
        if scheme.eq_ignore_ascii_case("shomei") {
            if entries.iter().count() != 1 {
                return Err(ApiError(
                    StatusCode::UNAUTHORIZED,
                    "invalid Shomei authorization",
                ));
            }
            return decode_assertion(token).map(Some);
        }
    }
    Ok(None)
}

fn decode_assertion(token: &str) -> Result<SignedChallenge<PublicKeyCredential>, ApiError> {
    let invalid = || ApiError(StatusCode::UNAUTHORIZED, "invalid Shomei authorization");
    if token.is_empty() || token.len() > 8192 {
        return Err(invalid());
    }
    let body = URL_SAFE_NO_PAD.decode(token).map_err(|_| invalid())?;
    serde_json::from_slice(&body).map_err(|_| invalid())
}

pub(crate) async fn approve_forward_http(
    app: Arc<App>,
    headers: &HeaderMap,
) -> Result<(usize, u64, Duration), StatusCode> {
    let required = StatusCode::PROXY_AUTHENTICATION_REQUIRED;
    let mut values = headers.get_all(PROXY_AUTHORIZATION).iter();
    let (scheme, token) = values
        .next()
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split_once(' '))
        .ok_or(required)?;
    if values.next().is_some() {
        return Err(required);
    }
    let forward = app.forward.as_ref().ok_or(required)?;
    if scheme.eq_ignore_ascii_case("shomei-session") {
        let (name, token) = token.split_once('.').ok_or(required)?;
        let scope = forward.gateway.scope_id(name).ok_or(required)?;
        let generation = app.auth.generation();
        let remaining = forward
            .http_sessions
            .get(scope)
            .and_then(|sessions| sessions.remaining(token, generation))
            .ok_or(required)?;
        return Ok((scope, generation, Duration::from_secs(remaining)));
    }
    if !scheme.eq_ignore_ascii_case("shomei") {
        return Err(required);
    }
    let signed = decode_assertion(token).map_err(|_| required)?;
    auth_work(app, move |app| {
        let (grant, generation) = app.auth.finish_login(signed)?;
        let Grant::ForwardHttp { scope } = grant else {
            return Err(ApiError(
                StatusCode::UNAUTHORIZED,
                "HTTP forward approval required",
            ));
        };
        check_generation(app, generation)?;
        let forward = app
            .forward
            .as_ref()
            .ok_or_else(|| ApiError::internal("missing forward proxy"))?;
        Ok((scope, generation, Duration::from_secs(forward.http_ttl)))
    })
    .await
    .map_err(|error| {
        if error.0 == StatusCode::UNAUTHORIZED {
            required
        } else {
            error.0
        }
    })
}

async fn forward(State(app): State<Arc<App>>, mut request: Request) -> Response {
    let Some(upstream) = &app.upstream else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if request.method() == Method::CONNECT || request.headers().contains_key(UPGRADE) {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let signed = match signed_header(request.headers()) {
        Ok(signed) => signed,
        Err(error) => return error.into_response(),
    };
    let fresh_approval = app
        .protected_paths
        .as_ref()
        .is_some_and(|paths| path_needs_approval(request.uri().path(), paths));
    if fresh_approval && signed.is_none() {
        let mut response = ApiError(
            StatusCode::UNAUTHORIZED,
            "a fresh YubiKey approval is required",
        )
        .into_response();
        response.headers_mut().insert(CACHE_CONTROL, NO_STORE);
        return response;
    }
    if app.protected_paths.is_none()
        && signed.is_none()
        && !app
            .sessions
            .verify(request.headers(), app.auth.generation())
    {
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
    if strip_hop_headers(request.headers_mut()).is_err() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let Ok(permit) = app.http_requests.clone().try_acquire_owned() else {
        return ApiError(StatusCode::SERVICE_UNAVAILABLE, "HTTP relay busy").into_response();
    };
    let session = if let Some(signed) = signed {
        let result = auth_work(app.clone(), move |app| {
            let (grant, generation) = app.auth.finish_login(signed)?;
            if !matches!(grant, Grant::Http) {
                return Err(ApiError(
                    StatusCode::UNAUTHORIZED,
                    "HTTP authorization required",
                ));
            }
            check_generation(app, generation)?;
            let (cookie, _) = app.sessions.issue(generation).map_err(ApiError::internal)?;
            Ok((cookie, generation))
        })
        .await;
        match result {
            Ok((cookie, generation)) => {
                if let Err(error) = check_generation(&app, generation) {
                    return error.into_response();
                }
                request.headers_mut().remove(AUTHORIZATION);
                Some(cookie)
            }
            Err(error) => return error.into_response(),
        }
    } else {
        None
    };
    let mut parts = upstream.origin.clone().into_parts();
    parts.path_and_query = request.uri().path_and_query().cloned();
    let Ok(uri) = Uri::from_parts(parts) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    *request.uri_mut() = uri;
    *request.version_mut() = axum::http::Version::HTTP_11;
    let headers = request.headers_mut();
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
    if app.protected_paths.is_some() {
        for name in [
            "x-original-url",
            "x-original-uri",
            "x-original-path",
            "x-rewrite-url",
            "x-rewrite-uri",
            "x-envoy-original-path",
        ] {
            headers.remove(name);
        }
    }
    headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
    headers.insert("x-forwarded-host", app.host.clone());
    filter_cookies(headers, COOKIE);

    let request = request.map(|body| relay_body(body, None));
    let mut response =
        match timeout(Duration::from_secs(30), upstream.client.request(request)).await {
            Ok(Ok(response)) if response.status() == StatusCode::SWITCHING_PROTOCOLS => {
                StatusCode::BAD_GATEWAY.into_response()
            }
            Ok(Ok(response)) => response.map(|body| relay_body(Body::new(body), Some(permit))),
            Ok(Err(error)) => {
                eprintln!("HTTP upstream request failed: {error}");
                StatusCode::BAD_GATEWAY.into_response()
            }
            Err(_) => StatusCode::GATEWAY_TIMEOUT.into_response(),
        };
    if strip_hop_headers(response.headers_mut()).is_err() {
        return StatusCode::BAD_GATEWAY.into_response();
    }
    filter_cookies(response.headers_mut(), SET_COOKIE);
    if let Some(session) = session {
        response.headers_mut().append(SET_COOKIE, session);
    }
    response.headers_mut().insert(CACHE_CONTROL, NO_STORE);
    response
}

fn path_needs_approval(path: &str, protected: &[String]) -> bool {
    let Ok(decoded) = percent_encoding::percent_decode_str(path).decode_utf8() else {
        return true;
    };
    !http_path_is_unambiguous(&decoded)
        || (decoded.len() != path.len()
            && decoded.matches('/').count() != path.matches('/').count())
        || http_path_matches(&decoded, PREFIX)
        || protected
            .iter()
            .any(|prefix| http_path_matches(&decoded, prefix))
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

pub(crate) fn strip_hop_headers(headers: &mut HeaderMap) -> Result<(), ()> {
    let mut nominated = Vec::new();
    for value in headers.get_all(CONNECTION) {
        for token in value
            .to_str()
            .map_err(|_| ())?
            .split(',')
            .map(str::trim)
            .filter(|token| !token.is_empty())
        {
            let name = HeaderName::from_bytes(token.as_bytes()).map_err(|_| ())?;
            if [HOST, CONTENT_LENGTH, TRANSFER_ENCODING].contains(&name) {
                return Err(());
            }
            nominated.push(name);
        }
    }
    for name in nominated {
        headers.remove(name);
    }
    for name in [
        CONNECTION,
        HeaderName::from_static("keep-alive"),
        HeaderName::from_static("proxy-connection"),
        PROXY_AUTHENTICATE,
        PROXY_AUTHORIZATION,
        HeaderName::from_static("proxy-authentication-info"),
        TE,
        TRAILER,
        TRANSFER_ENCODING,
        UPGRADE,
    ] {
        headers.remove(name);
    }
    Ok(())
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

pub(crate) fn relay_body(body: Body, permit: Option<OwnedSemaphorePermit>) -> Body {
    Body::new(body.map_frame(move |frame| {
        let _permit = &permit;
        if frame.is_trailers() {
            Frame::data(Bytes::new())
        } else {
            frame
        }
    }))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod load;
