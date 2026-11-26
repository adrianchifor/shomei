pub(crate) mod approval;

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use axum::{
    Extension, Json, Router,
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, RawQuery, Request, State},
    http::{
        HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri,
        header::{self, *},
        uri::Authority,
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
use uuid::Uuid;
use webauthn_rs::prelude::PublicKeyCredential;

use crate::{
    accept_tls,
    auth::{ApiError, Auth, Grant, SignedChallenge},
    config::{Config, Endpoint, HttpUpstreamConfig, ProtectedPath},
    session::{Sessions, session_value},
    tailscale::TailscaleSsh,
    tls::csr_key,
};

const PREFIX: &str = "/_shomei";
const NO_STORE: HeaderValue = HeaderValue::from_static("private, no-store");

pub struct App {
    pub(crate) auth: Arc<Auth>,
    origin: String,
    canonical: Endpoint,
    hosts: HashSet<Endpoint>,
    hostnames: HashSet<String>,
    forwarding: bool,
    http_forwarding: bool,
    allow_unlisted_host: bool,
    upstreams: HashMap<Endpoint, HttpUpstream>,
    http_client: Client<HttpsConnector<HttpConnector>, Body>,
    tickets: Mutex<HashMap<Uuid, LoginTicket>>,
    approvals: approval::Approvals,
    ticket_limit: usize,
    forward: Option<ForwardAccess>,
    tailscale: Option<TailscaleSsh>,
    auth_workers: Arc<Semaphore>,
    http_requests: Arc<Semaphore>,
    https_tunnels: Arc<Semaphore>,
}

struct ForwardAccess {
    gateway: Arc<crate::forward::Gateway>,
    endpoint: String,
    http_sessions: Vec<Sessions>,
    http_ttl: u64,
}

#[derive(Clone, Copy)]
struct Peer(IpAddr);

#[derive(Clone)]
struct RequestHost(Endpoint);

struct LoginTicket {
    host: Endpoint,
    next: String,
    generation: u64,
    deadline: Instant,
}

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
    protected_paths: Option<Vec<ProtectedPath>>,
    protected_session_ttl_seconds: u64,
    sessions: Sessions,
}

pub fn app(
    config: Config,
    forward: Option<Arc<crate::forward::Gateway>>,
) -> Result<(Router, Arc<App>)> {
    let state = state(config, forward)?;
    Ok((routes(state.clone()), state))
}

fn state(config: Config, forward: Option<Arc<crate::forward::Gateway>>) -> Result<Arc<App>> {
    let auth = Auth::new(
        &config.origin,
        &config.state_dir,
        &config.identities_file,
        &config.limits,
        config.allow_yubikey_4,
    )?;
    state_with_auth(config, auth, forward)
}

fn state_with_auth(
    config: Config,
    auth: Auth,
    forward: Option<Arc<crate::forward::Gateway>>,
) -> Result<Arc<App>> {
    let forwarding = config.forwarding;
    let http_forwarding = forwarding && config.http_forwarding;
    let allow_unlisted_host = !forwarding && config.http_upstream_count() == 1;
    let hostname = config.origin.domain().context("missing proxy hostname")?;
    let port = config.origin.port_or_known_default();
    let canonical = Endpoint::parse(hostname, port)?;
    let mut hosts = HashSet::from([canonical.clone()]);
    for host in config.hostnames {
        hosts.insert(Endpoint::parse(&host, port)?);
    }
    let mut upstreams = HashMap::new();
    let sessions = |host: &Endpoint| -> Result<Sessions> {
        let sessions = Sessions::new(config.session_ttl_seconds)?;
        Ok(if *host == canonical {
            sessions
        } else {
            sessions.for_port(host.port)
        })
    };
    let mut sites = config.http_upstreams;
    if let Some(origin) = config.http_upstream {
        sites.push(HttpUpstreamConfig {
            hostname: None,
            upstream: origin,
            protected_paths: config.protected_paths,
            protected_session_ttl_seconds: None,
        });
    }
    sites.sort_by_key(|site| site.hostname.is_some());
    for site in sites {
        let origin = site.upstream.as_str().parse::<Uri>()?;
        let protected_session_ttl_seconds = site
            .protected_session_ttl_seconds
            .unwrap_or(config.protected_session_ttl_seconds);
        if let Some(host) = site.hostname {
            let host = Endpoint::parse(&host, port)?;
            hosts.insert(host.clone());
            if allow_unlisted_host {
                for alias in hosts.iter().filter(|alias| **alias != host) {
                    upstreams.insert(
                        alias.clone(),
                        HttpUpstream {
                            origin: origin.clone(),
                            protected_paths: site.protected_paths.clone(),
                            protected_session_ttl_seconds,
                            sessions: sessions(alias)?,
                        },
                    );
                }
            }
            let sessions = sessions(&host)?;
            upstreams.insert(
                host,
                HttpUpstream {
                    origin,
                    protected_paths: site.protected_paths,
                    protected_session_ttl_seconds,
                    sessions,
                },
            );
        } else {
            for host in &hosts {
                upstreams.insert(
                    host.clone(),
                    HttpUpstream {
                        origin: origin.clone(),
                        protected_paths: site.protected_paths.clone(),
                        protected_session_ttl_seconds,
                        sessions: sessions(host)?,
                    },
                );
            }
        }
    }
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
    let http_client = Client::builder(TokioExecutor::new())
        .pool_timer(TokioTimer::new())
        .pool_idle_timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(config.limits.http_requests.min(4096))
        .http1_max_buf_size(32 * 1024)
        .http2_max_header_list_size(32 * 1024)
        .build(connector);
    let hostnames = hosts.iter().map(|host| host.host.clone()).collect();
    Ok(Arc::new(App {
        auth: Arc::new(auth),
        origin: config.origin.origin().ascii_serialization(),
        canonical,
        hosts,
        hostnames,
        forwarding,
        http_forwarding,
        allow_unlisted_host,
        upstreams,
        http_client,
        tickets: Mutex::new(HashMap::new()),
        approvals: approval::Approvals::new(config.limits.pending_challenges),
        ticket_limit: config.limits.pending_challenges,
        forward: forward
            .map(|gateway| -> Result<_> {
                let http_sessions = if http_forwarding {
                    gateway
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
                        gateway.tcp.public_port.unwrap_or(gateway.tcp.bind.port())
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
        https_tunnels: Arc::new(Semaphore::new(config.limits.https_connections)),
    }))
}

fn routes(state: Arc<App>) -> Router {
    let reserved = Router::new()
        .route("/login", get(page))
        .route("/auth.js", get(script))
        .route("/webauthn.js", get(webauthn_script))
        .route("/approval.js", get(approval::script))
        .route("/approval.css", get(approval::stylesheet))
        .route("/approval.html", get(approval::dialog))
        .route("/approval-popup", get(approval::popup))
        .route("/auth.css", get(styles))
        .route("/seal.png", get(seal))
        .route("/geist.woff2", get(font))
        .route("/api/auth/start", post(login_start))
        .route(approval::CHECK_PATH, post(approval::check))
        .route("/api/auth/finish", post(login_finish))
        .route("/api/auth/tailscale/start", post(tailscale_start))
        .route("/api/auth/tailscale/finish", post(tailscale_finish))
        .route("/complete", get(complete_login))
        .fallback(|| async { StatusCode::NOT_FOUND })
        .layer(DefaultBodyLimit::max(32 * 1024))
        .layer(middleware::from_fn_with_state(state.clone(), protect_auth));
    Router::new()
        .nest(PREFIX, reserved)
        .fallback(reverse)
        .layer(middleware::from_fn_with_state(state.clone(), check_host))
        .with_state(state)
}

pub async fn serve(
    socket: TcpStream,
    peer: SocketAddr,
    tls: TlsAcceptor,
    app: Router,
    state: Arc<App>,
    handshakes: Arc<Semaphore>,
) {
    let Some(stream) = accept_tls(socket, tls.clone(), &handshakes).await else {
        return;
    };
    let app = TowerToHyperService::new(app);
    let peer = peer.ip().to_canonical();
    let service = service_fn(move |mut request: hyper::Request<Incoming>| {
        request.extensions_mut().insert(Peer(peer));
        let state = state.clone();
        let app = app.clone();
        let tls = tls.clone();
        let handshakes = handshakes.clone();
        async move {
            let origin_form = request.uri().authority().is_none();
            let authority = if origin_form {
                let mut hosts = request.headers().get_all(HOST).iter();
                let authority = hosts
                    .next()
                    .and_then(|host| host.to_str().ok())
                    .and_then(|host| host.parse::<Authority>().ok());
                if hosts.next().is_some() {
                    return Ok(StatusCode::MISDIRECTED_REQUEST.into_response());
                }
                authority
            } else {
                request.uri().authority().cloned()
            };
            if let Some(authority) = authority {
                let port = if request.method() == Method::CONNECT {
                    None
                } else if request.uri().scheme_str() == Some("http") {
                    Some(80)
                } else {
                    Some(443)
                };
                let Some(endpoint) = Endpoint::from_authority(&authority, port) else {
                    return Ok(StatusCode::BAD_REQUEST.into_response());
                };
                let forward = state.forward.as_ref().filter(|_| state.http_forwarding);
                if state.hosts.contains(&endpoint) {
                    if request.method() == Method::CONNECT && forward.is_some() {
                        if !crate::forward::valid_connect(&request) {
                            return Ok(StatusCode::BAD_REQUEST.into_response());
                        }
                        let Ok(slot) = state.https_tunnels.clone().try_acquire_owned() else {
                            return Ok(StatusCode::SERVICE_UNAVAILABLE.into_response());
                        };
                        let upgrade = hyper::upgrade::on(&mut request);
                        tokio::spawn(async move {
                            let _slot = slot;
                            serve_reverse_tunnel(upgrade, tls, endpoint, app, peer, handshakes)
                                .await;
                        });
                        return Ok(StatusCode::OK.into_response());
                    }
                } else {
                    if state.forwarding && state.hostnames.contains(&endpoint.host) {
                        return Ok(StatusCode::MISDIRECTED_REQUEST.into_response());
                    }
                    if let Some(gateway) = forward {
                        if origin_form {
                            let Some(path) = request.uri().path_and_query().cloned() else {
                                return Ok(StatusCode::BAD_REQUEST.into_response());
                            };
                            let Ok(uri) = Uri::builder()
                                .scheme("http")
                                .authority(authority)
                                .path_and_query(path)
                                .build()
                            else {
                                return Ok(StatusCode::BAD_REQUEST.into_response());
                            };
                            *request.uri_mut() = uri;
                        }
                        return Ok(crate::forward::proxy_http(
                            request,
                            gateway.gateway.clone(),
                            state,
                        )
                        .await);
                    }
                }
            }
            app.call(request).await
        }
    });
    if stream.get_ref().1.alpn_protocol() == Some(b"h2") {
        let _ = http2()
            .serve_connection(TokioIo::new(stream), service)
            .await;
    } else {
        let _ = crate::forward::http1()
            .serve_connection(TokioIo::new(stream), service)
            .with_upgrades()
            .await;
    }
}

fn http2() -> auto::Builder<TokioExecutor> {
    let mut builder = auto::Builder::new(TokioExecutor::new()).http2_only();
    builder
        .http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(64)
        .max_pending_accept_reset_streams(64)
        .max_header_list_size(32 * 1024)
        .max_send_buf_size(64 * 1024)
        .keep_alive_interval(Duration::from_secs(30))
        .keep_alive_timeout(Duration::from_secs(10));
    builder
}

async fn serve_reverse_tunnel(
    upgrade: hyper::upgrade::OnUpgrade,
    tls: TlsAcceptor,
    host: Endpoint,
    app: TowerToHyperService<Router>,
    peer: IpAddr,
    handshakes: Arc<Semaphore>,
) {
    let Ok(Some(stream)) = timeout(Duration::from_secs(10), async {
        let socket = upgrade.await.ok()?;
        let _permit = handshakes.acquire().await.ok()?;
        tls.accept(TokioIo::new(socket)).await.ok()
    })
    .await
    else {
        return;
    };
    let service = service_fn(move |mut request: hyper::Request<Incoming>| {
        let expected = host.clone();
        let app = app.clone();
        async move {
            if reverse_endpoint(&request).as_ref() != Some(&expected)
                || request.method() == Method::CONNECT
            {
                return Ok(StatusCode::MISDIRECTED_REQUEST.into_response());
            }
            request.extensions_mut().insert(Peer(peer));
            app.call(request).await
        }
    });
    if stream.get_ref().1.alpn_protocol() == Some(b"h2") {
        let _ = http2()
            .serve_connection(TokioIo::new(stream), service)
            .await;
    } else {
        let _ = crate::forward::http1()
            .serve_connection(TokioIo::new(stream), service)
            .await;
    }
}

fn reverse_endpoint<B>(request: &hyper::Request<B>) -> Option<Endpoint> {
    let mut hosts = request.headers().get_all(HOST).iter();
    let host = hosts.next().map(HeaderValue::to_str).transpose().ok()?;
    if hosts.next().is_some() {
        return None;
    }
    let uri = request.uri();
    if uri
        .scheme_str()
        .is_some_and(|scheme| !matches!(scheme, "http" | "https"))
    {
        return None;
    }
    let default_port = Some(if uri.scheme_str() == Some("http") {
        80
    } else {
        443
    });
    if let Some(authority) = uri.authority() {
        Endpoint::from_authority(authority, default_port).filter(|endpoint| {
            host.is_none_or(|host| {
                Endpoint::parse(host, default_port).is_ok_and(|host| host == *endpoint)
            })
        })
    } else {
        host.and_then(|host| Endpoint::parse(host, default_port).ok())
    }
}

async fn check_host(State(app): State<Arc<App>>, mut request: Request, next: Next) -> Response {
    let Some(wire) = reverse_endpoint(&request) else {
        return StatusCode::MISDIRECTED_REQUEST.into_response();
    };
    let endpoint = if app.hosts.contains(&wire) {
        wire
    } else if app.allow_unlisted_host {
        if request.uri().path() == "/_shomei/login" {
            let path = request
                .uri()
                .path_and_query()
                .map_or("/", |path| path.as_str());
            return Redirect::to(&format!("{}{path}", app.origin)).into_response();
        }
        app.canonical.clone()
    } else {
        return StatusCode::MISDIRECTED_REQUEST.into_response();
    };
    if request.method() == Method::CONNECT {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    request.extensions_mut().insert(RequestHost(endpoint));
    next.run(request).await
}

async fn protect_auth(State(app): State<Arc<App>>, request: Request, next: Next) -> Response {
    let authorized_origin = if request.uri().path() == approval::CHECK_PATH {
        let host = request.extensions().get::<RequestHost>();
        reverse_endpoint(&request).is_some_and(|wire| {
            host.is_some_and(|host| {
                host.0 == wire && approval::same_origin_browser(request.headers(), &wire, true)
            })
        })
    } else {
        let read = matches!(*request.method(), Method::GET | Method::HEAD);
        let wire = reverse_endpoint(&request);
        let read_origin = read
            .then(|| wire.as_ref().map(approval::site_origin))
            .flatten();
        let expected_origin = read_origin.as_deref().unwrap_or(&app.origin);
        let mut origins = request.headers().get_all(ORIGIN).iter();
        let wrong_origin = origins
            .next()
            .is_some_and(|origin| origin.as_bytes() != expected_origin.as_bytes())
            || origins.next().is_some();
        let alias_write = !read && wire.as_ref() != Some(&app.canonical);
        !wrong_origin && !alias_write
    };
    let mut response = if !authorized_origin {
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

#[derive(Default, Deserialize)]
struct BrowserQuery {
    app: Option<String>,
    next: Option<String>,
}

impl App {
    fn browser_login_url(&self, host: &Endpoint, next: Option<&str>) -> String {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        if *host != self.canonical {
            query.append_pair("app", &host.to_string());
        }
        if let Some(next) = next {
            query.append_pair("next", next);
        }
        format!("{}{PREFIX}/login?{}", self.origin, query.finish())
    }
}

async fn page(
    State(app): State<Arc<App>>,
    Extension(RequestHost(host)): Extension<RequestHost>,
    RawQuery(query): RawQuery,
) -> Response {
    if host != app.canonical {
        if !app.upstreams.contains_key(&host) {
            return StatusCode::NOT_FOUND.into_response();
        }
        let next = url::form_urlencoded::parse(query.as_deref().unwrap_or_default().as_bytes())
            .find_map(|(name, value)| (name == "next").then_some(value));
        return Redirect::to(&app.browser_login_url(&host, next.as_deref())).into_response();
    }
    Html(include_str!("../assets/auth.html")).into_response()
}

fn safe_return_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.starts_with("//")
        && !path.contains(['\\', '#'])
        && path.len() <= 4096
        && !path.starts_with(PREFIX)
        && path.bytes().all(|byte| byte.is_ascii_graphic())
}

async fn complete_login(
    State(app): State<Arc<App>>,
    Extension(RequestHost(host)): Extension<RequestHost>,
    RawQuery(query): RawQuery,
) -> Result<Response, ApiError> {
    let key = url::form_urlencoded::parse(query.as_deref().unwrap_or_default().as_bytes())
        .find_map(|(name, value)| {
            if name == "ticket" {
                value.parse::<Uuid>().ok()
            } else {
                None
            }
        })
        .ok_or(ApiError(StatusCode::BAD_REQUEST, "invalid login ticket"))?;
    let (ticket, cookie) = {
        let mut tickets = app.tickets.lock().map_err(ApiError::internal)?;
        let ticket = tickets
            .get(&key)
            .filter(|ticket| ticket.host == host && ticket.deadline > Instant::now())
            .ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid login ticket"))?;
        check_generation(&app, ticket.generation)?;
        let site = app
            .upstreams
            .get(&host)
            .ok_or(ApiError(StatusCode::NOT_FOUND, "unknown HTTP upstream"))?;
        let (cookie, _) = site
            .sessions
            .issue(ticket.generation)
            .map_err(ApiError::internal)?;
        let ticket = tickets.remove(&key).expect("ticket held under lock");
        (ticket, cookie)
    };
    Ok(([(SET_COOKIE, cookie)], Redirect::to(&ticket.next)).into_response())
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
    http_destination: Option<url::Url>,
    tcp_destination: Option<String>,
    browser_login: Option<BrowserQuery>,
    browser_approval: Option<approval::Start>,
}

async fn login_start(
    State(app): State<Arc<App>>,
    Extension(peer): Extension<Peer>,
    headers: HeaderMap,
    Json(mut body): Json<LoginStart>,
) -> Result<impl IntoResponse, ApiError> {
    auth_work(app, move |app| {
        let peer = peer.challenge_key();
        app.auth.check_challenge_capacity(peer)?;
        let destinations = [
            body.browser_login.is_some(),
            body.browser_approval.is_some(),
            body.http_destination.is_some(),
            body.tcp_destination.is_some(),
            body.tcp_target.is_some(),
        ]
        .into_iter()
        .filter(|selected| *selected)
        .count();
        if destinations > 1
            || (body.client_csr_pem.is_some()
                && (body.browser_login.is_some()
                    || body.browser_approval.is_some()
                    || body.http_destination.is_some()))
            || (body.tcp_destination.is_some() && body.client_csr_pem.is_none())
        {
            return Err(ApiError(
                StatusCode::BAD_REQUEST,
                "invalid approval destination or client CSR",
            ));
        }
        if let Some(browser) = body.browser_approval.take() {
            if !approval::same_origin_browser(&headers, &app.canonical, true) {
                return Err(ApiError(
                    StatusCode::FORBIDDEN,
                    "browser approval requires the gateway origin",
                ));
            }
            let intent = approval::intent(app, browser)?;
            return Ok(Json(
                app.auth.start_login(Grant::BrowserApproval(intent), peer)?,
            ));
        }
        if let Some(browser) = body.browser_login.take() {
            let host = match browser.app {
                Some(host) => Endpoint::parse(&host, Some(443)).ok(),
                None => Some(app.canonical.clone()),
            }
            .filter(|host| app.upstreams.contains_key(host))
            .ok_or(ApiError(
                StatusCode::FORBIDDEN,
                "HTTP upstream is not configured",
            ))?;
            let next = browser
                .next
                .filter(|next| safe_return_path(next))
                .unwrap_or_else(|| "/".into());
            return Ok(Json(
                app.auth
                    .start_login(Grant::BrowserLogin { host, next }, peer)?,
            ));
        }
        if let Some(url) = body.http_destination.take() {
            let host = Endpoint::parse(
                &url[url::Position::BeforeHost..url::Position::AfterPort],
                url.port_or_known_default(),
            )
            .ok()
            .filter(|_| {
                matches!(url.scheme(), "http" | "https")
                    && url.username().is_empty()
                    && url.password().is_none()
            })
            .ok_or(ApiError(
                StatusCode::BAD_REQUEST,
                "invalid HTTP destination",
            ))?;
            if app.upstreams.contains_key(&host) || app.allow_unlisted_host {
                let host = if app.upstreams.contains_key(&host) {
                    host
                } else {
                    app.canonical.clone()
                };
                return Ok(Json(app.auth.start_login(Grant::HttpHost(host), peer)?));
            }
            if app.hostnames.contains(&host.host) {
                return Err(ApiError(
                    StatusCode::NOT_FOUND,
                    "HTTP upstream is not configured for that authority",
                ));
            }
            body.forward = true;
        }
        if let Some(target) = body.tcp_destination.take() {
            let endpoint = Endpoint::parse(&target, None)
                .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid TCP destination"))?;
            if let Some(scope) = app
                .forward
                .as_ref()
                .and_then(|forward| forward.gateway.tcp_id(&endpoint))
            {
                let key = body
                    .client_csr_pem
                    .as_deref()
                    .and_then(|csr| csr_key(csr).ok())
                    .ok_or(ApiError(
                        StatusCode::BAD_REQUEST,
                        "invalid P-256 client CSR",
                    ))?;
                return Ok(Json(
                    app.auth.start_login(Grant::Forward { key, scope }, peer)?,
                ));
            }
            if endpoint.port == 22
                && app
                    .forward
                    .as_ref()
                    .and_then(|forward| forward.gateway.tcp.ssh_host.as_deref())
                    .is_some_and(|host| host.eq_ignore_ascii_case(&endpoint.host))
            {
                body.tcp_target = Some(endpoint.host);
            } else {
                body.forward = true;
            }
        }
        if body.forward || body.forward_scope.is_some() {
            let forward = app
                .forward
                .as_ref()
                .filter(|_| app.forwarding)
                .ok_or(ApiError(
                    StatusCode::BAD_REQUEST,
                    "forward proxy is disabled",
                ))?;
            let scope = match body.forward_scope {
                Some(scope) => forward.gateway.scope_id(&scope).ok_or(ApiError(
                    StatusCode::FORBIDDEN,
                    "forward proxy scope is not configured",
                ))?,
                None if forward.gateway.scopes.len() == 1 => 0,
                None if forward.gateway.scopes.is_empty() => {
                    return Err(ApiError(
                        StatusCode::FORBIDDEN,
                        "no forward scope configured",
                    ));
                }
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
                    let forward = app
                        .forward
                        .as_ref()
                        .filter(|forward| forward.gateway.tcp.upstream.is_some())
                        .ok_or(ApiError(StatusCode::BAD_REQUEST, "TCP relay is disabled"))?;
                    if let Some(host) = body.tcp_target
                        && !forward
                            .gateway
                            .tcp
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
                None if !app.upstreams.contains_key(&app.canonical) => {
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
    headers: HeaderMap,
    Json(body): Json<SignedChallenge<PublicKeyCredential>>,
) -> Result<Response, ApiError> {
    auth_work(app, move |app| {
        let (grant, generation) = app.auth.finish_login(body)?;
        check_generation(app, generation)?;
        match grant {
            Grant::Http => {
                let session = &app
                    .upstreams
                    .get(&app.canonical)
                    .ok_or_else(|| ApiError::internal("missing HTTP upstream"))?
                    .sessions;
                let (cookie, expires_at) = session.issue(generation).map_err(ApiError::internal)?;
                Ok((
                    [(SET_COOKIE, cookie)],
                    Json(serde_json::json!({ "expires_at": expires_at })),
                )
                    .into_response())
            }
            Grant::HttpHost(_) => Err(ApiError(
                StatusCode::BAD_REQUEST,
                "use the assertion on the selected reverse HTTP upstream",
            )),
            Grant::BrowserApproval(intent) => {
                if !approval::same_origin_browser(&headers, &app.canonical, true) {
                    return Err(ApiError(
                        StatusCode::FORBIDDEN,
                        "browser approval requires the gateway origin",
                    ));
                }
                app.approvals.issue(intent, generation)
            }
            Grant::BrowserLogin { host, next } => {
                let key = Uuid::new_v4();
                let mut tickets = app.tickets.lock().map_err(ApiError::internal)?;
                let now = Instant::now();
                tickets.retain(|_, ticket| ticket.deadline > now);
                if tickets.len() >= app.ticket_limit {
                    return Err(ApiError(
                        StatusCode::TOO_MANY_REQUESTS,
                        "too many browser approvals",
                    ));
                }
                let redirect = format!("https://{host}{PREFIX}/complete?ticket={key}");
                tickets.insert(
                    key,
                    LoginTicket {
                        host,
                        next,
                        generation,
                        deadline: now + Duration::from_secs(30),
                    },
                );
                Ok(Json(serde_json::json!({ "redirect": redirect })).into_response())
            }
            Grant::Tcp(key) => {
                let forward = app
                    .forward
                    .as_ref()
                    .ok_or_else(|| ApiError::internal("missing TCP issuer"))?;
                let certificate = forward
                    .gateway
                    .issuer
                    .issue(
                        &key,
                        forward.gateway.tcp.cert_ttl_seconds,
                        generation,
                        crate::forward::FIXED_TCP_GRANT,
                    )
                    .map_err(ApiError::internal)?;
                Ok(Json(serde_json::json!({
                    "certificate_pem": certificate.certificate_pem,
                    "expires_at": certificate.expires_at,
                    "tcp_endpoint": forward.endpoint,
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
                        forward.gateway.tcp.cert_ttl_seconds,
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

async fn reverse(
    State(app): State<Arc<App>>,
    Extension(RequestHost(host)): Extension<RequestHost>,
    mut request: Request,
) -> Response {
    let Some(upstream) = app.upstreams.get(&host) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if request.method() == Method::CONNECT || request.headers().contains_key(UPGRADE) {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let signed = match signed_header(request.headers()) {
        Ok(signed) => signed,
        Err(error) => return error.into_response(),
    };
    let approval_policy = approval::policy(upstream, request.uri().path());
    if signed.is_none()
        && let Some(policy) = approval_policy
    {
        match approval::authorize(&app, &host, &request, policy) {
            Ok(true) => {}
            Err(error) => return error.into_response(),
            Ok(false) => {
                let mut response = ApiError(
                    StatusCode::UNAUTHORIZED,
                    "a fresh YubiKey approval is required",
                )
                .into_response();
                response.headers_mut().insert(CACHE_CONTROL, NO_STORE);
                return response;
            }
        }
    }
    if upstream.protected_paths.is_none()
        && signed.is_none()
        && !upstream
            .sessions
            .verify(request.headers(), app.auth.generation())
    {
        let mut response = if wants_login(&request) {
            let target = request
                .uri()
                .path_and_query()
                .map_or("/", |value| value.as_str());
            if host == app.canonical {
                let query = url::form_urlencoded::Serializer::new(String::new())
                    .append_pair("next", target)
                    .finish();
                Redirect::to(&format!("{PREFIX}/login?{query}")).into_response()
            } else {
                Redirect::to(&app.browser_login_url(&host, Some(target))).into_response()
            }
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
        let approved_host = host.clone();
        let result = auth_work(app.clone(), move |app| {
            let (grant, generation) = app.auth.finish_login(signed)?;
            let accepted = match grant {
                Grant::Http => approved_host == app.canonical,
                Grant::HttpHost(host) => host == approved_host,
                _ => false,
            };
            if !accepted {
                return Err(ApiError(
                    StatusCode::UNAUTHORIZED,
                    "HTTP authorization required",
                ));
            }
            Ok(generation)
        })
        .await;
        match result {
            Ok(generation) => {
                if let Err(error) = check_generation(&app, generation) {
                    return error.into_response();
                }
                let cookie = if let Some(policy) = approval_policy {
                    approval::issue_cookie(&app, &request, policy, generation)
                } else {
                    upstream
                        .sessions
                        .issue(generation)
                        .map(|(cookie, _)| Some(cookie))
                        .map_err(ApiError::internal)
                };
                request.headers_mut().remove(AUTHORIZATION);
                match cookie {
                    Ok(cookie) => cookie,
                    Err(error) => return error.into_response(),
                }
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
    if upstream.protected_paths.is_some() {
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
    if let Ok(host) = HeaderValue::from_str(&host.to_string()) {
        headers.insert("x-forwarded-host", host);
    }
    filter_cookies(headers, COOKIE);

    let sent = Arc::new(AtomicU64::new(0));
    let request = request.map(|body| upload_body(body, sent.clone()));
    let mut response =
        match response_head(app.http_client.request(request), &sent, UPSTREAM_TIMEOUT).await {
            Some(Ok(response)) if response.status() == StatusCode::SWITCHING_PROTOCOLS => {
                StatusCode::BAD_GATEWAY.into_response()
            }
            Some(Ok(response)) => response.map(|body| relay_body(Body::new(body), Some(permit))),
            Some(Err(error)) => {
                eprintln!("HTTP upstream request failed: {error}");
                StatusCode::BAD_GATEWAY.into_response()
            }
            None => StatusCode::GATEWAY_TIMEOUT.into_response(),
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
        HeaderName::from_static(approval::HEADER),
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

pub(crate) const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(30);
const MIN_UPLOAD_PROGRESS: u64 = 1024 * 1024;

/// A request body that counts the bytes the upstream has taken.
pub(crate) fn upload_body(body: Body, sent: Arc<AtomicU64>) -> Body {
    Body::new(relay_body(body, None).map_frame(move |frame| {
        if let Some(data) = frame.data_ref() {
            sent.fetch_add(data.len() as u64, Ordering::Relaxed);
        }
        frame
    }))
}

/// Waits for an upstream's response head. The limit restarts after each
/// `window` in which the request body moved at least `MIN_UPLOAD_PROGRESS`
/// bytes, so a large upload is not cut off while a stalled one still is.
pub(crate) async fn response_head<F: Future>(
    response: F,
    sent: &AtomicU64,
    window: Duration,
) -> Option<F::Output> {
    let mut response = std::pin::pin!(response);
    let mut seen = 0;
    loop {
        if let Ok(output) = timeout(window, response.as_mut()).await {
            return Some(output);
        }
        let total = sent.load(Ordering::Relaxed);
        if total - seen < MIN_UPLOAD_PROGRESS {
            return None;
        }
        seen = total;
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
