use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap},
    convert::Infallible,
    future::Future,
    net::IpAddr,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use axum::{
    body::Body,
    http::{Method, Response, StatusCode, Uri, Version, header, uri::Authority},
    response::IntoResponse,
};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde::Deserialize;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, copy_bidirectional_with_sizes},
    net::TcpStream,
    sync::{Semaphore, watch},
    time::{Instant, sleep_until, timeout},
};
use tokio_rustls::TlsAcceptor;

use crate::{
    accept_tls,
    config::{Endpoint, TcpConfig},
    http::{App, approve_forward_http, relay_body, strip_hop_headers},
    tls::{Issuer, client_grant},
};

pub const FIXED_TCP_GRANT: usize = usize::MAX;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    #[serde(default)]
    allow_all: bool,
    #[serde(default)]
    dns_suffixes: Vec<String>,
    #[serde(default)]
    cidrs: Vec<Network>,
    #[serde(default)]
    ports: Vec<u16>,
    http_ports: Option<Vec<u16>>,
    #[serde(default = "https_ports")]
    https_ports: Vec<u16>,
}

#[derive(Deserialize)]
#[serde(try_from = "String")]
struct Network {
    ip: IpAddr,
    prefix: u32,
}

impl TryFrom<String> for Network {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self> {
        let (ip, prefix) = value
            .split_once('/')
            .context("CIDR needs a prefix length")?;
        let ip: IpAddr = ip.parse().context("invalid CIDR address")?;
        let prefix = prefix.parse()?;
        ensure!(
            ip == ip.to_canonical() && prefix <= if ip.is_ipv4() { 32 } else { 128 },
            "invalid CIDR prefix"
        );
        Ok(Self { ip, prefix })
    }
}

impl Network {
    fn contains(&self, address: IpAddr) -> bool {
        match (self.ip, address.to_canonical()) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                self.prefix == 0
                    || ((u32::from(network) ^ u32::from(address)) >> (32 - self.prefix)) == 0
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                self.prefix == 0
                    || ((u128::from(network) ^ u128::from(address)) >> (128 - self.prefix)) == 0
            }
            _ => false,
        }
    }
}

pub fn validate_scopes(scopes: &BTreeMap<String, Scope>) -> Result<()> {
    for (name, scope) in scopes {
        ensure!(
            (1..=64).contains(&name.len())
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
            "invalid forward scope name {name:?}"
        );
        if scope.allow_all {
            ensure!(
                scope.cidrs.is_empty() && scope.ports.is_empty() && scope.dns_suffixes.is_empty(),
                "forward scope {name:?} cannot combine allow_all with CIDRs, ports, or DNS suffixes"
            );
        } else {
            ensure!(
                !scope.cidrs.is_empty() && !scope.ports.is_empty() && !scope.ports.contains(&0),
                "forward scope {name:?} needs CIDRs and nonzero ports"
            );
        }
        ensure!(
            !scope
                .http_ports
                .as_ref()
                .is_some_and(|ports| ports.contains(&0))
                && !scope.https_ports.contains(&0),
            "invalid HTTP proxy ports in forward scope {name:?}"
        );
        ensure!(
            scope
                .dns_suffixes
                .iter()
                .all(|suffix| dns_name(suffix) && suffix.parse::<IpAddr>().is_err()),
            "invalid DNS suffix in forward scope {name:?}"
        );
    }
    Ok(())
}

pub struct Gateway {
    pub tcp: TcpConfig,
    pub scopes: BTreeMap<String, Scope>,
    pub issuer: Issuer,
    scope_names: Vec<String>,
    tcp_targets: HashMap<Endpoint, usize>,
    tcp_upstreams: Vec<Endpoint>,
    requests: Arc<Semaphore>,
}

impl Gateway {
    pub fn new(tcp: TcpConfig, scopes: BTreeMap<String, Scope>, requests: usize) -> Result<Self> {
        let scope_names = scopes.keys().cloned().collect();
        Ok(Self {
            tcp,
            scopes,
            issuer: Issuer::new()?,
            scope_names,
            tcp_targets: HashMap::new(),
            tcp_upstreams: Vec::new(),
            requests: Arc::new(Semaphore::new(requests)),
        })
    }

    pub fn scope_id(&self, name: &str) -> Option<usize> {
        self.scope_names
            .binary_search_by(|current| current.as_str().cmp(name))
            .ok()
    }

    pub fn scope_name(&self, id: usize) -> Option<&str> {
        self.scope_names.get(id).map(String::as_str)
    }

    pub fn with_tcp_upstreams(mut self, routes: BTreeMap<String, String>) -> Result<Self> {
        for (host, upstream) in routes {
            let host = Endpoint::parse(&host, None)?;
            let upstream = Endpoint::parse(&upstream, None)?;
            self.tcp_targets
                .insert(host, self.scope_names.len() + self.tcp_upstreams.len());
            self.tcp_upstreams.push(upstream);
        }
        Ok(self)
    }

    pub fn tcp_id(&self, target: &Endpoint) -> Option<usize> {
        self.tcp_targets.get(target).copied()
    }

    fn tcp_upstream(&self, id: usize) -> Option<&Endpoint> {
        self.tcp_upstreams
            .get(id.checked_sub(self.scope_names.len())?)
    }
}

fn https_ports() -> Vec<u16> {
    vec![443]
}

fn dns_name(name: &str) -> bool {
    name.len() <= 253
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

pub fn target(authority: &Authority, default_port: Option<u16>) -> Option<(&str, u16)> {
    let authority_host = authority.host();
    let host = authority_host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(authority_host);
    let port = if authority.as_str() == authority_host {
        default_port?
    } else {
        authority.port_u16()?
    };
    (!authority.as_str().contains('@')
        && port != 0
        && (host.parse::<IpAddr>().is_ok() || dns_name(host.strip_suffix('.').unwrap_or(host))))
    .then_some((host, port))
}

impl Scope {
    fn allows_http_port(&self, port: u16, connect: bool) -> bool {
        if connect {
            self.https_ports.contains(&port)
        } else {
            self.http_ports
                .as_ref()
                .map_or(self.allow_all || port == 80, |ports| ports.contains(&port))
        }
    }

    fn allows_host(&self, host: &str) -> bool {
        self.dns_suffixes.is_empty()
            || (host.parse::<IpAddr>().is_err() && {
                let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
                self.dns_suffixes.iter().any(|suffix| {
                    let suffix = suffix.to_ascii_lowercase();
                    host == suffix
                        || host
                            .strip_suffix(&suffix)
                            .is_some_and(|prefix| prefix.ends_with('.'))
                })
            })
    }

    async fn dial(&self, host: &str, port: u16) -> Result<TcpStream, StatusCode> {
        if !(self.allow_all || self.ports.contains(&port) && self.allows_host(host)) {
            return Err(StatusCode::FORBIDDEN);
        }
        let query = if !self.dns_suffixes.is_empty() && !host.ends_with('.') {
            Cow::Owned(format!("{host}."))
        } else {
            Cow::Borrowed(host)
        };
        timeout(Duration::from_secs(5), async {
            let addresses: Vec<_> = resolve(query.into_owned(), port)
                .await
                .map_err(|_| StatusCode::BAD_GATEWAY)?
                .into_iter()
                .filter(|address| {
                    self.allow_all
                        || self
                            .cidrs
                            .iter()
                            .any(|network| network.contains(address.ip()))
                })
                .collect();
            if addresses.is_empty() {
                return Err(StatusCode::FORBIDDEN);
            }
            let socket = TcpStream::connect(addresses.as_slice())
                .await
                .map_err(|_| StatusCode::BAD_GATEWAY)?;
            let _ = socket.set_nodelay(true);
            Ok(socket)
        })
        .await
        .map_err(|_| StatusCode::GATEWAY_TIMEOUT)?
    }
}

/// Resolves a destination on a blocking thread. The caller's timeout cannot
/// stop a lookup that is already running, so the slot is held by the thread
/// itself: a slow resolver then delays further lookups rather than taking
/// the blocking threads that verify approvals.
async fn resolve(host: String, port: u16) -> std::io::Result<Vec<std::net::SocketAddr>> {
    use std::net::ToSocketAddrs;
    static LOOKUPS: Semaphore = Semaphore::const_new(64);
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![(ip, port).into()]);
    }
    let slot = LOOKUPS.acquire().await.map_err(std::io::Error::other)?;
    tokio::task::spawn_blocking(move || {
        let _slot = slot;
        (host.as_str(), port)
            .to_socket_addrs()
            .map(Iterator::collect)
    })
    .await?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unrestricted_scope_dials_an_unlisted_port() {
        let scopes = toml::from_str("[all]\nallow_all = true").unwrap();
        validate_scopes(&scopes).unwrap();
        let scope = &scopes["all"];
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(scope.allows_http_port(port, false));
        assert!(scope.allows_http_port(443, true));
        assert!(!scope.allows_http_port(22, true));
        assert!(scope.dial("127.0.0.1", port).await.is_ok());

        for invalid in [
            "[all]",
            "[all]\nallow_all = true\nports = [80]",
            "[all]\nallow_all = true\nhttps_ports = [0]",
        ] {
            assert!(validate_scopes(&toml::from_str(invalid).unwrap()).is_err());
        }
    }

    #[tokio::test]
    async fn dials_only_addresses_inside_the_scope() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let scope = |cidr: &str| -> Scope {
            toml::from_str(&format!("cidrs = [\"{cidr}\"]\nports = [{port}]")).unwrap()
        };
        let inside = scope("127.0.0.0/8");
        assert!(inside.dial("127.0.0.1", port).await.is_ok());
        assert!(inside.dial("localhost", port).await.is_ok());
        assert_eq!(
            inside.dial("127.0.0.1", port + 1).await.unwrap_err(),
            StatusCode::FORBIDDEN
        );
        // A name is judged by the addresses it resolves to, not by how it is written.
        let outside = scope("10.0.0.0/8");
        for host in ["127.0.0.1", "localhost"] {
            assert_eq!(
                outside.dial(host, port).await.unwrap_err(),
                StatusCode::FORBIDDEN
            );
        }
        assert_eq!(
            resolve("192.0.2.7".into(), 443).await.unwrap(),
            ["192.0.2.7:443".parse().unwrap()]
        );
        assert!(
            resolve("localhost".into(), port)
                .await
                .unwrap()
                .iter()
                .all(|address| address.ip().is_loopback() && address.port() == port)
        );
    }

    #[test]
    fn matches_hosts_and_cidrs_on_boundaries() {
        let scope: Scope = toml::from_str(
            r#"dns_suffixes = ["INTERNAL.example"]
               cidrs = ["10.12.0.0/16", "fd00::/8"]
               ports = [443]"#,
        )
        .unwrap();
        for name in ["internal.example", "DB.internal.example."] {
            assert!(scope.allows_host(name));
        }
        for name in ["evilinternal.example", "internal.example.evil", "10.12.0.1"] {
            assert!(!scope.allows_host(name));
        }
        for ip in ["10.12.255.255", "::ffff:10.12.0.1", "fd12::1"] {
            assert!(
                scope
                    .cidrs
                    .iter()
                    .any(|net| net.contains(ip.parse().unwrap()))
            );
        }
        for ip in ["10.13.0.1", "::ffff:10.13.0.1", "fe80::1"] {
            assert!(
                !scope
                    .cidrs
                    .iter()
                    .any(|net| net.contains(ip.parse().unwrap()))
            );
        }
        for authority in [
            "localhost:abc",
            "localhost:65536",
            "localhost:",
            "localhost..",
            "user@localhost:80",
        ] {
            if let Ok(authority) = authority.parse() {
                assert!(target(&authority, Some(80)).is_none());
            }
        }
        let ipv6 = "[::1]:443".parse().unwrap();
        assert_eq!(target(&ipv6, None), Some(("::1", 443)));
        let http = "localhost".parse().unwrap();
        assert_eq!(target(&http, Some(80)), Some(("localhost", 80)));
        assert!(target(&http, None).is_none());
    }
}

/// Copies both ways with buffers the size of a TLS record. The default 8 KiB
/// splits every record in two on the way through.
async fn copy_both<A, B>(a: &mut A, b: &mut B) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    const RECORD: usize = 16 * 1024;
    copy_bidirectional_with_sizes(a, b, RECORD, RECORD).await
}

#[derive(Clone)]
struct Approval {
    generation: u64,
    allowed: watch::Receiver<u64>,
    deadline: Instant,
}

impl Approval {
    async fn until_revoked<T>(mut self, work: impl Future<Output = T>) -> Option<T> {
        tokio::select! {
            biased;
            _ = self.allowed.wait_for(|allowed| *allowed != self.generation) => None,
            _ = sleep_until(self.deadline) => None,
            result = work => Some(result),
        }
    }
}

pub async fn serve(
    socket: TcpStream,
    tls: TlsAcceptor,
    gateway: Arc<Gateway>,
    handshakes: Arc<Semaphore>,
    allowed: watch::Receiver<u64>,
) {
    let Some(mut stream) = accept_tls(socket, tls, &handshakes).await else {
        return;
    };
    let Some(leaf) = stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|chain| chain.first())
    else {
        return;
    };
    let Ok((generation, scope, lifetime)) = client_grant(leaf) else {
        return;
    };
    let approval = Approval {
        generation,
        allowed,
        deadline: Instant::now() + lifetime,
    };
    if scope == FIXED_TCP_GRANT {
        let Some(upstream) = &gateway.tcp.upstream else {
            return;
        };
        let relay = async {
            if let Ok(Ok(mut upstream)) = timeout(
                Duration::from_secs(5),
                TcpStream::connect(upstream.as_str()),
            )
            .await
            {
                let _ = upstream.set_nodelay(true);
                let _ = copy_both(&mut stream, &mut upstream).await;
            }
        };
        if approval.until_revoked(relay).await.is_none() {
            let _ = timeout(Duration::from_millis(250), stream.shutdown()).await;
        }
        return;
    }
    if gateway.scope_name(scope).is_none() && gateway.tcp_upstream(scope).is_none() {
        return;
    }
    let handler_approval = approval.clone();
    let service = service_fn(move |request| {
        let gateway = gateway.clone();
        let approval = handler_approval.clone();
        async move {
            let result = proxy(request, gateway, scope, approval, true).await;
            Ok::<_, Infallible>(result.unwrap_or_else(IntoResponse::into_response))
        }
    });
    let _ = approval
        .until_revoked(
            http1()
                .serve_connection(TokioIo::new(stream), service)
                .with_upgrades(),
        )
        .await;
}

pub async fn proxy_http(
    request: hyper::Request<Incoming>,
    gateway: Arc<Gateway>,
    app: Arc<App>,
) -> Response<Body> {
    let allowed = app.auth.subscribe_generation();
    let result = async {
        let (scope, generation, lifetime) = approve_forward_http(app, request.headers()).await?;
        let approval = Approval {
            generation,
            allowed,
            deadline: Instant::now() + lifetime,
        };
        approval
            .clone()
            .until_revoked(proxy(request, gateway, scope, approval, false))
            .await
            .unwrap_or(Err(StatusCode::PROXY_AUTHENTICATION_REQUIRED))
    }
    .await;
    let mut response = result.unwrap_or_else(IntoResponse::into_response);
    if response.status() == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
        response.headers_mut().insert(
            header::PROXY_AUTHENTICATE,
            header::HeaderValue::from_static("Shomei"),
        );
    }
    response
}

pub(crate) fn http1() -> hyper::server::conn::http1::Builder {
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(10))
        .max_buf_size(32 * 1024);
    builder
}

pub(crate) fn valid_connect<B>(request: &hyper::Request<B>) -> bool {
    request.uri().scheme().is_none()
        && request.uri().path_and_query().is_none()
        && !request.headers().contains_key(header::UPGRADE)
        && !request.headers().contains_key(header::TRANSFER_ENCODING)
        && request
            .headers()
            .get_all(header::CONTENT_LENGTH)
            .iter()
            .all(|length| length == "0")
}

async fn proxy(
    mut request: hyper::Request<Incoming>,
    gateway: Arc<Gateway>,
    scope: usize,
    approval: Approval,
    tcp_only: bool,
) -> Result<Response<Body>, StatusCode> {
    let connect = request.method() == Method::CONNECT;
    if tcp_only && !connect {
        return Err(StatusCode::METHOD_NOT_ALLOWED);
    }
    let uri = request.uri();
    let authority = uri.authority().ok_or(StatusCode::BAD_REQUEST)?;
    if request.headers().contains_key(header::UPGRADE) {
        return Err(StatusCode::BAD_REQUEST);
    }
    if connect {
        if !valid_connect(&request) {
            return Err(StatusCode::BAD_REQUEST);
        }
    } else if uri.scheme_str() != Some("http") {
        return Err(StatusCode::BAD_REQUEST);
    }
    let (host, port) =
        target(authority, (!connect).then_some(80)).ok_or(StatusCode::BAD_REQUEST)?;
    let destination =
        Endpoint::from_authority(authority, Some(port)).ok_or(StatusCode::BAD_REQUEST)?;
    let tcp_target = gateway.tcp_id(&destination);
    let host = host.to_owned();
    let upstream_host =
        header::HeaderValue::from_str(authority.as_str()).map_err(|_| StatusCode::BAD_REQUEST)?;
    let path = Uri::builder()
        .path_and_query(
            match uri.path_and_query() {
                Some(path) if path.as_str().starts_with('?') => {
                    Cow::Owned(format!("/{}", path.as_str()))
                }
                Some(path) => Cow::Borrowed(path.as_str()),
                None => Cow::Borrowed("/"),
            }
            .as_ref(),
        )
        .build()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    strip_hop_headers(request.headers_mut()).map_err(|_| StatusCode::BAD_REQUEST)?;
    let permit = gateway
        .requests
        .clone()
        .try_acquire_owned()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let mut socket = if tcp_only {
        match (tcp_target, gateway.tcp_upstream(scope)) {
            (Some(id), Some(upstream)) if id == scope => {
                let socket = timeout(
                    Duration::from_secs(5),
                    TcpStream::connect((upstream.host.as_str(), upstream.port)),
                )
                .await
                .map_err(|_| StatusCode::GATEWAY_TIMEOUT)?
                .map_err(|_| StatusCode::BAD_GATEWAY)?;
                let _ = socket.set_nodelay(true);
                socket
            }
            (None, None) => {
                gateway.scopes[gateway.scope_name(scope).ok_or(StatusCode::FORBIDDEN)?]
                    .dial(&host, port)
                    .await?
            }
            _ => return Err(StatusCode::FORBIDDEN),
        }
    } else {
        if tcp_target.is_some() {
            return Err(StatusCode::FORBIDDEN);
        }
        let rules = &gateway.scopes[gateway.scope_name(scope).ok_or(StatusCode::FORBIDDEN)?];
        if !rules.allows_http_port(port, connect) {
            return Err(StatusCode::FORBIDDEN);
        }
        rules.dial(&host, port).await?
    };
    if connect {
        let upgrade = hyper::upgrade::on(&mut request);
        tokio::spawn(approval.until_revoked(async move {
            let _permit = permit;
            if let Ok(stream) = upgrade.await {
                let _ = copy_both(&mut TokioIo::new(stream), &mut socket).await;
            }
        }));
        return Ok(StatusCode::OK.into_response());
    }

    *request.uri_mut() = path;
    *request.version_mut() = Version::HTTP_11;
    request.headers_mut().insert(header::HOST, upstream_host);

    let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
        .max_buf_size(32 * 1024)
        .handshake(TokioIo::new(socket))
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    tokio::spawn(approval.until_revoked(connection));
    let mut response = timeout(
        Duration::from_secs(30),
        sender.send_request(request.map(|body| relay_body(Body::new(body), None))),
    )
    .await
    .map_err(|_| StatusCode::GATEWAY_TIMEOUT)?
    .map_err(|_| StatusCode::BAD_GATEWAY)?;
    if response.status() == StatusCode::SWITCHING_PROTOCOLS {
        return Err(StatusCode::BAD_GATEWAY);
    }
    strip_hop_headers(response.headers_mut()).map_err(|_| StatusCode::BAD_GATEWAY)?;
    Ok(response.map(|body| relay_body(Body::new(body), Some(permit))))
}
