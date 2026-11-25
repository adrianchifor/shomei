use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub origin: Url,
    #[serde(default = "https_bind")]
    pub https_bind: SocketAddr,
    pub tls_cert: PathBuf,
    pub tls_key: PathBuf,
    pub state_dir: PathBuf,
    pub identities_file: PathBuf,
    pub http_upstream: Option<Url>,
    pub browser_action: Option<BrowserAction>,
    #[serde(default = "session_ttl")]
    pub session_ttl_seconds: u64,
    pub tcp: Option<TcpConfig>,
    #[serde(default)]
    pub limits: Limits,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserAction {
    pub path: String,
    pub label: String,
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub https_connections: usize,
    pub tcp_connections: usize,
    pub tls_handshakes: usize,
    pub http_requests: usize,
    pub auth_workers: usize,
    pub pending_challenges: usize,
    pub pending_per_ip: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            https_connections: 4096,
            tcp_connections: 4096,
            tls_handshakes: 512,
            http_requests: 8192,
            auth_workers: 32,
            pending_challenges: 8192,
            pending_per_ip: 128,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcpConfig {
    #[serde(default = "tcp_bind")]
    pub bind: SocketAddr,
    pub upstream: String,
    pub ssh_host: Option<String>,
    pub public_port: Option<u16>,
    #[serde(default = "tcp_ttl")]
    pub cert_ttl_seconds: u64,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path).context("read config")?;
        let config: Self = toml::from_str(&contents).context("parse config")?;
        validate_origin(&config.origin)?;
        ensure!(
            config.http_upstream.is_some() || config.tcp.is_some(),
            "configure an upstream"
        );
        ensure!(
            (1..=3600).contains(&config.session_ttl_seconds),
            "session TTL must be 1 to 3600 seconds"
        );
        let limits = &config.limits;
        ensure!(
            [
                limits.https_connections,
                limits.tcp_connections,
                limits.tls_handshakes,
                limits.http_requests,
                limits.pending_challenges,
                limits.pending_per_ip
            ]
            .into_iter()
            .all(|limit| (1..=65_536).contains(&limit))
                && (1..=128).contains(&limits.auth_workers)
                && limits.pending_per_ip <= limits.pending_challenges,
            "invalid capacity limits"
        );
        if let Some(upstream) = &config.http_upstream {
            ensure!(
                matches!(upstream.scheme(), "http" | "https")
                    && upstream.host().is_some()
                    && upstream.username().is_empty()
                    && upstream.password().is_none()
                    && upstream.path() == "/"
                    && upstream.query().is_none()
                    && upstream.fragment().is_none(),
                "HTTP upstream must be an HTTP or HTTPS origin"
            );
        }
        if let Some(action) = &config.browser_action {
            ensure!(
                config.http_upstream.is_some(),
                "browser action requires an HTTP upstream"
            );
            ensure!(
                action.path.starts_with('/')
                    && !action.path.starts_with("/_shomei")
                    && action.path.len() <= 1024
                    && action.path.bytes().all(|byte| byte.is_ascii_alphanumeric()
                        || matches!(byte, b'/' | b'.' | b'-' | b'_'))
                    && action.path[1..]
                        .split('/')
                        .all(|segment| !matches!(segment, "" | "." | "..")),
                "browser action requires an unambiguous upstream path"
            );
            ensure!(
                !action.label.trim().is_empty() && action.label.len() <= 120,
                "invalid browser action label"
            );
        }
        if let Some(tcp) = &config.tcp {
            let endpoint: axum::http::uri::Authority =
                tcp.upstream.parse().context("parse TCP upstream")?;
            ensure!(
                !endpoint.host().is_empty()
                    && !endpoint.as_str().contains('@')
                    && endpoint.port_u16().is_some_and(|port| port != 0),
                "TCP upstream must have a host and port"
            );
            ensure!(
                (1..=86_400).contains(&tcp.cert_ttl_seconds),
                "TCP certificate TTL must be 1 to 86400 seconds"
            );
            ensure!(
                tcp.public_port.unwrap_or(tcp.bind.port()) != 0,
                "TCP public port must be nonzero"
            );
            if let Some(host) = &tcp.ssh_host {
                ensure!(
                    host.parse::<std::net::IpAddr>().is_ok()
                        || (!host.is_empty()
                            && host.len() <= 253
                            && !host.starts_with('-')
                            && host.bytes().all(|byte| byte.is_ascii_alphanumeric()
                                || matches!(byte, b'.' | b'-' | b'_'))),
                    "invalid TCP SSH host alias"
                );
            }
        }
        Ok(config)
    }
}

pub fn validate_origin(origin: &Url) -> Result<()> {
    ensure!(
        origin.scheme() == "https"
            && origin.domain().is_some()
            && origin.username().is_empty()
            && origin.password().is_none()
            && origin.path() == "/"
            && origin.query().is_none()
            && origin.fragment().is_none(),
        "origin must be an HTTPS origin with a DNS name"
    );
    Ok(())
}

fn https_bind() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 8443))
}

fn tcp_bind() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 9443))
}

fn session_ttl() -> u64 {
    600
}

fn tcp_ttl() -> u64 {
    300
}
