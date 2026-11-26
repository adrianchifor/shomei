use std::{fs, net::IpAddr, os::unix::fs::FileTypeExt, path::PathBuf, time::Duration};

use anyhow::{Context, Result, ensure};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    Request, StatusCode, Uri,
    body::Bytes,
    header::{AUTHORIZATION, CONNECTION, CONTENT_TYPE, HOST, HeaderValue},
};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo, TokioTimer},
};
use serde::Deserialize;
use serde_json::json;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::{
    net::UnixStream,
    sync::{Mutex, Semaphore},
    time::{Instant, timeout},
};
use url::form_urlencoded;
use zeroize::Zeroizing;

use crate::config::{TailscaleSshConfig, is_tailnet_ip};

const RESPONSE_LIMIT: usize = 32 * 1024;
const SCOPE: &str = "devices:posture_attributes";
// Each Tailscale API step is bounded so that WhoIs (2 s), assertion
// verification, the token fetch and the posture call end well inside the
// 10 s authentication handler budget.
const API_TIMEOUT: Duration = Duration::from_secs(3);

pub struct TailscaleSsh {
    pub target: Option<String>,
    pub requests: Semaphore,
    gateway: Option<IpAddr>,
    posture_attribute: String,
    ttl_seconds: u64,
    socket: PathBuf,
    api_origin: Uri,
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
    oauth_id: String,
    oauth_secret: Zeroizing<String>,
    token: Mutex<Option<CachedToken>>,
    api_timeout: Duration,
}

struct CachedToken {
    authorization: HeaderValue,
    refresh_at: Instant,
}

#[derive(Deserialize)]
struct Token {
    access_token: String,
    expires_in: u64,
}

#[derive(PartialEq, Eq)]
pub struct Device {
    id: String,
    owner: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct WhoIs {
    node: Node,
    user_profile: UserProfile,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Node {
    #[serde(rename = "StableID")]
    stable_id: String,
    user: u64,
    addresses: Vec<String>,
    tags: Option<Vec<String>>,
    #[serde(default)]
    sharer: u64,
    #[serde(default)]
    expired: bool,
}

#[derive(Deserialize)]
struct UserProfile {
    #[serde(rename = "ID")]
    id: u64,
}

impl TailscaleSsh {
    pub fn new(
        config: TailscaleSshConfig,
        gateway: Option<IpAddr>,
        workers: usize,
    ) -> Result<Self> {
        ensure!(
            fs::metadata(&config.socket)
                .context("inspect tailscaled LocalAPI socket")?
                .file_type()
                .is_socket(),
            "Tailscale LocalAPI path must be a Unix socket"
        );
        let secret = Zeroizing::new(
            fs::read_to_string(config.oauth_client_secret_file)
                .context("read Tailscale OAuth client secret file")?,
        );
        ensure!(
            !secret.trim().is_empty() && !config.oauth_client_id.trim().is_empty(),
            "missing Tailscale OAuth credentials"
        );
        let mut transport = HttpConnector::new();
        transport.enforce_http(false);
        transport.set_connect_timeout(Some(Duration::from_secs(3)));
        let connector = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_only()
            .enable_http1()
            .wrap_connector(transport);
        let client = Client::builder(TokioExecutor::new())
            .pool_timer(TokioTimer::new())
            .pool_idle_timeout(Duration::from_secs(30))
            .http1_max_buf_size(RESPONSE_LIMIT)
            .build(connector);
        Ok(Self {
            target: config.target,
            requests: Semaphore::new(workers),
            gateway,
            posture_attribute: config.posture_attribute,
            ttl_seconds: config.ttl_seconds,
            socket: config.socket,
            api_origin: Uri::from_static("https://api.tailscale.com"),
            client,
            oauth_id: config.oauth_client_id,
            oauth_secret: secret,
            token: Mutex::new(None),
            api_timeout: API_TIMEOUT,
        })
    }

    /// Rejects peers outside the tailnet and, when forwarding is enabled, the
    /// gateway itself, which a forward user could reach through the proxy.
    pub fn accepts_peer(&self, peer: IpAddr) -> bool {
        is_tailnet_ip(peer)
            && self
                .gateway
                .is_none_or(|gateway| peer.to_canonical() != gateway.to_canonical())
    }

    pub async fn device(&self, peer: IpAddr) -> Result<Option<Device>> {
        if !self.accepts_peer(peer) {
            return Ok(None);
        }
        let response = timeout(Duration::from_secs(2), async {
            let socket = UnixStream::connect(&self.socket).await?;
            let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
                .max_buf_size(RESPONSE_LIMIT)
                .handshake(TokioIo::new(socket))
                .await?;
            let query = form_urlencoded::Serializer::new(String::new())
                .append_pair("addr", &peer.to_string())
                .finish();
            let request = Request::get(format!("/localapi/v0/whois?{query}"))
                .header(HOST, "local-tailscaled.sock")
                .header(CONNECTION, "close")
                .body(Full::<Bytes>::default())?;
            let (_, response) = tokio::try_join!(async { Ok(connection.await?) }, async {
                let response = sender.send_request(request).await?;
                match response.status() {
                    StatusCode::NOT_FOUND => Ok(None),
                    StatusCode::OK => Ok(Some(read_json::<WhoIs>(response).await?)),
                    status => anyhow::bail!("tailscaled WhoIs returned {status}"),
                }
            })?;
            Ok::<_, anyhow::Error>(response)
        })
        .await
        .context("tailscaled WhoIs timed out")??;
        Ok(response.and_then(|response| response.device(peer)))
    }

    /// Fails with a `tokio::time::error::Elapsed` error after `api_timeout`,
    /// including time spent waiting for another refresh. Dropping the
    /// future releases the lock and leaves the cache unchanged.
    pub async fn authorization(&self) -> Result<HeaderValue> {
        timeout(self.api_timeout, self.refresh_authorization()).await?
    }

    async fn refresh_authorization(&self) -> Result<HeaderValue> {
        let mut cache = self.token.lock().await;
        if let Some(token) = cache
            .as_ref()
            .filter(|token| token.refresh_at > Instant::now())
        {
            return Ok(token.authorization.clone());
        }
        let body = form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "client_credentials")
            .append_pair("client_id", &self.oauth_id)
            .append_pair("client_secret", self.oauth_secret.trim())
            .append_pair("scope", SCOPE)
            .finish();
        let requested_at = Instant::now();
        let request = Request::post(self.uri("/api/v2/oauth/token")?)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Full::new(Bytes::from(body)))?;
        let response = self.client.request(request).await?;
        ensure!(
            response.status().is_success(),
            "Tailscale OAuth returned {}",
            response.status()
        );
        let Token {
            access_token,
            expires_in,
        } = read_json(response).await?;
        ensure!(
            !access_token.is_empty() && expires_in > 0,
            "invalid Tailscale OAuth token"
        );
        let access_token = Zeroizing::new(access_token);
        let mut authorization = HeaderValue::from_str(&format!("Bearer {}", *access_token))?;
        authorization.set_sensitive(true);
        *cache = Some(CachedToken {
            authorization: authorization.clone(),
            refresh_at: requested_at + Duration::from_secs(expires_in.min(3600).saturating_sub(60)),
        });
        Ok(authorization)
    }

    /// Fails with a `tokio::time::error::Elapsed` error after `api_timeout`,
    /// when the attribute may or may not have been set.
    pub async fn approve(&self, device: &Device, authorization: HeaderValue) -> Result<u64> {
        timeout(self.api_timeout, self.set_attribute(device, authorization)).await?
    }

    async fn set_attribute(&self, device: &Device, authorization: HeaderValue) -> Result<u64> {
        let expiry = OffsetDateTime::now_utc() + time::Duration::seconds(self.ttl_seconds as i64);
        let body = json!({ "value": true, "expiry": expiry.format(&Rfc3339)? });
        let path = format!(
            "/api/v2/device/{}/attributes/{}",
            device.id, self.posture_attribute
        );
        let request = Request::post(self.uri(&path)?)
            .header(AUTHORIZATION, authorization.clone())
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(serde_json::to_vec(&body)?)))?;
        let response = self.client.request(request).await?;
        if response.status() == StatusCode::UNAUTHORIZED {
            let mut cache = self.token.lock().await;
            if cache
                .as_ref()
                .is_some_and(|token| token.authorization == authorization)
            {
                *cache = None;
            }
        }
        ensure!(
            response.status().is_success(),
            "Tailscale posture API returned {}",
            response.status()
        );
        u64::try_from(expiry.unix_timestamp()).context("invalid Tailscale approval expiry")
    }

    fn uri(&self, path: &str) -> Result<Uri> {
        let mut parts = self.api_origin.clone().into_parts();
        parts.path_and_query = Some(path.parse()?);
        Ok(Uri::from_parts(parts)?)
    }

    #[cfg(test)]
    pub(crate) fn use_test_api(&mut self, origin: Uri) {
        self.api_origin = origin;
        self.client = Client::builder(TokioExecutor::new()).build(
            HttpsConnectorBuilder::new()
                .with_webpki_roots()
                .https_or_http()
                .enable_http1()
                .build(),
        );
    }

    #[cfg(test)]
    pub(crate) fn set_api_timeout(&mut self, api_timeout: Duration) {
        self.api_timeout = api_timeout;
    }
}

impl WhoIs {
    fn device(self, peer: IpAddr) -> Option<Device> {
        let node = self.node;
        let host_mask = if peer.is_ipv4() { "/32" } else { "/128" };
        let owns_address = node.addresses.iter().any(|prefix| {
            prefix
                .strip_suffix(host_mask)
                .and_then(|address| address.parse::<IpAddr>().ok())
                == Some(peer)
        });
        (owns_address
            && !node.expired
            && node.sharer == 0
            && node.tags.is_none_or(|tags| tags.is_empty())
            && node.user != 0
            && node.user == self.user_profile.id
            && (1..=128).contains(&node.stable_id.len())
            && node
                .stable_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')))
        .then_some(Device {
            id: node.stable_id,
            owner: node.user,
        })
    }
}

async fn read_json<T: serde::de::DeserializeOwned>(
    response: hyper::Response<hyper::body::Incoming>,
) -> Result<T> {
    let body = Limited::new(response.into_body(), RESPONSE_LIMIT)
        .collect()
        .await
        .map_err(|_| anyhow::anyhow!("read bounded Tailscale response"))?;
    serde_json::from_slice(&body.to_bytes())
        .map_err(|_| anyhow::anyhow!("invalid Tailscale response"))
}
