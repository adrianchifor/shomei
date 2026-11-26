use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::Write,
    net::SocketAddr,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use clap::Args;
use http_body_util::Empty;
use hyper::{Method, Request, Uri, body::Bytes, header::HOST, http::uri::Authority};
use hyper_util::rt::TokioIo;
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject},
};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncWrite, copy_bidirectional},
    net::TcpStream,
    time::{Instant, sleep_until, timeout},
};
use tokio_rustls::TlsConnector;
use url::Url;
use zeroize::Zeroizing;

use super::{
    Access, Gateway, https_origin, sign_origin, ssh::endpoint_port, tls_client, trust_roots,
};

#[derive(Args)]
pub(super) struct MtlsArgs {
    /// Forward proxy scope. The gateway selects it automatically when there is only one.
    #[arg(long)]
    scope: Option<String>,
    /// New directory for the certificate and private key.
    #[arg(long)]
    out: PathBuf,
    #[command(flatten)]
    access: Access,
}

#[derive(Args)]
pub(super) struct ConnectArgs {
    /// Local loopback address for plain TCP clients. Use port 0 to pick a free port.
    #[arg(long, default_value = "127.0.0.1:0")]
    listen: SocketAddr,
    /// Destination through the forward proxy, in HOST:PORT form.
    #[arg(value_parser = destination)]
    target: Authority,
    #[command(flatten)]
    forward: CredentialsArgs,
    #[command(flatten)]
    access: Access,
}

#[derive(Args, Default)]
pub(super) struct CredentialsArgs {
    /// Approve a new certificate for this scope. Optional when the gateway has one scope.
    #[arg(long, conflicts_with = "credentials")]
    scope: Option<String>,
    /// Reuse a certificate directory created by shomei mtls.
    #[arg(long)]
    credentials: Option<PathBuf>,
}

#[derive(Deserialize)]
struct Certificate {
    certificate_pem: String,
    expires_at: u64,
    forward_endpoint: Option<String>,
    tcp_endpoint: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct CredentialMetadata {
    origin: Url,
    endpoint: String,
    expires_at: u64,
    #[serde(default)]
    direct: bool,
}

struct Credentials {
    metadata: CredentialMetadata,
    certificate: String,
    key: Zeroizing<String>,
}

impl Credentials {
    async fn approve(
        origin: Url,
        roots: RootCertStore,
        scope: Option<&str>,
        target: Option<&Authority>,
    ) -> Result<Self> {
        let gateway = Gateway::new(origin.clone(), roots)?;
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let csr = CertificateParams::default()
            .serialize_request(&key)?
            .pem()?;
        let signed = if let Some(target) = target {
            gateway
                .sign_challenge(
                    "start",
                    &serde_json::json!({
                        "tcp_destination": target.as_str(),
                        "client_csr_pem": csr,
                        "forward_scope": scope,
                    }),
                    &format!("a TCP certificate for {target}, or for its whole forward scope"),
                )
                .await?
        } else {
            gateway.sign_forward(scope, Some(&csr)).await?
        };
        let grant: Certificate = gateway.post("finish", &signed).await?;
        let (endpoint, direct) = match (grant.forward_endpoint, grant.tcp_endpoint) {
            (Some(endpoint), None) => (endpoint, false),
            (None, Some(endpoint)) if target.is_some() => (endpoint, true),
            _ => anyhow::bail!("gateway returned an invalid TCP approval"),
        };
        let metadata = CredentialMetadata {
            origin,
            endpoint,
            expires_at: grant.expires_at,
            direct,
        };
        Ok(Self {
            metadata,
            certificate: grant.certificate_pem,
            key: Zeroizing::new(key.serialize_pem()),
        })
    }

    fn read(dir: &Path) -> Result<Self> {
        let key_file =
            fs::File::open(dir.join("client-key.pem")).context("open the forward proxy key")?;
        let metadata = key_file.metadata()?;
        ensure!(
            metadata.is_file() && metadata.mode() & 0o077 == 0,
            "the forward proxy key must be a private file"
        );
        let mut key = Zeroizing::new(String::new());
        use std::io::Read;
        key_file.take(32 * 1024).read_to_string(&mut key)?;
        Ok(Self {
            metadata: serde_json::from_slice(&fs::read(dir.join("proxy.json"))?)?,
            certificate: fs::read_to_string(dir.join("client.pem"))?,
            key,
        })
    }

    fn write(&self, dir: &Path) -> Result<()> {
        DirBuilder::new()
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("create a new credential directory at {}", dir.display()))?;
        let result = (|| {
            for (file, contents) in [
                ("client-key.pem", self.key.as_bytes()),
                ("client.pem", self.certificate.as_bytes()),
                ("proxy.json", &serde_json::to_vec(&self.metadata)?),
            ] {
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(dir.join(file))?
                    .write_all(contents)?;
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(dir);
        }
        result
    }

    fn endpoint(&self) -> Result<(&str, u16, Duration)> {
        let host = self
            .metadata
            .origin
            .domain()
            .context("missing forward gateway hostname")?;
        let port = endpoint_port(&self.metadata.endpoint, host, None)?;
        let lifetime = self
            .metadata
            .expires_at
            .saturating_sub(crate::tls::unix_seconds()?);
        ensure!(
            (1..=if self.metadata.direct { 86_400 } else { 3600 }).contains(&lifetime),
            "the forward proxy certificate is expired or has an invalid lifetime"
        );
        Ok((host, port, Duration::from_secs(lifetime)))
    }
}

pub(super) fn destination(value: &str) -> Result<Authority> {
    let authority: Authority = value
        .parse()
        .context("expected a destination in HOST:PORT form")?;
    crate::forward::target(&authority, None)
        .context("expected a valid destination in HOST:PORT form")?;
    Ok(authority)
}

impl CredentialsArgs {
    pub(super) fn enabled(&self) -> bool {
        self.scope.is_some() || self.credentials.is_some()
    }

    pub(super) async fn tunnel(self, access: Access, target: &Authority) -> Result<Tunnel> {
        if let Some(dir) = self.credentials {
            let credentials = Credentials::read(&dir)
                .with_context(|| format!("read credentials from {}", dir.display()))?;
            let origin = https_origin(credentials.metadata.origin.as_str())?;
            ensure!(
                access.proxy.is_none_or(|proxy| proxy == origin),
                "the credentials are for a different gateway"
            );
            let origin = sign_origin(Some(origin), access.identity)?;
            let roots = trust_roots(&origin, access.ca_file.as_deref())?;
            return Tunnel::new(credentials, roots);
        }
        let origin = sign_origin(access.proxy, access.identity)?;
        let roots = trust_roots(&origin, access.ca_file.as_deref())?;
        let credentials =
            Credentials::approve(origin, roots.clone(), self.scope.as_deref(), Some(target))
                .await?;
        Tunnel::new(credentials, roots)
    }
}

pub(super) async fn export(args: MtlsArgs) -> Result<()> {
    ensure!(
        !args.out.try_exists()?,
        "credential output directory already exists"
    );
    let origin = sign_origin(args.access.proxy, args.access.identity)?;
    let roots = trust_roots(&origin, args.access.ca_file.as_deref())?;
    let credentials = Credentials::approve(origin, roots, args.scope.as_deref(), None).await?;
    let (_, _, lifetime) = credentials.endpoint()?;
    credentials.write(&args.out)?;
    eprintln!(
        "Saved forward proxy credentials to {} for https://{} (expires in {}s).",
        args.out.display(),
        credentials.metadata.endpoint,
        lifetime.as_secs()
    );
    Ok(())
}

#[derive(Clone)]
pub(super) struct Tunnel {
    tls: TlsConnector,
    host: Arc<str>,
    port: u16,
    deadline: Instant,
    direct: bool,
}

pub(super) trait TunnelStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> TunnelStream for T {}

impl Tunnel {
    fn new(credentials: Credentials, roots: RootCertStore) -> Result<Self> {
        let (host, port, lifetime) = credentials.endpoint()?;
        let certificate = CertificateDer::from_pem_slice(credentials.certificate.as_bytes())?;
        let key = PrivateKeyDer::from_pem_slice(credentials.key.as_bytes())?;
        let tls = tls_client(roots)?.with_client_auth_cert(vec![certificate], key)?;
        Ok(Self {
            tls: TlsConnector::from(Arc::new(tls)),
            host: host.into(),
            port,
            deadline: Instant::now() + lifetime,
            direct: credentials.metadata.direct,
        })
    }

    pub(super) async fn open(&self, target: Authority) -> Result<Box<dyn TunnelStream>> {
        ensure!(
            Instant::now() < self.deadline,
            "the forward proxy certificate has expired"
        );
        timeout(Duration::from_secs(12), async {
            let socket = TcpStream::connect((self.host.as_ref(), self.port))
                .await
                .context("connect to the forward proxy")?;
            socket.set_nodelay(true)?;
            let tls = self
                .tls
                .connect(ServerName::try_from(self.host.to_string())?, socket)
                .await
                .context("authenticate the forward proxy with mTLS")?;
            if self.direct {
                return Ok(Box::new(tls) as Box<dyn TunnelStream>);
            }
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
            tokio::spawn(connection.with_upgrades());
            let response = sender
                .send_request(
                    Request::builder()
                        .method(Method::CONNECT)
                        .header(HOST, target.as_str())
                        .uri(Uri::builder().authority(target).build()?)
                        .body(Empty::<Bytes>::new())?,
                )
                .await
                .context("open forward proxy tunnel")?;
            ensure!(
                response.status().is_success(),
                "forward proxy returned {}",
                response.status()
            );
            Ok(Box::new(TokioIo::new(hyper::upgrade::on(response).await?))
                as Box<dyn TunnelStream>)
        })
        .await
        .context("forward proxy connection timed out")?
    }
}

pub(super) async fn connect(args: ConnectArgs) -> Result<()> {
    ensure!(
        args.listen.ip().is_loopback(),
        "the TCP bridge must listen on a loopback address"
    );
    let listener = crate::listen(args.listen).context("bind the local TCP bridge")?;
    let tunnel = args.forward.tunnel(args.access, &args.target).await?;
    let deadline = tunnel.deadline;
    println!("{}", listener.local_addr()?);
    std::io::stdout().flush()?;
    tokio::select! {
        result = crate::serve(listener, 4096, move |mut socket, _| {
            let tunnel = tunnel.clone();
            let target = args.target.clone();
            async move {
                let result = async {
                    let _ = socket.set_nodelay(true);
                    let mut stream = tunnel.open(target).await?;
                    copy_bidirectional(&mut socket, &mut stream).await?;
                    Ok::<_, anyhow::Error>(())
                }.await;
                if let Err(error) = result {
                    eprintln!("{error:#}");
                }
            }
        }) => result?,
        _ = sleep_until(deadline) => {},
        result = tokio::signal::ctrl_c() => result?,
    }
    Ok(())
}

#[cfg(test)]
mod tests;
