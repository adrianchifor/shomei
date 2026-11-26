mod forward;
mod hardware;
mod ssh;

use std::{
    env, fs,
    io::{self, BufRead, BufReader, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Args, Parser, Subcommand};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, Uri, body::Bytes, header::CONTENT_TYPE};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioTimer},
};
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, pem::PemObject},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::time::timeout;
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{PublicKeyCredential, RequestChallengeResponse};

use crate::auth::{ACCOUNT, StaticIdentity, encode_identity, prepare_identity};

#[derive(Parser)]
#[command(
    version,
    about = "YubiKey authentication proxy",
    args_conflicts_with_subcommands = true
)]
struct Arguments {
    #[command(subcommand)]
    command: Option<Command>,
    #[arg(value_name = "CONFIG")]
    config: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Start the authentication proxy.
    Serve {
        #[arg(value_name = "CONFIG")]
        config: Option<PathBuf>,
    },
    /// Create a credential on a USB YubiKey and save its public identity.
    Init(InitArgs),
    /// Print the saved public identity as a compact allowlist token.
    GetId(GetIdArgs),
    /// Delete the local public identity after confirmation.
    Clear(IdentityFile),
    /// Approve HTTP access and print an assertion or forward session.
    Sign(SignArgs),
    /// Export a reusable, short-lived mTLS credential for TCP forwarding.
    Mtls(forward::MtlsArgs),
    /// Open a local TCP bridge through the forward proxy.
    Connect(forward::ConnectArgs),
    /// Connect to an allowlisted SSH host after YubiKey approval.
    Ssh(ssh::SshArgs),
    #[command(hide = true)]
    SshStdio { socket: PathBuf },
}

#[derive(Args)]
struct IdentityFile {
    /// Local public identity file. Defaults to ~/.shomei/identity.json.
    #[arg(long)]
    identity_file: Option<PathBuf>,
}

#[derive(Args)]
struct GetIdArgs {
    /// Print the public identity as JSON for legacy allowlists.
    #[arg(long)]
    json: bool,
    #[command(flatten)]
    identity: IdentityFile,
}

impl IdentityFile {
    fn resolve(self) -> Result<PathBuf> {
        if let Some(path) = self.identity_file {
            return Ok(path);
        }
        let home = home_directory();
        let config = env::var_os("XDG_CONFIG_HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);
        default_identity_path(home.as_deref(), config.as_deref())
    }
}

fn home_directory() -> Option<PathBuf> {
    env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn default_identity_path(home: Option<&Path>, config: Option<&Path>) -> Result<PathBuf> {
    let path = home.map(|home| home.join(".shomei/identity.json"));
    if let Some(path) = &path
        && path.try_exists()?
    {
        return Ok(path.clone());
    }
    let legacy = config
        .map(|config| config.join("shomei/identity.json"))
        .or_else(|| home.map(|home| home.join(".config/shomei/identity.json")));
    if let Some(legacy) = legacy
        && legacy.try_exists()?
    {
        return Ok(legacy);
    }
    path.context("set --identity-file when the home directory is unavailable")
}

#[derive(Args)]
struct InitArgs {
    /// The gateway HTTPS origin, including its port if nonstandard.
    #[arg(long, env = "SHOMEI_PROXY", default_value = "https://localhost:8443", value_parser = https_origin)]
    proxy: Url,
    /// Set a FIDO2 PIN on a YubiKey that has never had one.
    #[arg(long)]
    set_pin: bool,
    /// Create an attested YubiKey 4 credential for a localhost demo.
    #[arg(long, conflicts_with = "set_pin")]
    u2f: bool,
    #[command(flatten)]
    identity: IdentityFile,
}

#[derive(Args)]
struct Access {
    /// The gateway HTTPS origin. Defaults to the origin in the local identity.
    #[arg(long, env = "SHOMEI_PROXY", value_parser = https_origin)]
    proxy: Option<Url>,
    /// PEM trust roots. Localhost can use ~/.shomei/localhost-ca.pem.
    #[arg(long, env = "SHOMEI_CA_FILE")]
    ca_file: Option<PathBuf>,
    #[command(flatten)]
    identity: IdentityFile,
}

#[derive(Args)]
struct SignArgs {
    /// Approve a request through the HTTP forward proxy.
    #[arg(long)]
    forward: bool,
    /// Authorize HTTP forwarding within this configured scope.
    #[arg(long)]
    scope: Option<String>,
    /// Exchange the assertion for a reusable HTTP forward session.
    #[arg(long)]
    session: bool,
    #[command(flatten)]
    access: Access,
}

pub async fn run() -> Result<Option<PathBuf>> {
    let args = Arguments::parse();
    match args.command {
        None => return Ok(Some(config_path(args.config))),
        Some(Command::Serve { config }) => return Ok(Some(config_path(config))),
        Some(Command::Init(args)) => init(args).await?,
        Some(Command::GetId(args)) => get_id(args)?,
        Some(Command::Clear(args)) => {
            clear_identity(&args.resolve()?, io::stdin().lock(), io::stderr().lock())?;
        }
        Some(Command::Sign(args)) => {
            let origin = sign_origin(args.access.proxy, args.access.identity)?;
            let roots = trust_roots(&origin, args.access.ca_file.as_deref())?;
            let gateway = Gateway::new(origin, roots)?;
            let signed = if args.forward || args.session || args.scope.is_some() {
                gateway.sign_forward(args.scope.as_deref(), None).await?
            } else {
                gateway.sign(None).await?
            };
            if args.session {
                #[derive(Deserialize)]
                struct ForwardSession {
                    proxy_session: String,
                }
                let session: ForwardSession = gateway.post("finish", &signed).await?;
                println!("{}", session.proxy_session);
            } else {
                println!("{}", URL_SAFE_NO_PAD.encode(serde_json::to_vec(&signed)?));
            }
        }
        Some(Command::Ssh(args)) => ssh::run(args).await?,
        Some(Command::Mtls(args)) => forward::export(args).await?,
        Some(Command::Connect(args)) => forward::connect(args).await?,
        Some(Command::SshStdio { socket }) => ssh::stdio(&socket)?,
    }
    Ok(None)
}

fn config_path(config: Option<PathBuf>) -> PathBuf {
    config.unwrap_or_else(|| "shomei.toml".into())
}

fn https_origin(value: &str) -> Result<Url> {
    let url = Url::parse(value).context("parse HTTPS origin")?;
    crate::config::validate_origin(&url)?;
    ensure!(
        url.port() != Some(0),
        "the HTTPS gateway port must be nonzero"
    );
    Ok(url)
}

async fn init(args: InitArgs) -> Result<()> {
    let path = args.identity.resolve()?;
    ensure!(
        !path.try_exists()?,
        "identity already exists at {}. Run shomei get-id or choose another --identity-file",
        path.display()
    );
    let dir = path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(dir).context("create the local identity directory")?;
    let (options, setup) = prepare_identity(&args.proxy, args.u2f)?;
    eprintln!(
        "Creating a YubiKey identity for {ACCOUNT} at {}.",
        args.proxy.origin().ascii_serialization()
    );
    let registration = hardware::register(args.proxy, options, args.set_pin, args.u2f).await?;
    let identity = setup.finish(registration)?;
    let mut file = tempfile::NamedTempFile::new_in(dir)?;
    serde_json::to_writer(file.as_file_mut(), &identity)?;
    writeln!(file)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(&path)
        .with_context(|| format!("save identity to {}", path.display()))?;
    eprintln!(
        "Saved public identity to {}. Run shomei get-id to export it.",
        path.display()
    );
    Ok(())
}

fn get_id(args: GetIdArgs) -> Result<()> {
    let identity = read_identity(args.identity)?;
    let output = if args.json {
        serde_json::to_string(&identity)?
    } else {
        encode_identity(&identity)?
    };
    println!("{output}");
    Ok(())
}

fn clear_identity(path: &Path, mut input: impl BufRead, mut output: impl Write) -> Result<()> {
    let original = fs::symlink_metadata(path)
        .with_context(|| format!("locate identity at {}", path.display()))?;
    ensure!(
        original.is_file() || original.is_symlink(),
        "identity path must point to a file"
    );
    write!(
        output,
        "Delete the local identity at {}? [y/N] ",
        path.display()
    )?;
    output.flush()?;
    let mut answer = String::new();
    input.read_line(&mut answer).context("read confirmation")?;
    let answer = answer.trim();
    if !answer.eq_ignore_ascii_case("y") && !answer.eq_ignore_ascii_case("yes") {
        writeln!(output, "Kept the local identity.")?;
        return Ok(());
    }
    let current = fs::symlink_metadata(path)
        .with_context(|| format!("locate identity at {}", path.display()))?;
    ensure!(
        (original.dev(), original.ino()) == (current.dev(), current.ino()),
        "the identity changed during confirmation. Run shomei clear again"
    );
    fs::remove_file(path).with_context(|| format!("remove identity at {}", path.display()))?;
    writeln!(output, "Deleted the local identity.")?;
    Ok(())
}

fn read_identity(args: IdentityFile) -> Result<StaticIdentity> {
    let path = args.resolve()?;
    let file = fs::File::open(&path).with_context(|| format!("open {}", path.display()))?;
    let identity: StaticIdentity =
        serde_json::from_reader(BufReader::new(file)).context("read public identity")?;
    identity.verify()?;
    Ok(identity)
}

fn sign_origin(proxy: Option<Url>, args: IdentityFile) -> Result<Url> {
    if args.identity_file.is_none()
        && let Some(proxy) = proxy
    {
        return Ok(proxy);
    }
    let identity = read_identity(args)
        .context("load the local identity to select a proxy. Run shomei init or pass --proxy")?;
    ensure!(
        proxy.is_none_or(|proxy| proxy == identity.origin),
        "proxy URL does not match the selected identity"
    );
    Ok(identity.origin)
}

fn localhost_ca(origin: &Url, home: Option<&Path>) -> Result<Option<PathBuf>> {
    let Some(home) = home.filter(|_| origin.domain() == Some("localhost")) else {
        return Ok(None);
    };
    let path = home.join(".shomei/localhost-ca.pem");
    Ok(path.try_exists()?.then_some(path))
}

fn trust_roots(origin: &Url, path: Option<&Path>) -> Result<RootCertStore> {
    let local = if path.is_none() {
        localhost_ca(origin, home_directory().as_deref())?
    } else {
        None
    };
    let Some(path) = path.or(local.as_deref()) else {
        return Ok(RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        });
    };
    let mut store = RootCertStore::empty();
    for certificate in CertificateDer::pem_file_iter(path)
        .with_context(|| format!("open gateway CA file {}", path.display()))?
    {
        store
            .add(certificate?)
            .context("invalid gateway trust root")?;
    }
    ensure!(
        !store.is_empty(),
        "gateway CA file contains no certificates"
    );
    Ok(store)
}

fn tls_client(
    roots: RootCertStore,
) -> Result<rustls::ConfigBuilder<ClientConfig, rustls::client::WantsClientCert>> {
    Ok(
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots),
    )
}

struct Gateway {
    origin: Url,
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
}

#[derive(Deserialize)]
struct Started {
    challenge_id: Uuid,
    #[serde(flatten)]
    options: RequestChallengeResponse,
}

#[derive(Serialize)]
struct Signed {
    challenge_id: Uuid,
    credential: PublicKeyCredential,
}

impl Gateway {
    fn new(origin: Url, roots: RootCertStore) -> Result<Self> {
        let mut transport = HttpConnector::new();
        transport.enforce_http(false);
        transport.set_connect_timeout(Some(Duration::from_secs(5)));
        let connector = HttpsConnectorBuilder::new()
            .with_tls_config(tls_client(roots)?.with_no_client_auth())
            .https_only()
            .enable_http1()
            .wrap_connector(transport);
        let client = Client::builder(TokioExecutor::new())
            .pool_timer(TokioTimer::new())
            .http1_max_buf_size(32 * 1024)
            .build(connector);
        Ok(Self { origin, client })
    }

    async fn sign(&self, tcp: Option<(&str, &str)>) -> Result<Signed> {
        let mut body = serde_json::json!({});
        if let Some((target, csr)) = tcp {
            body["tcp_target"] = target.into();
            body["client_csr_pem"] = csr.into();
        }
        self.sign_challenge("start", &body).await
    }

    async fn sign_forward(&self, scope: Option<&str>, csr: Option<&str>) -> Result<Signed> {
        let mut body = match scope {
            Some(name) => serde_json::json!({ "forward_scope": name }),
            None => serde_json::json!({ "forward": true }),
        };
        if let Some(csr) = csr {
            body["client_csr_pem"] = csr.into();
        }
        self.sign_challenge("start", &body).await
    }

    async fn sign_challenge(&self, step: &str, body: &impl Serialize) -> Result<Signed> {
        let started: Started = self.post(step, body).await?;
        ensure!(
            self.origin.domain() == Some(started.options.public_key.rp_id.as_str()),
            "gateway returned a different WebAuthn relying party"
        );
        eprintln!(
            "Authenticating {ACCOUNT} at {}.",
            self.origin.origin().ascii_serialization()
        );
        let credential = hardware::authenticate(self.origin.clone(), started.options).await?;
        Ok(Signed {
            challenge_id: started.challenge_id,
            credential,
        })
    }

    async fn post<T: DeserializeOwned>(&self, step: &str, body: &impl Serialize) -> Result<T> {
        let uri: Uri = self
            .origin
            .join(&format!("/_shomei/api/auth/{step}"))?
            .as_str()
            .parse()?;
        let request = Request::post(uri)
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(serde_json::to_vec(body)?)))?;
        let (status, body) = timeout(Duration::from_secs(15), async {
            let response = self
                .client
                .request(request)
                .await
                .context("connect to the gateway")?;
            let status = response.status();
            let body = Limited::new(response.into_body(), 128 * 1024)
                .collect()
                .await
                .map_err(|error| anyhow::anyhow!("read gateway response: {error}"))?;
            Ok::<_, anyhow::Error>((status, body.to_bytes()))
        })
        .await
        .context("gateway response timed out")??;
        if !status.is_success() {
            let error = serde_json::from_slice::<serde_json::Value>(&body)
                .ok()
                .and_then(|body| body["error"].as_str().map(str::to_owned))
                .map(|message| {
                    message
                        .chars()
                        .filter(|c| !c.is_control())
                        .take(512)
                        .collect::<String>()
                });
            if let Some(error) = error {
                bail!("gateway returned {status}: {error}");
            }
            bail!("gateway returned {status}");
        }
        serde_json::from_slice(&body).context("invalid gateway response")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clearing_the_identity_requires_an_explicit_yes() {
        let directory = tempfile::tempdir().unwrap();
        let identity = directory.path().join("identity.json");
        let ca = directory.path().join("localhost-ca.pem");
        fs::write(&identity, "identity").unwrap();
        fs::write(&ca, "ca").unwrap();

        for answer in ["", "\n", "no\n"] {
            let mut output = Vec::new();
            clear_identity(&identity, answer.as_bytes(), &mut output).unwrap();
            assert!(identity.exists());
            assert!(String::from_utf8(output).unwrap().contains("[y/N]"));
        }
        clear_identity(&identity, &b"yes\n"[..], io::sink()).unwrap();
        assert!(!identity.exists());
        assert!(ca.exists());
    }

    #[test]
    fn the_local_ca_is_only_selected_for_localhost() {
        let home = tempfile::tempdir().unwrap();
        let local = https_origin("https://localhost:8443").unwrap();
        let remote = https_origin("https://gateway.example.com:8443").unwrap();
        assert_eq!(localhost_ca(&local, Some(home.path())).unwrap(), None);
        let ca = home.path().join(".shomei/localhost-ca.pem");
        fs::create_dir_all(ca.parent().unwrap()).unwrap();
        fs::write(&ca, "ca").unwrap();
        assert_eq!(localhost_ca(&local, Some(home.path())).unwrap(), Some(ca));
        assert_eq!(localhost_ca(&remote, Some(home.path())).unwrap(), None);
    }

    #[test]
    fn prefers_the_home_store_and_falls_back_to_the_previous_default() {
        let home = tempfile::tempdir().unwrap();
        let config = tempfile::tempdir().unwrap();
        let path = home.path().join(".shomei/identity.json");
        let legacy = config.path().join("shomei/identity.json");
        let resolve = || default_identity_path(Some(home.path()), Some(config.path())).unwrap();

        assert_eq!(resolve(), path);
        fs::create_dir_all(legacy.parent().unwrap()).unwrap();
        fs::write(&legacy, "").unwrap();
        assert_eq!(resolve(), legacy);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "").unwrap();
        assert_eq!(resolve(), path);
    }

    #[test]
    fn an_explicit_proxy_can_sign_without_a_local_identity() {
        let proxy = https_origin("https://gateway.example.com").unwrap();
        let resolved = sign_origin(
            Some(proxy.clone()),
            IdentityFile {
                identity_file: None,
            },
        )
        .unwrap();
        assert_eq!(resolved, proxy);
    }
}
