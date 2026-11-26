mod hardware;
mod ssh;

use std::{
    env, fs,
    io::{BufReader, Write},
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

use crate::auth::{ACCOUNT, StaticIdentity, prepare_identity};

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
    /// Print the saved public identity as JSON.
    GetId(IdentityFile),
    /// Print a one-use Shomei authorization assertion.
    Sign(Access),
    /// Connect to an allowlisted SSH host through Shomei.
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

impl IdentityFile {
    fn resolve(self) -> Result<PathBuf> {
        if let Some(path) = self.identity_file {
            return Ok(path);
        }
        let home = env::var_os("HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);
        let config = env::var_os("XDG_CONFIG_HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);
        default_identity_path(home.as_deref(), config.as_deref())
    }
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
    /// PEM trust roots for this gateway. Defaults to public WebPKI roots.
    #[arg(long, env = "SHOMEI_CA_FILE")]
    ca_file: Option<PathBuf>,
    #[command(flatten)]
    identity: IdentityFile,
}

pub async fn run() -> Result<Option<PathBuf>> {
    let args = Arguments::parse();
    match args.command {
        None => return Ok(Some(config_path(args.config))),
        Some(Command::Serve { config }) => return Ok(Some(config_path(config))),
        Some(Command::Init(args)) => init(args).await?,
        Some(Command::GetId(args)) => get_id(args)?,
        Some(Command::Sign(args)) => {
            let origin = sign_origin(args.proxy, args.identity)?;
            let gateway = Gateway::new(origin, trust_roots(args.ca_file.as_deref())?)?;
            let signed = gateway.sign(None).await?;
            println!("{}", URL_SAFE_NO_PAD.encode(serde_json::to_vec(&signed)?));
        }
        Some(Command::Ssh(args)) => ssh::run(args).await?,
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

fn get_id(args: IdentityFile) -> Result<()> {
    let identity = read_identity(args)?;
    println!("{}", serde_json::to_string(&identity)?);
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

fn trust_roots(path: Option<&Path>) -> Result<RootCertStore> {
    let Some(path) = path else {
        return Ok(RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        });
    };
    let mut store = RootCertStore::empty();
    for certificate in CertificateDer::pem_file_iter(path).context("open gateway CA file")? {
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
        let started: Started = self.post("start", &body).await?;
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
