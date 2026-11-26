use std::{
    ffi::{OsStr, OsString},
    io::{self, Read, Write},
    net::{IpAddr, Shutdown},
    os::unix::net::UnixStream as BlockingStream,
    path::{Path, PathBuf},
    process::ExitStatus,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use clap::Args;
use hyper::http::uri::Authority;
use rcgen::{CertificateParams, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, pem::PemObject};
use serde::Deserialize;
use tokio::{
    io::copy_bidirectional,
    net::{TcpStream, UnixListener},
    process::Command,
    time::timeout,
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use url::Url;

use super::{Gateway, https_origin, tls_client, trust_roots};

#[derive(Args)]
pub(super) struct SshArgs {
    /// The gateway HTTPS origin or a tls://host:port TCP endpoint.
    #[arg(long, env = "SHOMEI_PROXY")]
    proxy: Url,
    /// The HTTPS authorization origin for tls:// proxies. Defaults to port 8443.
    #[arg(long, value_parser = https_origin)]
    auth_url: Option<Url>,
    /// PEM trust roots. Localhost can use ~/.shomei/localhost-ca.pem.
    #[arg(long, env = "SHOMEI_CA_FILE")]
    ca_file: Option<PathBuf>,
    /// Pass one option or value to OpenSSH. Repeat with --ssh-arg=<value>.
    #[arg(long, allow_hyphen_values = true)]
    ssh_arg: Vec<OsString>,
    /// A username and the gateway's allowlisted SSH host alias.
    #[arg(value_name = "USER@HOST")]
    destination: String,
    /// Optional remote command and arguments after --.
    #[arg(last = true, num_args = 1.., allow_hyphen_values = true)]
    command: Vec<OsString>,
}

#[derive(Deserialize)]
struct ClientCertificate {
    certificate_pem: String,
    expires_at: u64,
    tcp_endpoint: String,
}

pub(super) async fn run(args: SshArgs) -> Result<()> {
    let host = ssh_host(&args.destination)?;
    let (origin, expected_port) = proxy_origins(&args.proxy, args.auth_url.clone())?;
    let tls_host = origin
        .domain()
        .context("missing TLS server name")?
        .to_owned();
    let roots = trust_roots(&origin, args.ca_file.as_deref())?;
    let gateway = Gateway::new(origin, roots.clone())?;
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "Shomei SSH client");
    let csr = params.serialize_request(&key)?.pem()?;
    let signed = gateway.sign(Some((host, &csr))).await?;
    let grant: ClientCertificate = gateway.post("finish", &signed).await?;
    ensure!(
        grant.expires_at > crate::tls::unix_seconds()?,
        "the gateway client certificate has expired"
    );
    let port = endpoint_port(&grant.tcp_endpoint, &tls_host, expected_port)?;

    let certificate = CertificateDer::from_pem_slice(grant.certificate_pem.as_bytes())?;
    let private_key = PrivatePkcs8KeyDer::from(key.serialize_der()).into();
    let tls = TlsConnector::from(Arc::new(
        tls_client(roots)?.with_client_auth_cert(vec![certificate], private_key)?,
    ));
    let stream = timeout(Duration::from_secs(10), async {
        let socket = TcpStream::connect((tls_host.as_str(), port))
            .await
            .context("connect to the TCP gateway")?;
        socket.set_nodelay(true)?;
        tls.connect(ServerName::try_from(tls_host)?, socket)
            .await
            .context("authenticate the TCP gateway with mTLS")
    })
    .await
    .context("TCP gateway connection timed out")??;
    let status = openssh(&args, host, stream).await?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

fn ssh_host(destination: &str) -> Result<&str> {
    let (user, host) = destination
        .split_once('@')
        .context("expected SSH destination USER@HOST")?;
    let valid = |value: &str| {
        !value.is_empty()
            && value.len() <= 253
            && !value.starts_with('-')
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    };
    ensure!(valid(user), "invalid SSH username");
    if let Some(ip) = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        && ip.parse::<std::net::Ipv6Addr>().is_ok()
    {
        return Ok(ip);
    }
    ensure!(
        valid(host) || host.parse::<IpAddr>().is_ok(),
        "invalid SSH host alias"
    );
    Ok(host)
}

fn proxy_origins(proxy: &Url, auth_url: Option<Url>) -> Result<(Url, Option<u16>)> {
    if proxy.scheme() == "https" {
        ensure!(
            auth_url.is_none(),
            "--auth-url is only used with tls:// proxies"
        );
        return Ok((https_origin(proxy.as_str())?, None));
    }
    ensure!(
        proxy.scheme() == "tls"
            && proxy.domain().is_some()
            && proxy.port().is_some_and(|port| port != 0)
            && proxy.username().is_empty()
            && proxy.password().is_none()
            && matches!(proxy.path(), "" | "/")
            && proxy.query().is_none()
            && proxy.fragment().is_none(),
        "expected an HTTPS origin or tls://host:port"
    );
    let host = proxy.domain().context("missing TCP gateway hostname")?;
    let origin = match auth_url {
        Some(origin) => origin,
        None => https_origin(&format!("https://{host}:8443"))?,
    };
    ensure!(
        origin
            .domain()
            .is_some_and(|domain| domain.eq_ignore_ascii_case(host)),
        "the HTTPS and TCP gateway hostnames must match"
    );
    Ok((origin, proxy.port()))
}

fn endpoint_port(endpoint: &str, host: &str, expected_port: Option<u16>) -> Result<u16> {
    let authority: Authority = endpoint
        .parse()
        .context("invalid TCP endpoint from the gateway")?;
    ensure!(
        !endpoint.contains('@') && authority.host().eq_ignore_ascii_case(host),
        "the TCP endpoint must use the gateway hostname"
    );
    let port = authority
        .port_u16()
        .filter(|port| *port != 0)
        .context("the TCP endpoint is missing a valid port")?;
    ensure!(
        expected_port.is_none_or(|expected| expected == port),
        "the gateway issued access for a different TCP endpoint"
    );
    Ok(port)
}

async fn openssh(
    args: &SshArgs,
    host: &str,
    mut stream: TlsStream<TcpStream>,
) -> Result<ExitStatus> {
    let dir = tempfile::Builder::new()
        .prefix("shomei-")
        .tempdir_in("/tmp")?;
    let socket_path = dir.path().join("ssh.sock");
    let listener = UnixListener::bind(&socket_path).context("open local SSH bridge")?;
    let executable = shell_arg(std::env::current_exe()?.as_os_str())?;
    let socket = shell_arg(socket_path.as_os_str())?;
    let mut ssh = Command::new("ssh");
    ssh.kill_on_drop(true)
        .arg("-o")
        .arg(format!("ProxyCommand={executable} ssh-stdio {socket}"))
        .arg("-o")
        .arg(format!("HostKeyAlias={host}"))
        .arg("-o")
        .arg("ControlMaster=no")
        .arg("-o")
        .arg("ControlPath=none")
        .arg("-o")
        .arg("ProxyUseFdpass=no")
        .args(&args.ssh_arg)
        .arg("--")
        .arg(&args.destination)
        .args(&args.command);
    let mut ssh = ssh.spawn().context("start OpenSSH")?;
    let bridge = async {
        let (mut socket, _) = listener.accept().await.context("accept local SSH bridge")?;
        copy_bidirectional(&mut socket, &mut stream)
            .await
            .context("relay SSH traffic")?;
        Ok::<_, anyhow::Error>(())
    };
    let status = tokio::select! {
        biased;
        status = ssh.wait() => status,
        result = bridge => {
            if result.is_err()
                && let Ok(Ok(status)) = timeout(Duration::from_secs(1), ssh.wait()).await
            {
                return Ok(status);
            }
            result?;
            ssh.wait().await
        }
    };
    status.context("wait for OpenSSH")
}

fn shell_arg(value: &OsStr) -> Result<String> {
    let value = value
        .to_str()
        .context("the SSH bridge path must be UTF-8")?;
    Ok(format!(
        "'{}'",
        value.replace('%', "%%").replace('\'', "'\"'\"'")
    ))
}

pub(super) fn stdio(socket: &Path) -> Result<()> {
    let mut stream = BlockingStream::connect(socket).context("connect local SSH bridge")?;
    let mut output = stream.try_clone()?;
    std::thread::spawn(move || {
        let _ = io::copy(&mut io::stdin().lock(), &mut output);
        let _ = output.shutdown(Shutdown::Write);
    });
    let mut stdout = io::stdout().lock();
    let mut buffer = [0; 16 * 1024];
    loop {
        let bytes = stream.read(&mut buffer)?;
        if bytes == 0 {
            return Ok(());
        }
        stdout.write_all(&buffer[..bytes])?;
        stdout.flush()?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_ssh_destination_and_gateway_endpoint() {
        assert_eq!(ssh_host("ubuntu@deploy.example").unwrap(), "deploy.example");
        assert_eq!(ssh_host("ubuntu@[::1]").unwrap(), "::1");
        assert!(ssh_host("user@different:2222").is_err());
        assert!(ssh_host("-oProxyCommand=echo@deploy").is_err());
        let (origin, port) =
            proxy_origins(&Url::parse("tls://gateway.example:9443").unwrap(), None).unwrap();
        assert_eq!(origin.as_str(), "https://gateway.example:8443/");
        assert_eq!(
            endpoint_port("gateway.example:9443", "gateway.example", port).unwrap(),
            9443
        );
        assert!(endpoint_port("gateway.example:22", "gateway.example", port).is_err());
        assert!(endpoint_port("unexpected.example:9443", "gateway.example", port).is_err());
    }

    #[test]
    fn quotes_proxy_command_paths_with_spaces_and_percent_tokens() {
        assert_eq!(
            shell_arg(OsStr::new("/tmp/my %h/key's")).unwrap(),
            "'/tmp/my %%h/key'\"'\"'s'"
        );
    }
}
