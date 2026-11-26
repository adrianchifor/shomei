mod auth;
mod cli;
mod config;
mod forward;
mod http;
mod session;
mod tailscale;
mod tls;

use std::{future, io, net::SocketAddr, sync::Arc, time::Duration};

use crate::{config::Config, tls::Identity};
use anyhow::{Context, Result};
use tokio::{
    net::{TcpListener, TcpSocket, TcpStream},
    signal::unix::{SignalKind, signal},
    sync::Semaphore,
    time::{MissedTickBehavior, interval, sleep, timeout},
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::main]
async fn main() -> Result<()> {
    let Some(path) = cli::run().await? else {
        return Ok(());
    };
    let mut config = Config::load(path.as_ref())?;
    let identity = Identity::load(&config.tls_cert, &config.tls_key)?;
    let issuer = config
        .tcp
        .as_ref()
        .map(|_| tls::Issuer::new())
        .transpose()?;
    let https_bind = config.https_bind;
    let https_tls = identity.server(None)?;
    let tcp = if let (Some(tcp), Some(issuer)) = (&config.tcp, &issuer) {
        let listener = listen(tcp.bind).context("bind TCP listener")?;
        Some((
            listener,
            identity.server(Some(issuer))?,
            Arc::<str>::from(tcp.upstream.as_str()),
        ))
    } else {
        None
    };
    let https_max = config.limits.https_connections;
    let tcp_max = config.limits.tcp_connections;
    let handshakes = config.limits.tls_handshakes;
    let https_handshakes = Arc::new(Semaphore::new(handshakes));
    let forward = config
        .forward
        .take()
        .map(|forward| -> Result<_> {
            let listener = listen(forward.bind).context("bind forward proxy listener")?;
            let gateway = Arc::new(forward::Gateway::new(forward, config.limits.http_requests)?);
            let tls = identity.server(Some(&gateway.issuer))?;
            Ok((listener, gateway, tls))
        })
        .transpose()?;
    let http_forward = forward
        .as_ref()
        .and_then(|(_, gateway, _)| {
            gateway.config.http_bind.map(|bind| -> Result<_> {
                let listener = listen(bind).context("bind HTTP forward proxy listener")?;
                Ok((listener, gateway.clone(), identity.http1_server()?))
            })
        })
        .transpose()?;
    let (app, state) = http::app(
        config,
        issuer,
        forward.as_ref().map(|(_, gateway, _)| gateway.clone()),
    )?;
    let auth = state.auth.clone();
    let mut terminate = signal(SignalKind::terminate())?;
    let https = listen(https_bind).context("bind HTTPS listener")?;
    let generation = auth.subscribe_generation();
    let forward_generation = generation.clone();
    let reloader = tokio::spawn(reload_identities(auth));
    eprintln!("HTTPS listening on {}", https.local_addr()?);
    if let Some((listener, _, _)) = &tcp {
        eprintln!("mTLS listening on {}", listener.local_addr()?);
    }
    if let Some((listener, _, _)) = &forward {
        eprintln!("TCP forward proxy listening on {}", listener.local_addr()?);
    }
    if let Some((listener, _, _)) = &http_forward {
        eprintln!(
            "HTTP forward proxy listening with TLS on {}",
            listener.local_addr()?
        );
    }

    tokio::select! {
        result = serve(https, https_max, move |socket, peer| http::serve(socket, peer, https_tls.clone(), app.clone(), https_handshakes.clone())) => result?,
        result = async {
            let Some((listener, tls, upstream)) = tcp else { return future::pending().await };
            let handshakes = Arc::new(Semaphore::new(handshakes));
            serve(listener, tcp_max, move |socket, _| tls::relay(socket, tls.clone(), upstream.clone(), handshakes.clone(), generation.clone())).await
        } => result?,
        result = async {
            let Some((listener, gateway, tls)) = forward else { return future::pending().await };
            let handshakes = Arc::new(Semaphore::new(handshakes));
            serve(listener, tcp_max, move |socket, _| forward::serve(socket, tls.clone(), gateway.clone(), handshakes.clone(), forward_generation.clone())).await
        } => result?,
        result = async {
            let Some((listener, gateway, tls)) = http_forward else { return future::pending().await };
            let handshakes = Arc::new(Semaphore::new(handshakes));
            serve(listener, https_max, move |socket, _| forward::serve_http(socket, tls.clone(), gateway.clone(), handshakes.clone(), state.clone())).await
        } => result?,
        result = tokio::signal::ctrl_c() => result?,
        _ = terminate.recv() => {},
    }
    reloader.abort();
    Ok(())
}

async fn reload_identities(auth: Arc<auth::Auth>) {
    let mut timer = interval(Duration::from_secs(1));
    timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    timer.tick().await;
    let mut last_error = None;
    loop {
        timer.tick().await;
        let auth = auth.clone();
        let result = tokio::task::spawn_blocking(move || auth.reload()).await;
        let error = match result {
            Ok(Ok(true)) => {
                eprintln!("Reloaded YubiKey identities");
                last_error = None;
                continue;
            }
            Ok(Ok(false)) => continue,
            Ok(Err(error)) => format!("{error:#}"),
            Err(error) => error.to_string(),
        };
        if last_error.as_ref() != Some(&error) {
            eprintln!("Identity reload failed, keeping the last valid file: {error}");
            last_error = Some(error);
        }
    }
}

fn listen(addr: SocketAddr) -> io::Result<TcpListener> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    socket.listen(4096)
}

async fn accept_tls(
    socket: TcpStream,
    tls: TlsAcceptor,
    handshakes: &Semaphore,
) -> Option<TlsStream<TcpStream>> {
    timeout(HANDSHAKE_TIMEOUT, async {
        let _permit = handshakes.acquire().await.ok()?;
        socket.set_nodelay(true).ok()?;
        tls.accept(socket).await.ok()
    })
    .await
    .ok()
    .flatten()
}

async fn serve<F>(
    listener: TcpListener,
    limit: usize,
    handle: impl Fn(TcpStream, SocketAddr) -> F,
) -> io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let slots = Arc::new(Semaphore::new(limit));
    loop {
        let permit = slots
            .clone()
            .acquire_owned()
            .await
            .expect("connection semaphore stays open");
        let (socket, peer) = match listener.accept().await {
            Ok(connection) => connection,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted
                ) =>
            {
                continue;
            }
            Err(error) if matches!(error.raw_os_error(), Some(23 | 24)) => {
                sleep(Duration::from_millis(100)).await;
                continue;
            }
            Err(error) => return Err(error),
        };
        let connection = handle(socket, peer);
        tokio::spawn(async move {
            connection.await;
            drop(permit);
        });
    }
}
