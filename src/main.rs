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
use rustls::server::Acceptor;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpSocket, TcpStream},
    signal::unix::{SignalKind, signal},
    sync::Semaphore,
    time::{MissedTickBehavior, interval, sleep, timeout},
};
use tokio_rustls::{LazyConfigAcceptor, TlsAcceptor, server::TlsStream};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_ACCEPT_FAILURES: u32 = 100;

#[tokio::main]
async fn main() -> Result<()> {
    let Some(path) = cli::run().await? else {
        return Ok(());
    };
    let mut config = Config::load(path.as_ref())?;
    let identity = Identity::load(&config.tls_cert, &config.tls_key)?;
    let https_bind = config.https_bind;
    let https_tls = identity.server(None)?;
    let tcp = if config.tcp_enabled() {
        let tcp = std::mem::take(&mut config.tcp);
        let routes = std::mem::take(&mut config.tcp_upstreams);
        let scopes = if config.forwarding {
            std::mem::take(&mut config.scopes)
        } else {
            Default::default()
        };
        let listener = listen(tcp.bind).context("bind TCP listener")?;
        let gateway = Arc::new(
            forward::Gateway::new(tcp, scopes, config.limits.http_requests)?
                .with_tcp_upstreams(routes)?,
        );
        let tls = identity.server(Some(&gateway.issuer))?;
        Some((listener, gateway, tls))
    } else {
        None
    };
    let https_max = config.limits.https_connections;
    let tcp_max = config.limits.tcp_connections;
    let handshakes = config.limits.tls_handshakes;
    let https_handshakes = Arc::new(Semaphore::new(handshakes));
    let (app, state) = http::app(config, tcp.as_ref().map(|(_, gateway, _)| gateway.clone()))?;
    let auth = state.auth.clone();
    let mut terminate = signal(SignalKind::terminate())?;
    let https = listen(https_bind).context("bind HTTPS listener")?;
    let generation = auth.subscribe_generation();
    let reloader = tokio::spawn(reload_identities(auth));
    eprintln!("HTTPS listening on {}", https.local_addr()?);
    if let Some((listener, _, _)) = &tcp {
        eprintln!("mTLS listening on {}", listener.local_addr()?);
    }

    tokio::select! {
        result = serve(https, https_max, move |socket, peer| http::serve(socket, peer, https_tls.clone(), app.clone(), state.clone(), https_handshakes.clone())) => result?,
        result = async {
            let Some((listener, gateway, tls)) = tcp else { return future::pending().await };
            let handshakes = Arc::new(Semaphore::new(handshakes));
            serve(listener, tcp_max, move |socket, _| forward::serve(socket, tls.clone(), gateway.clone(), handshakes.clone(), generation.clone())).await
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

/// Completes a TLS handshake. A connection waits for its ClientHello without a
/// handshake slot, so idle sockets cannot keep other clients from connecting.
async fn accept_tls<IO>(io: IO, tls: &TlsAcceptor, handshakes: &Semaphore) -> Option<TlsStream<IO>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let hello = timeout(
        HANDSHAKE_TIMEOUT,
        LazyConfigAcceptor::new(Acceptor::default(), io),
    )
    .await
    .ok()?
    .ok()?;
    timeout(HANDSHAKE_TIMEOUT, async {
        let _permit = handshakes.acquire().await.ok()?;
        hello.into_stream(tls.config().clone()).await.ok()
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
    let mut failures = 0;
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
            // Other errors are usually transient, such as a peer that reset
            // while queued or a kernel short of buffers. Stop only when the
            // listener keeps failing, so a supervisor can restart the gateway.
            Err(error) if failures < MAX_ACCEPT_FAILURES => {
                if failures == 0 {
                    eprintln!("Accepting a connection failed, retrying: {error}");
                }
                failures += 1;
                sleep(Duration::from_millis(100)).await;
                continue;
            }
            Err(error) => return Err(error),
        };
        failures = 0;
        let connection = handle(socket, peer);
        tokio::spawn(async move {
            connection.await;
            drop(permit);
        });
    }
}
