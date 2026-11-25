mod auth;
mod config;
mod http;
mod session;
mod tls;

use std::{future, io, sync::Arc, time::Duration};

use crate::{config::Config, tls::Identity};
use anyhow::{Context, Result};
use tokio::{
    net::{TcpListener, TcpStream},
    signal::unix::{SignalKind, signal},
    sync::Semaphore,
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::main]
async fn main() -> Result<()> {
    let path = std::env::args_os()
        .nth(1)
        .unwrap_or_else(|| "shomei.toml".into());
    let config = Config::load(path.as_ref())?;
    let identity = Identity::load(&config.tls_cert, &config.tls_key)?;
    let issuer = config
        .tcp
        .as_ref()
        .map(|_| tls::Issuer::new())
        .transpose()?;
    let https = TcpListener::bind(config.https_bind)
        .await
        .context("bind HTTPS listener")?;
    let https_tls = identity.server(None)?;
    let tcp = if let (Some(tcp), Some(issuer)) = (&config.tcp, &issuer) {
        let listener = TcpListener::bind(tcp.bind)
            .await
            .context("bind TCP listener")?;
        Some((
            listener,
            identity.server(Some(issuer))?,
            tcp.upstream.clone(),
        ))
    } else {
        None
    };
    let app = http::app(config, issuer)?;
    let mut terminate = signal(SignalKind::terminate())?;
    eprintln!("HTTPS listening on {}", https.local_addr()?);
    if let Some((listener, _, _)) = &tcp {
        eprintln!("mTLS listening on {}", listener.local_addr()?);
    }

    tokio::select! {
        result = serve(https, 256, move |socket| http::serve(socket, https_tls.clone(), app.clone())) => result?,
        result = async {
            let Some((listener, tls, upstream)) = tcp else { return future::pending().await };
            serve(listener, 128, move |socket| tls::relay(socket, tls.clone(), upstream.clone())).await
        } => result?,
        result = tokio::signal::ctrl_c() => result?,
        _ = terminate.recv() => {},
    }
    Ok(())
}

async fn serve<F>(
    listener: TcpListener,
    limit: usize,
    handle: impl Fn(TcpStream) -> F,
) -> io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let slots = Arc::new(Semaphore::new(limit));
    loop {
        let (socket, _) = listener.accept().await?;
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let connection = handle(socket);
        tokio::spawn(async move {
            connection.await;
            drop(permit);
        });
    }
}
