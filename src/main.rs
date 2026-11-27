mod auth;
mod cli;
mod config;
mod forward;
mod http;
mod session;
mod tailscale;
mod tls;

use std::{
    collections::HashMap,
    future, io,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use crate::{config::Config, tls::Identity};
use anyhow::{Context, Result};
use rustls::server::Acceptor;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpSocket, TcpStream},
    signal::unix::{SignalKind, signal},
    sync::{OwnedSemaphorePermit, Semaphore},
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
    let tcp_capacity = Capacity::new(config.limits.tcp_connections, config.limits.per_ip_percent);
    let handshakes = config.limits.tls_handshakes;
    let https_handshakes = Arc::new(Semaphore::new(handshakes));
    let (app, state) = http::app(config, tcp.as_ref().map(|(_, gateway, _)| gateway.clone()))?;
    let https_capacity = state.connections.clone();
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
        result = serve(https, https_capacity, move |socket, peer| http::serve(socket, peer, https_tls.clone(), app.clone(), state.clone(), https_handshakes.clone())) => result?,
        result = async {
            let Some((listener, gateway, tls)) = tcp else { return future::pending().await };
            let handshakes = Arc::new(Semaphore::new(handshakes));
            serve(listener, tcp_capacity, move |socket, _| forward::serve(socket, tls.clone(), gateway.clone(), handshakes.clone(), generation.clone())).await
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

/// The address a client is counted under: the IPv4 address, or the /64 that
/// an IPv6 address belongs to, since one host usually holds a whole /64.
pub fn client_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(ip) => IpAddr::V6(Ipv6Addr::from(u128::from(ip) & (u128::MAX << 64))),
        ip => ip,
    }
}

/// A capacity limit of which one client address may hold only a share, so a
/// single client cannot take every slot.
#[derive(Clone)]
pub struct Capacity {
    slots: Arc<Semaphore>,
    clients: Arc<Clients>,
}

/// What each client address holds. An address leaves the map when it holds
/// nothing, so the map never outgrows the capacity it counts.
struct Clients {
    share: usize,
    held: Mutex<HashMap<IpAddr, usize>>,
}

/// One unit of a capacity, returned to it on drop.
pub struct Slot {
    _slot: OwnedSemaphorePermit,
    client: Option<(Arc<Clients>, IpAddr)>,
}

impl Capacity {
    /// `percent` of `limit`, rounded down and at least 1, is each client's share.
    pub fn new(limit: usize, percent: usize) -> Self {
        Self {
            slots: Arc::new(Semaphore::new(limit)),
            clients: Arc::new(Clients {
                share: (limit * percent / 100).max(1),
                held: Mutex::default(),
            }),
        }
    }

    /// The same slots with a separate count of client shares.
    pub fn with_shares(&self, limit: usize, percent: usize) -> Self {
        Self {
            slots: self.slots.clone(),
            ..Self::new(limit, percent)
        }
    }

    /// A separate limit of `slots` whose client shares are counted together
    /// with this capacity's.
    pub fn with_slots(&self, slots: usize) -> Self {
        Self {
            slots: Arc::new(Semaphore::new(slots)),
            clients: self.clients.clone(),
        }
    }

    /// Takes a slot if one is free and `client` is within its share. `None`
    /// takes a slot without counting it against any client.
    pub fn try_acquire(&self, client: Option<IpAddr>) -> Option<Slot> {
        let slot = self.slots.clone().try_acquire_owned().ok()?;
        self.claim(slot, client)
    }

    fn claim(&self, slot: OwnedSemaphorePermit, client: Option<IpAddr>) -> Option<Slot> {
        let Some(client) = client.map(client_key) else {
            return Some(Slot {
                _slot: slot,
                client: None,
            });
        };
        let mut held = self
            .clients
            .held
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let count = held.entry(client).or_default();
        if *count >= self.clients.share {
            return None;
        }
        *count += 1;
        Some(Slot {
            _slot: slot,
            client: Some((self.clients.clone(), client)),
        })
    }

    #[cfg(test)]
    pub fn clients(&self) -> usize {
        self.clients.held.lock().unwrap().len()
    }

    #[cfg(test)]
    pub fn available(&self) -> usize {
        self.slots.available_permits()
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        if let Some((clients, client)) = &self.client {
            let mut held = clients.held.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(count) = held.get_mut(client) {
                *count -= 1;
                if *count == 0 {
                    held.remove(client);
                }
            }
        }
    }
}

/// Accepts connections while `capacity` has a free slot. A connection from an
/// address that already holds its share is closed before the TLS handshake.
async fn serve<F>(
    listener: TcpListener,
    capacity: Capacity,
    handle: impl Fn(TcpStream, SocketAddr) -> F,
) -> io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let mut failures = 0;
    loop {
        let permit = capacity
            .slots
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
        let Some(permit) = capacity.claim(permit, Some(peer.ip())) else {
            continue;
        };
        let connection = handle(socket, peer);
        tokio::spawn(async move {
            connection.await;
            drop(permit);
        });
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncReadExt;

    use super::*;

    #[test]
    fn a_client_address_holds_at_most_its_share() {
        let capacity = Capacity::new(8, 25);
        let ip = |ip: &str| Some(ip.parse::<IpAddr>().unwrap());
        // One /64 counts as one client, and so does an IPv4-mapped address.
        let held: Vec<_> = ["2001:db8::1", "2001:db8::2"]
            .into_iter()
            .map(|client| capacity.try_acquire(ip(client)).unwrap())
            .collect();
        assert!(capacity.try_acquire(ip("2001:db8::ffff")).is_none());
        let other = capacity.try_acquire(ip("2001:db8:0:1::1")).unwrap();
        let v4 = capacity.try_acquire(ip("192.0.2.1")).unwrap();
        let mapped = capacity.try_acquire(ip("::ffff:192.0.2.1")).unwrap();
        assert!(capacity.try_acquire(ip("192.0.2.1")).is_none());
        // Uncounted slots still take from the shared limit.
        let uncounted: Vec<_> = (0..3)
            .map(|_| capacity.try_acquire(None).unwrap())
            .collect();
        assert_eq!(capacity.available(), 0);
        assert!(capacity.try_acquire(ip("192.0.2.2")).is_none());
        assert_eq!(capacity.clients(), 3);
        drop((held, other, v4, mapped, uncounted));
        assert_eq!(capacity.clients(), 0);
        assert_eq!(capacity.available(), 8);
        // A share is at least one slot.
        let tiny = Capacity::new(3, 1);
        let _one = tiny.try_acquire(ip("192.0.2.1")).unwrap();
        assert!(tiny.try_acquire(ip("192.0.2.1")).is_none());
        // Tunnels have their own limit but the connections' shares.
        let tunnels = capacity.with_slots(8);
        let _connection = capacity.try_acquire(ip("192.0.2.1")).unwrap();
        let _tunnel = tunnels.try_acquire(ip("192.0.2.1")).unwrap();
        assert!(tunnels.try_acquire(ip("192.0.2.1")).is_none());
        assert_eq!(tunnels.available(), 7);
    }

    #[tokio::test]
    async fn connections_over_a_client_share_close_at_accept() {
        let listener = listen("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = listener.local_addr().unwrap();
        let capacity = Capacity::new(4, 50);
        let accepted = Arc::new(Semaphore::new(0));
        let counted = accepted.clone();
        let server = tokio::spawn(serve(listener, capacity.clone(), move |mut socket, _| {
            counted.add_permits(1);
            async move {
                let _ = socket.read(&mut [0; 1]).await;
            }
        }));
        let first = TcpStream::connect(addr).await.unwrap();
        let second = TcpStream::connect(addr).await.unwrap();
        accepted.acquire_many(2).await.unwrap().forget();
        let mut refused = TcpStream::connect(addr).await.unwrap();
        let closed = timeout(Duration::from_secs(2), refused.read(&mut [0; 1])).await;
        assert!(matches!(closed, Ok(Ok(0) | Err(_))), "{closed:?}");
        assert_eq!(accepted.available_permits(), 0);
        // Two held, and one taken by the loop waiting to accept.
        assert_eq!((capacity.clients(), capacity.available()), (1, 1));
        drop(first);
        let mut third = TcpStream::connect(addr).await.unwrap();
        timeout(Duration::from_secs(2), accepted.acquire())
            .await
            .expect("a freed share admits a new connection")
            .unwrap()
            .forget();
        assert!(
            timeout(Duration::from_millis(200), third.read(&mut [0; 1]))
                .await
                .is_err()
        );
        drop((second, third));
        server.abort();
    }
}
