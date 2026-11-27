//! Closes client connections that stop taking the data sent to them.
//!
//! Timeouts on reads cannot see a client that requests a response and then
//! never reads it: HTTP/2 flow control or a full socket then holds the
//! connection, its slot and any upstream request open for as long as the
//! client keeps the connection alive. Each connection keeps a set of marks,
//! one per thing that can only move when the client takes data, and closes
//! when any mark has waited longer than `STALL`:
//!
//! - A response body, from when it is handed to hyper and again after every
//!   frame it yields, until hyper polls it again. hyper polls an HTTP/2 body
//!   for its next frame only when the stream has send capacity for the last
//!   one, and an HTTP/1 body only when its write buffer has room. A body whose
//!   last poll returned `Pending` waits for its upstream instead, so an idle
//!   event stream does not count.
//! - The socket, from when a write or flush returns `Pending` until one makes
//!   progress. This covers the gaps between HTTP/1 responses, when no body is
//!   alive but hyper waits to flush before it reads the next request.
//! - After a graceful shutdown, the connection itself once nothing is left in
//!   flight. HTTP/2 can still hold the last frames of a finished body behind a
//!   flow-control window that the client never opens.

use std::{
    future::Future,
    io,
    pin::{Pin, pin},
    sync::{
        Arc, Mutex, PoisonError, Weak,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use axum::{
    body::{Body, Bytes},
    response::Response,
};
use http_body::{Frame, SizeHint};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{Instant, sleep_until},
};

use super::HTTP2_IDLE;

/// How long a response may wait for its client to take data.
pub(crate) const STALL: Duration = Duration::from_secs(if cfg!(test) { 1 } else { 30 });

/// The marks of one connection.
pub(crate) struct Stalls {
    origin: Instant,
    marks: Mutex<Marks>,
    in_flight: AtomicUsize,
    /// When `in_flight` last fell to zero, as a mark value.
    drained: AtomicU64,
}

struct Marks {
    live: Vec<Weak<AtomicU64>>,
    prune_at: usize,
}

/// A time something started waiting for the client, as milliseconds after
/// the connection's origin plus one, or zero while it is not waiting.
#[derive(Clone)]
struct Mark {
    since: Arc<AtomicU64>,
    origin: Instant,
}

impl Mark {
    fn now(&self) -> u64 {
        self.origin.elapsed().as_millis() as u64 + 1
    }

    /// Starts waiting now.
    fn wait(&self) {
        self.since.store(self.now(), Ordering::Relaxed);
    }

    /// Starts waiting now unless already waiting.
    fn keep_waiting(&self) {
        let _ = self
            .since
            .compare_exchange(0, self.now(), Ordering::Relaxed, Ordering::Relaxed);
    }

    fn clear(&self) {
        self.since.store(0, Ordering::Relaxed);
    }
}

impl Stalls {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            origin: Instant::now(),
            marks: Mutex::new(Marks {
                live: Vec::new(),
                prune_at: 16,
            }),
            in_flight: AtomicUsize::new(0),
            drained: AtomicU64::new(0),
        })
    }

    fn mark(&self) -> Mark {
        let since = Arc::new(AtomicU64::new(0));
        let mut marks = self.marks.lock().unwrap_or_else(PoisonError::into_inner);
        if marks.live.len() >= marks.prune_at {
            marks.live.retain(|mark| mark.strong_count() > 0);
            marks.prune_at = (marks.live.len() * 2).max(16);
        }
        marks.live.push(Arc::downgrade(&since));
        Mark {
            since,
            origin: self.origin,
        }
    }

    /// Counts a request as in flight until its response body is dropped. A
    /// tunnel holds one for as long as it runs: on HTTP/2 it is a stream of
    /// this connection, which must stay open after the idle shutdown.
    pub(crate) fn begin(self: &Arc<Self>) -> InFlight {
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        InFlight(self.clone())
    }

    /// Counts a tunnel opened by `request` as in flight on the connection
    /// that carries it, if that connection is watched.
    pub(crate) fn tunnel<B>(request: &hyper::Request<B>) -> Option<InFlight> {
        request
            .extensions()
            .get::<Arc<Self>>()
            .map(|stalls| stalls.begin())
    }

    /// Wraps a client connection so writes that cannot make progress count.
    pub(crate) fn watch_io<IO>(&self, io: IO) -> Watched<IO> {
        Watched {
            io,
            mark: self.mark(),
        }
    }

    /// The oldest time anything on the connection started waiting for the
    /// client. After a shutdown, a connection with nothing left in flight is
    /// waiting for the client too.
    fn waiting_since(&self, draining: bool) -> Option<Instant> {
        let at = |since: u64| self.origin + Duration::from_millis(since - 1);
        let mut oldest = None::<u64>;
        let mut consider = |since: u64| {
            if since != 0 {
                oldest = Some(oldest.map_or(since, |oldest| oldest.min(since)));
            }
        };
        {
            let marks = self.marks.lock().unwrap_or_else(PoisonError::into_inner);
            for mark in &marks.live {
                if let Some(mark) = mark.upgrade() {
                    consider(mark.load(Ordering::Relaxed));
                }
            }
        }
        if draining && self.in_flight.load(Ordering::Relaxed) == 0 {
            consider(self.drained.load(Ordering::Relaxed));
        }
        oldest.map(at)
    }

    /// Starts the wait for a shut-down connection to finish, from now or from
    /// when its last request completes.
    fn start_draining(&self) {
        let now = self.origin.elapsed().as_millis() as u64 + 1;
        self.drained.store(now, Ordering::Relaxed);
    }
}

/// A request being handled or a response body still alive.
pub(crate) struct InFlight(Arc<Stalls>);

impl InFlight {
    /// Tracks a response from the moment it is handed to hyper.
    pub(crate) fn track(self, response: Response) -> Response {
        let mark = self.0.mark();
        mark.wait();
        response.map(|body| {
            Body::new(Tracked {
                body,
                mark,
                _in_flight: self,
            })
        })
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        let stalls = &self.0;
        if stalls.in_flight.fetch_sub(1, Ordering::Relaxed) == 1 {
            let now = stalls.origin.elapsed().as_millis() as u64 + 1;
            stalls.drained.store(now, Ordering::Relaxed);
        }
    }
}

struct Tracked {
    body: Body,
    mark: Mark,
    _in_flight: InFlight,
}

impl http_body::Body for Tracked {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, axum::Error>>> {
        self.mark.clear();
        let frame = Pin::new(&mut self.body).poll_frame(cx);
        if let Poll::Ready(Some(Ok(_))) = frame {
            self.mark.wait();
        }
        frame
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

/// A client connection whose blocked writes count as waiting for the client.
pub(crate) struct Watched<IO> {
    io: IO,
    mark: Mark,
}

impl<IO> Watched<IO> {
    fn progress<T>(&self, poll: Poll<io::Result<T>>) -> Poll<io::Result<T>> {
        match poll {
            Poll::Pending => self.mark.keep_waiting(),
            Poll::Ready(_) => self.mark.clear(),
        }
        poll
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for Watched<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for Watched<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.io).poll_write(cx, buf);
        self.progress(poll)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.io).poll_write_vectored(cx, bufs);
        self.progress(poll)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let poll = Pin::new(&mut self.io).poll_flush(cx);
        self.progress(poll)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let poll = Pin::new(&mut self.io).poll_shutdown(cx);
        self.progress(poll)
    }
}

/// Drives a client connection and drops it, closing it, once anything on it
/// has waited for the client for longer than `STALL`. With `idle`, a count of
/// the requests started, it also starts a graceful shutdown once no request
/// has arrived for `HTTP2_IDLE`: HTTP/2 has no idle timeout of its own, so a
/// silent connection would otherwise hold its slot for as long as the peer
/// answers pings. Requests already in flight finish first, under the same
/// watch. Dropping the connection drops its response bodies and handlers,
/// which releases their request slots and upstream connections.
pub(crate) async fn watch<C: Future>(
    connection: C,
    stalls: &Stalls,
    idle: Option<&AtomicU64>,
    shutdown: impl FnOnce(Pin<&mut C>),
) {
    let mut connection = pin!(connection);
    let mut shutdown = Some(shutdown);
    let mut seen = 0;
    let mut idle_at = Instant::now() + HTTP2_IDLE;
    loop {
        let now = Instant::now();
        let waiting = stalls.waiting_since(shutdown.is_none());
        if waiting.is_some_and(|since| now.saturating_duration_since(since) >= STALL) {
            return;
        }
        // A mark set after now cannot run out before now + STALL.
        let mut wake = waiting.map_or(now, |since| since.min(now)) + STALL;
        if idle.is_some() && shutdown.is_some() {
            wake = wake.min(idle_at);
        }
        tokio::select! {
            _ = connection.as_mut() => return,
            () = sleep_until(wake) => {}
        }
        if let Some(requests) = idle
            && shutdown.is_some()
            && Instant::now() >= idle_at
        {
            let started = requests.load(Ordering::Relaxed);
            if started == seen {
                if let Some(shutdown) = shutdown.take() {
                    shutdown(connection.as_mut());
                }
                stalls.start_draining();
            } else {
                seen = started;
                idle_at = Instant::now() + HTTP2_IDLE;
            }
        }
    }
}

#[cfg(test)]
mod tests;
