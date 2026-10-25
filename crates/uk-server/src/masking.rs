//! Masking admission gate for the TLS/TCP carrier.
//!
//! When `[masking] enabled = true`, every accepted TCP connection must open
//! with a valid 64-byte prelude plus 12-byte nonce (see `uk-mask`). The gate
//! runs *before* the handshake permit is taken and *before* rustls sees any
//! bytes, so a blind prober never reaches certificate signing and never holds
//! handshake budget while being drained.
//!
//! Rejection is silent: no TLS bytes are ever written, remaining input is
//! drained under a bounded budget (4 KiB / 64 reads) until the admission
//! deadline, and the socket is closed abortively (`SO_LINGER=0`). Prelude and
//! replay rejections count as authentication failures in the
//! `auth_rate_limit_*` limiter, so blind probing degrades exactly like
//! password guessing does on the unmasked listener.
//!
//! Replay state is committed in two phases (Phase 1b): the prelude is only
//! *prechecked* at admission, and the counter commits on the [`CommitGate`]
//! just before the first non-alert TLS record is flushed — which rustls only
//! produces after a ClientHello parsed successfully. A malformed ClientHello
//! from a *valid* credential holder therefore never burns its counter. If a
//! duplicate commits first (a race), the losing side is aborted before any
//! response byte reaches the wire.

use std::{
    error, fmt, io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use socket2::SockRef;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf},
    net::TcpStream,
    sync::watch,
    time,
};
use uk_mask::{
    MaskKeys, MaskedStream, NONCE_LEN, PRELUDE_LEN, ReplayDecision, ReplayRegistry, verify_prelude,
};

use crate::observability::{HandshakeFailureReason, ServerMetrics};
use crate::rate_limit::AuthRateLimiter;

/// Drain budget in bytes and reads for a rejected connection.
const DRAIN_READ_BYTES: usize = 4096;
const DRAIN_MAX_READS: usize = 64;

/// Terminal error for a rejected masked connection. Carries no detail beyond
/// a static reason: rejection responses must be indistinguishable.
#[derive(Debug)]
pub(crate) struct MaskRejected {
    reason: &'static str,
}

impl fmt::Display for MaskRejected {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason)
    }
}

impl error::Error for MaskRejected {}

/// Server-wide masking admission state: the prelude replay registry and the
/// QUIC endpoint's designated masking keys.
pub(crate) struct MaskingState {
    registry: Arc<std::sync::Mutex<ReplayRegistry>>,
    /// Keys masking the QUIC endpoint, when `masking.quic` is enabled. The
    /// endpoint carries no per-packet credential authentication, so exactly
    /// one designated credential masks it; pinned at startup (a change
    /// requires a restart, enforced by the reload compatibility check).
    quic_keys: Option<Arc<MaskKeys>>,
}

impl MaskingState {
    pub(crate) fn new(capacity: usize, quic_keys: Option<MaskKeys>) -> Self {
        Self {
            registry: Arc::new(std::sync::Mutex::new(ReplayRegistry::new(capacity))),
            quic_keys: quic_keys.map(Arc::new),
        }
    }

    /// The QUIC endpoint's masking keys, when configured.
    pub(crate) fn quic_keys(&self) -> Option<&Arc<MaskKeys>> {
        self.quic_keys.as_ref()
    }

    /// Reads and verifies the masking prelude and returns the wrapped stream
    /// for the TLS acceptor. Replay state is only prechecked here; the
    /// counter commits via [`CommitGate`] on the first non-alert TLS write.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn admit(
        &self,
        tcp: TcpStream,
        mask_keys: &[MaskKeys],
        metrics: &Arc<ServerMetrics>,
        limiter: &AuthRateLimiter,
        peer: SocketAddr,
        admission_timeout: Duration,
        shutdown_rx: watch::Receiver<bool>,
    ) -> Result<CommitGate<MaskedStream<TcpStream>>, MaskRejected> {
        let mut tcp = tcp;
        // The prelude read gets its own slice of the handshake deadline; a
        // peer that tricks us into TLS still runs under the caller's
        // handshake timeout afterwards.
        let mut wire = [0_u8; PRELUDE_LEN + NONCE_LEN];
        let read = time::timeout(admission_timeout, tcp.read_exact(&mut wire)).await;
        let read = match read {
            Ok(Ok(_)) => true,
            Ok(Err(_)) | Err(_) => false,
        };
        if !read {
            return Err(self
                .reject(
                    Rejection {
                        tcp,
                        metrics,
                        limiter,
                        peer,
                        drain_budget: None,
                        shutdown_rx,
                    },
                    RejectKind::Prelude,
                    "masking prelude read failed",
                )
                .await);
        }
        let (prelude, nonce) = wire.split_at(PRELUDE_LEN);
        let prelude: [u8; PRELUDE_LEN] = prelude.try_into().expect("split at PRELUDE_LEN");
        let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("split at NONCE_LEN");
        let Some((keys, authenticated)) = verify_prelude(mask_keys, &prelude, &nonce) else {
            return Err(self
                .reject(
                    Rejection {
                        tcp,
                        metrics,
                        limiter,
                        peer,
                        drain_budget: Some(admission_timeout),
                        shutdown_rx,
                    },
                    RejectKind::Prelude,
                    "masking prelude rejected",
                )
                .await);
        };
        let precheck_passed = match self.registry.lock() {
            Ok(guard) => matches!(
                guard.precheck(authenticated.identity, authenticated.counter),
                ReplayDecision::Accepted
            ),
            // A poisoned registry fails closed.
            Err(_) => false,
        };
        if !precheck_passed {
            return Err(self
                .reject(
                    Rejection {
                        tcp,
                        metrics,
                        limiter,
                        peer,
                        drain_budget: Some(admission_timeout),
                        shutdown_rx,
                    },
                    RejectKind::Replay,
                    "masking prelude replayed",
                )
                .await);
        }
        // Phase 1b deferred commit: fires on the first non-alert record write.
        let registry = Arc::clone(&self.registry);
        let identity = authenticated.identity;
        let counter = authenticated.counter;
        let commit = move |identity: u64, counter: u64| match registry.lock() {
            Ok(mut registry) => {
                matches!(registry.commit(identity, counter), ReplayDecision::Accepted)
            }
            Err(_) => false,
        };
        Ok(CommitGate::new(
            MaskedStream::new_server(tcp, keys, &nonce),
            (identity, counter),
            Box::new(commit),
        ))
    }

    /// Records the failure (metrics + limiter) and silently drains the
    /// rejected connection until its deadline budget, then drops it with an
    /// abortive close.
    async fn reject(
        &self,
        rejection: Rejection<'_>,
        kind: RejectKind,
        reason: &'static str,
    ) -> MaskRejected {
        match kind {
            RejectKind::Prelude => rejection.metrics.record_mask_prelude_reject(),
            RejectKind::Replay => rejection.metrics.record_mask_replay_reject(),
        }
        rejection
            .metrics
            .record_failed_handshake(HandshakeFailureReason::Auth);
        if rejection.limiter.record_failure(rejection.peer.ip()) {
            tracing::warn!(
                event = "server.auth_rate_limit.banned_after_failure",
                peer = %rejection.peer,
                "IP temporarily banned after repeated masking rejections"
            );
        }
        if let Some(budget) = rejection.drain_budget {
            silent_drain(rejection.tcp, budget, rejection.shutdown_rx).await;
        }
        MaskRejected { reason }
    }
}

enum RejectKind {
    Prelude,
    Replay,
}

/// Everything a rejection needs to record and drain one connection.
struct Rejection<'a> {
    tcp: TcpStream,
    metrics: &'a Arc<ServerMetrics>,
    limiter: &'a AuthRateLimiter,
    peer: SocketAddr,
    drain_budget: Option<Duration>,
    shutdown_rx: watch::Receiver<bool>,
}

/// Discards remaining input under a bounded budget, then closes abortively.
/// `SO_LINGER=0` is set up front so the close is a RST even when the runtime
/// drops this future mid-drain (admission deadline, server shutdown).
async fn silent_drain(tcp: TcpStream, budget: Duration, mut shutdown_rx: watch::Receiver<bool>) {
    let mut tcp = tcp;
    let _ = SockRef::from(&tcp).set_linger(Some(Duration::ZERO));
    let deadline = time::Instant::now() + budget;
    let mut sink = [0_u8; DRAIN_READ_BYTES];
    let mut reads = 0_usize;
    loop {
        if *shutdown_rx.borrow() {
            return;
        }
        tokio::select! {
            changed = shutdown_rx.changed() => {
                let _ = changed;
                let _ = shutdown_rx.borrow_and_update();
                return;
            }
            read = tcp.read(&mut sink) => match read {
                Ok(0) | Err(_) => return,
                Ok(_) => {
                    reads += 1;
                    if reads >= DRAIN_MAX_READS {
                        return;
                    }
                }
            },
            () = time::sleep_until(deadline) => return,
        }
    }
}

/// TLS record content type byte for alerts.
const TLS_ALERT_CONTENT_TYPE: u8 = 21;

type CommitFn = Box<dyn Fn(u64, u64) -> bool + Send + Sync>;

/// Defers the replay commit until rustls is about to flush its first
/// non-alert record — the ServerHello flight, which only exists after a
/// ClientHello parsed successfully. Alert records (content type 21) and
/// read-side failures never commit, so a valid credential holder cannot burn
/// its counter with a malformed hello. If a racing duplicate commits first,
/// the write fails closed and the connection is torn down.
pub(crate) struct CommitGate<S> {
    inner: S,
    pending: Option<(u64, u64)>,
    commit: CommitFn,
}

impl<S> CommitGate<S> {
    fn new(inner: S, pending: (u64, u64), commit: CommitFn) -> Self {
        Self {
            inner,
            pending: Some(pending),
            commit,
        }
    }
}

impl<S> std::fmt::Debug for CommitGate<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommitGate")
            .field("pending", &self.pending.is_some())
            .finish_non_exhaustive()
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CommitGate<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CommitGate<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Some((identity, counter)) = this.pending {
            if buf.is_empty() || buf[0] == TLS_ALERT_CONTENT_TYPE {
                // Alerts (and empty writes) carry no handshake progress:
                // keep the commit pending for the next non-alert record.
                return Pin::new(&mut this.inner).poll_write(cx, buf);
            }
            this.pending = None;
            if !(this.commit)(identity, counter) {
                // A racing duplicate committed first: abort before any
                // response byte reaches the wire.
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "masking prelude replayed at commit",
                )));
            }
        }
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
