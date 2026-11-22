//! Masking admission gate for the TLS/TCP carrier.
//!
//! When `[masking] enabled = true`, every accepted TCP connection must open
//! with a valid 64-byte prelude plus 12-byte nonce (see `uk-mask`). The gate
//! runs *before* the handshake permit is taken and *before* rustls sees any
//! bytes, so a blind prober never reaches certificate signing and never holds
//! handshake budget while being drained.
//!
//! Rejection is silent: no TLS bytes are ever written, remaining input is
//! drained under a bounded budget (4 KiB / 64 reads) until a jittered dwell
//! elapses, and the socket is closed abortively (`SO_LINGER=0`). Every
//! rejection path — short prelude read, bad prelude, replayed prelude —
//! drains for the same uniform distribution, so a prober cannot correlate
//! what it sent with which check failed or when the RST arrives. Prelude and
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

use rand::Rng;
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

/// Samples the silent-drain dwell for a rejected connection: uniformly in
/// `[1/2, 1] × admission_timeout`. Every rejection path draws from this same
/// distribution, so neither the rejection reason nor the amount of garbage a
/// prober sent is correlated with when the abortive close arrives. While the
/// global failure governor is in enhanced mode the dwell pins to the full
/// admission timeout — distributed probing earns the maximal posture.
fn rejection_dwell(admission_timeout: Duration, enhanced: bool) -> Duration {
    if enhanced {
        return admission_timeout;
    }
    let timeout_ms = u64::try_from(admission_timeout.as_millis()).unwrap_or(u64::MAX);
    let min_ms = timeout_ms / 2;
    let max_ms = timeout_ms.max(min_ms + 1);
    Duration::from_millis(rand::thread_rng().gen_range(min_ms..=max_ms))
}

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
        // Every rejection path below drains for the same jittered dwell so
        // the silent treatment is uniform; the governor's enhanced mode pins
        // it to the full admission timeout.
        let dwell = rejection_dwell(admission_timeout, limiter.enhanced_mode_active());
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
                        drain_budget: dwell,
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
                        drain_budget: dwell,
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
                        drain_budget: dwell,
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
        let failure_reason = match kind {
            RejectKind::Prelude => {
                rejection.metrics.record_mask_prelude_reject();
                HandshakeFailureReason::Auth
            }
            RejectKind::Replay => {
                rejection.metrics.record_mask_replay_reject();
                HandshakeFailureReason::Replay
            }
        };
        rejection.metrics.record_failed_handshake(failure_reason);
        if rejection.limiter.record_failure(rejection.peer.ip()) {
            tracing::warn!(
                event = "server.auth_rate_limit.banned_after_failure",
                peer = %rejection.peer,
                "IP temporarily banned after repeated masking rejections"
            );
        }
        silent_drain(rejection.tcp, rejection.drain_budget, rejection.shutdown_rx).await;
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
    drain_budget: Duration,
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
    let mut read_done = false;
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
            read = tcp.read(&mut sink), if !read_done => match read {
                Ok(0) | Err(_) => {
                    read_done = true;
                }
                Ok(_) => {
                    reads += 1;
                    if reads >= DRAIN_MAX_READS {
                        read_done = true;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability::{HandshakeFailureReason, ServerMetrics};
    use std::sync::Arc;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn test_poc_finding_08_commit_gate_replay_collision_classified_as_tls() {
        let (_client, server) = tokio::io::duplex(1024);

        // A commit closure simulating duplicate commit collision
        let commit_fn = Box::new(|_id, _ctr| false);
        let mut gate = CommitGate::new(server, (0xbeef, 10), commit_fn);

        // Rustls sends ServerHello (ContentType 22 = Handshake)
        let handshake_record = [22_u8, 3, 3, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let write_res = gate.write_all(&handshake_record).await;

        assert!(write_res.is_err());
        let err = write_res.unwrap_err();
        assert_eq!(err.to_string(), "masking prelude replayed at commit");

        // complete_handshake maps tls accept errors via tls_accept_failure_reason
        let reason = crate::tls_accept_failure_reason(&err);
        let phase_err = crate::phase_error("tls accept", reason, err);
        let classified_reason = crate::handshake_failure_reason(&phase_err);

        // Invariant: Replay collision should be classified as HandshakeFailureReason::Replay
        assert_eq!(
            classified_reason,
            HandshakeFailureReason::Replay,
            "CommitGate replay race must be classified as Replay error!"
        );
    }

    #[tokio::test]
    async fn test_poc_finding_09_masking_phase1_replay_merged_into_auth_metric() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        drop(client); // Ensure silent_drain sees EOF and exits quickly

        let metrics = Arc::new(ServerMetrics::default());
        let limiter = AuthRateLimiter::new(crate::rate_limit::AuthRateLimitConfig::default());
        let (_tx, shutdown_rx) = watch::channel(false);
        let state = MaskingState::new(16, None);

        let rejection = Rejection {
            tcp: server,
            metrics: &metrics,
            limiter: &limiter,
            peer: addr,
            drain_budget: Duration::from_millis(1),
            shutdown_rx,
        };

        // Directly invoke MaskingState::reject with RejectKind::Replay
        let rejected = state
            .reject(rejection, RejectKind::Replay, "prelude replayed")
            .await;
        assert_eq!(rejected.reason, "prelude replayed");

        let rendered = metrics.render();
        // Invariant: Replay failure must increment handshake_failures_replay
        assert!(
            rendered
                .contains("uncrowned_king_server_handshake_failures_total{reason=\"replay\"} 1\n"),
            "Replay failure bucket must be incremented on replay rejection"
        );
        assert!(
            rendered
                .contains("uncrowned_king_server_handshake_failures_total{reason=\"auth\"} 0\n"),
            "Auth failure bucket must remain 0 on replay rejection"
        );
    }

    #[tokio::test]
    async fn test_poc_finding_10_silent_drain_early_return_on_eof() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let budget = Duration::from_millis(100);
            let (_tx, rx) = tokio::sync::watch::channel(false);
            silent_drain(stream, budget, rx).await;
        });

        let start = std::time::Instant::now();
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        client.write_all(&[0x42; 64]).await.unwrap();
        client.shutdown().await.unwrap(); // Sends FIN (EOF)

        server.await.unwrap();
        let elapsed = start.elapsed();

        // Invariant: Server must dwell for the full duration (budget = 100ms) even on EOF.
        assert!(
            elapsed >= Duration::from_millis(80),
            "silent_drain must dwell until deadline, elapsed was {elapsed:?}"
        );
    }
}
