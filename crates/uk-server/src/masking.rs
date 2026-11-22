//! Masking admission gate for the TLS/TCP carrier.
//!
//! When `[masking] enabled = true`, every accepted TCP connection sets
//! `SO_LINGER=0` immediately upon accept and opens with a valid 64-byte
//! prelude plus 12-byte nonce (see `uk-mask`). The gate runs *before*
//! `handshake_permits` is taken and *before* TLS `ServerHello` / certificate
//! signing, so a blind prober never holds handshake budget and receives zero
//! response bytes.
//!
//! Rejection is silent: [`prehello_accept`] drives `rustls::server::Acceptor`
//! with an explicit 64 KiB (`65_536` byte) cumulative buffer cap and drops any
//! TLS alert without writing to the socket. Remaining input is drained under
//! a bounded budget (4 KiB / 64 reads) until a jittered dwell (clamped to the
//! single shared admission deadline) elapses, and the socket closes abortively
//! (`SO_LINGER=0` RST). Prelude, replay, and pre-`ClientHello` TLS failures
//! count as failures in `AuthRateLimiter`.
//!
//! Replay state is committed in two phases: the prelude is only *prechecked*
//! at admission, `prehello_accept` must parse a complete valid `ClientHello`
//! and `Accepted::into_connection` (plus ALPN presence) must validate it
//! against `ServerConfig` first, and only then does `(identity, counter)`
//! commit atomically to `ReplayRegistry` before `MaskedTlsStream` writes
//! `ServerHello`. Normal close semantics are restored by
//! [`finish_authentication`] only after application-layer `AUTH_RESPONSE`
//! succeeds and strictly before the shared deadline.

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
    io::{AsyncRead, AsyncReadExt, ReadBuf},
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

/// Maximum per-read chunk passed to `rustls::server::Acceptor::read_tls`.
const PREHELLO_READ_CHUNK: usize = 4096;

/// Explicit cumulative 64 KiB cap on pre-`ClientHello` TLS buffering.
const PREHELLO_BUFFER_MAX: usize = 64 * 1024;

/// Sets `SO_LINGER=0` so closing the socket emits a TCP RST rather than FIN.
pub(crate) fn set_zero_linger(stream: &TcpStream) -> io::Result<()> {
    SockRef::from(stream).set_linger(Some(Duration::ZERO))
}

/// Restores normal TCP close semantics after application authentication
/// succeeds and strictly before `deadline`. Re-arms `SO_LINGER=0` if
/// `deadline` expires during the `setsockopt` window.
pub(crate) fn finish_authentication(
    stream: &TcpStream,
    deadline: time::Instant,
) -> io::Result<bool> {
    if time::Instant::now() >= deadline {
        return Ok(false);
    }
    SockRef::from(stream).set_linger(None)?;
    if time::Instant::now() >= deadline {
        set_zero_linger(stream)?;
        return Ok(false);
    }
    Ok(true)
}

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

/// Authenticated masked TCP stream plus validated TLS server connection.
pub(crate) struct AdmittedTcp {
    pub(crate) stream: MaskedStream<TcpStream>,
    pub(crate) connection: rustls::ServerConnection,
}

/// Server-wide masking admission state: the optional TCP prelude replay
/// registry and the QUIC endpoint's designated masking keys.
pub(crate) struct MaskingState {
    registry: Option<Arc<std::sync::Mutex<ReplayRegistry>>>,
    /// Keys masking the QUIC endpoint, when `masking.quic` is enabled. The
    /// endpoint carries no per-packet credential authentication, so exactly
    /// one designated credential masks it; pinned at startup (a change
    /// requires a restart, enforced by the reload compatibility check).
    quic_keys: Option<Arc<MaskKeys>>,
}

impl MaskingState {
    pub(crate) fn new(tcp_capacity: Option<usize>, quic_keys: Option<MaskKeys>) -> Self {
        Self {
            registry: tcp_capacity
                .map(|capacity| Arc::new(std::sync::Mutex::new(ReplayRegistry::new(capacity)))),
            quic_keys: quic_keys.map(Arc::new),
        }
    }

    /// Whether TLS/TCP masking admission is enabled.
    pub(crate) fn tcp_enabled(&self) -> bool {
        self.registry.is_some()
    }

    /// The QUIC endpoint's masking keys, when configured.
    pub(crate) fn quic_keys(&self) -> Option<&Arc<MaskKeys>> {
        self.quic_keys.as_ref()
    }

    /// Reads and verifies the masking prelude, prechecks replay state, parses
    /// the `ClientHello` silently via `rustls::server::Acceptor` (capped at
    /// 64 KiB, emitting zero bytes on failure), validates ALPN presence and
    /// `ServerConfig` compatibility via `Accepted::into_connection` without
    /// writing alert bytes, and atomically commits the replay counter strictly
    /// after a valid `ServerConnection` is created.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn admit_prehello(
        &self,
        tcp: TcpStream,
        mask_keys: &[MaskKeys],
        tls_config: Arc<rustls::ServerConfig>,
        metrics: &Arc<ServerMetrics>,
        limiter: &AuthRateLimiter,
        peer: SocketAddr,
        accepted_at: time::Instant,
        admission_timeout: Duration,
        deadline: time::Instant,
        shutdown_rx: watch::Receiver<bool>,
    ) -> Result<AdmittedTcp, MaskRejected> {
        self.admit_prehello_inner(
            tcp,
            mask_keys,
            tls_config,
            metrics,
            limiter,
            peer,
            accepted_at,
            admission_timeout,
            deadline,
            shutdown_rx,
            |d| d,
            || {},
        )
        .await
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn admit_prehello_inner<D, F>(
        &self,
        tcp: TcpStream,
        mask_keys: &[MaskKeys],
        tls_config: Arc<rustls::ServerConfig>,
        metrics: &Arc<ServerMetrics>,
        limiter: &AuthRateLimiter,
        peer: SocketAddr,
        accepted_at: time::Instant,
        admission_timeout: Duration,
        deadline: time::Instant,
        shutdown_rx: watch::Receiver<bool>,
        post_accept_deadline: D,
        before_commit: F,
    ) -> Result<AdmittedTcp, MaskRejected>
    where
        D: FnOnce(time::Instant) -> time::Instant,
        F: FnOnce(),
    {
        let mut tcp = tcp;
        let Some(registry) = &self.registry else {
            return Err(self
                .reject(
                    Rejection {
                        tcp,
                        metrics,
                        limiter,
                        peer,
                        drain_deadline: accepted_at,
                        shutdown_rx,
                    },
                    RejectKind::Prelude,
                    "tcp masking is not active",
                )
                .await);
        };

        // Every rejection path below drains under the same uniform distribution
        // clamped to the shared absolute deadline; the governor's enhanced mode
        // pins dwell to the full admission timeout.
        let dwell = rejection_dwell(admission_timeout, limiter.enhanced_mode_active());
        let drain_deadline = (accepted_at + dwell).min(deadline);

        if time::Instant::now() >= deadline {
            return Err(self
                .reject(
                    Rejection {
                        tcp,
                        metrics,
                        limiter,
                        peer,
                        drain_deadline,
                        shutdown_rx,
                    },
                    RejectKind::Timeout,
                    "masking admission deadline exceeded",
                )
                .await);
        }

        let mut wire = [0_u8; PRELUDE_LEN + NONCE_LEN];
        let read = time::timeout_at(deadline, tcp.read_exact(&mut wire)).await;
        let read_ok = matches!(read, Ok(Ok(_)));
        if !read_ok {
            return Err(self
                .reject(
                    Rejection {
                        tcp,
                        metrics,
                        limiter,
                        peer,
                        drain_deadline,
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
                        drain_deadline,
                        shutdown_rx,
                    },
                    RejectKind::Prelude,
                    "masking prelude rejected",
                )
                .await);
        };

        let precheck_passed = match registry.lock() {
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
                        drain_deadline,
                        shutdown_rx,
                    },
                    RejectKind::Replay,
                    "masking prelude replayed",
                )
                .await);
        }

        let mut masked = MaskedStream::new_server(tcp, keys, &nonce);
        let accepted = match time::timeout_at(deadline, prehello_accept(&mut masked)).await {
            Ok(Ok(Some(accepted))) => accepted,
            Ok(Ok(None) | Err(_)) => {
                let tcp = masked.into_inner();
                return Err(self
                    .reject(
                        Rejection {
                            tcp,
                            metrics,
                            limiter,
                            peer,
                            drain_deadline,
                            shutdown_rx,
                        },
                        RejectKind::ClientHello,
                        "masking client hello rejected",
                    )
                    .await);
            }
            Err(_) => {
                let tcp = masked.into_inner();
                return Err(self
                    .reject(
                        Rejection {
                            tcp,
                            metrics,
                            limiter,
                            peer,
                            drain_deadline,
                            shutdown_rx,
                        },
                        RejectKind::Timeout,
                        "masking client hello timed out",
                    )
                    .await);
            }
        };

        if !tls_config.alpn_protocols.is_empty() && accepted.client_hello().alpn().is_none() {
            let tcp = masked.into_inner();
            return Err(self
                .reject(
                    Rejection {
                        tcp,
                        metrics,
                        limiter,
                        peer,
                        drain_deadline,
                        shutdown_rx,
                    },
                    RejectKind::ClientHello,
                    "masking client hello missing alpn",
                )
                .await);
        }

        let connection = match accepted.into_connection(tls_config) {
            Ok(connection) => connection,
            Err((_err, _alert)) => {
                // Drop `_alert` without writing any bytes to `masked`.
                let tcp = masked.into_inner();
                return Err(self
                    .reject(
                        Rejection {
                            tcp,
                            metrics,
                            limiter,
                            peer,
                            drain_deadline,
                            shutdown_rx,
                        },
                        RejectKind::ClientHello,
                        "masking client hello rejected by server tls config",
                    )
                    .await);
            }
        };

        let deadline = post_accept_deadline(deadline);
        if time::Instant::now() >= deadline {
            let tcp = masked.into_inner();
            return Err(self
                .reject(
                    Rejection {
                        tcp,
                        metrics,
                        limiter,
                        peer,
                        drain_deadline,
                        shutdown_rx,
                    },
                    RejectKind::Timeout,
                    "masking admission deadline exceeded",
                )
                .await);
        }

        before_commit();

        let committed = match registry.lock() {
            Ok(mut guard) => matches!(
                guard.commit(authenticated.identity, authenticated.counter),
                ReplayDecision::Accepted
            ),
            Err(_) => false,
        };
        if !committed {
            let tcp = masked.into_inner();
            return Err(self
                .reject(
                    Rejection {
                        tcp,
                        metrics,
                        limiter,
                        peer,
                        drain_deadline,
                        shutdown_rx,
                    },
                    RejectKind::Replay,
                    "masking prelude replayed",
                )
                .await);
        }

        Ok(AdmittedTcp {
            stream: masked,
            connection,
        })
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
            RejectKind::ClientHello => HandshakeFailureReason::Tls,
            RejectKind::Timeout => HandshakeFailureReason::Timeout,
        };
        rejection.metrics.record_failed_handshake(failure_reason);
        if rejection.limiter.record_failure(rejection.peer.ip()) {
            tracing::warn!(
                event = "server.auth_rate_limit.banned_after_failure",
                peer = %rejection.peer,
                "IP temporarily banned after repeated masking rejections"
            );
        }
        silent_drain_until(
            rejection.tcp,
            rejection.drain_deadline,
            rejection.shutdown_rx,
        )
        .await;
        MaskRejected { reason }
    }
}

struct PrehelloReader<'a, 'b, R> {
    stream: &'a mut R,
    cx: &'a mut Context<'b>,
    remaining_cap: usize,
}

impl<R: AsyncRead + Unpin> io::Read for PrehelloReader<'_, '_, R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let len = bytes.len().min(PREHELLO_READ_CHUNK).min(self.remaining_cap);
        let mut buffer = ReadBuf::new(&mut bytes[..len]);
        match Pin::new(&mut self.stream).poll_read(self.cx, &mut buffer) {
            Poll::Ready(Ok(())) => Ok(buffer.filled().len()),
            Poll::Ready(Err(error)) => Err(error),
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

/// Reads and parses a `ClientHello` via `rustls::server::Acceptor` with an
/// explicit 64 KiB cumulative cap. Returns `Ok(None)` on EOF, buffer overflow,
/// `InvalidData`, or TLS alert without emitting any response bytes.
async fn prehello_accept<R: AsyncRead + Unpin>(
    stream: &mut R,
) -> io::Result<Option<rustls::server::Accepted>> {
    let mut acceptor = rustls::server::Acceptor::default();
    let mut buffered = 0_usize;
    loop {
        if buffered >= PREHELLO_BUFFER_MAX {
            return Ok(None);
        }
        let remaining_cap = PREHELLO_BUFFER_MAX - buffered;
        let read = std::future::poll_fn(|cx| {
            match acceptor.read_tls(&mut PrehelloReader {
                stream,
                cx,
                remaining_cap,
            }) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
                result => Poll::Ready(result),
            }
        })
        .await;
        match read {
            Ok(0) => return Ok(None),
            Err(error) if error.kind() == io::ErrorKind::InvalidData => return Ok(None),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
            Ok(count) => {
                buffered = buffered.saturating_add(count);
                if buffered > PREHELLO_BUFFER_MAX {
                    return Ok(None);
                }
                match acceptor.accept() {
                    Ok(Some(accepted)) => return Ok(Some(accepted)),
                    Ok(None) if buffered >= PREHELLO_BUFFER_MAX => return Ok(None),
                    Ok(None) => {}
                    Err((_error, _alert)) => return Ok(None),
                }
            }
        }
        tokio::task::yield_now().await;
    }
}

enum RejectKind {
    Prelude,
    Replay,
    ClientHello,
    Timeout,
}

/// Everything a rejection needs to record and drain one connection.
struct Rejection<'a> {
    tcp: TcpStream,
    metrics: &'a Arc<ServerMetrics>,
    limiter: &'a AuthRateLimiter,
    peer: SocketAddr,
    drain_deadline: time::Instant,
    shutdown_rx: watch::Receiver<bool>,
}

/// Discards remaining input under a bounded budget until `deadline`, then
/// closes abortively (`SO_LINGER=0` RST).
async fn silent_drain_until(
    tcp: TcpStream,
    deadline: time::Instant,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut tcp = tcp;
    let _ = set_zero_linger(&tcp);
    let mut sink = [0_u8; DRAIN_READ_BYTES];
    let mut reads = 0_usize;
    let mut read_done = false;
    loop {
        if *shutdown_rx.borrow() || time::Instant::now() >= deadline {
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

#[cfg(test)]
async fn silent_drain(tcp: TcpStream, budget: Duration, shutdown_rx: watch::Receiver<bool>) {
    silent_drain_until(tcp, time::Instant::now() + budget, shutdown_rx).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability::ServerMetrics;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::io::AsyncWriteExt;
    use tokio_rustls::TlsAcceptor;
    use uk_mask::PreludePolicy;

    struct CountingStream {
        inner: tokio::io::DuplexStream,
        bytes_read: Arc<AtomicUsize>,
    }

    impl AsyncRead for CountingStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let before = buf.filled().len();
            let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
            if let Poll::Ready(Ok(())) = &poll {
                let delta = buf.filled().len().saturating_sub(before);
                self.bytes_read.fetch_add(delta, Ordering::Relaxed);
            }
            poll
        }
    }

    const TEST_CERT: &str = r"-----BEGIN CERTIFICATE-----
MIIDSTCCAjGgAwIBAgIUEX51v2igsFngMQTuqhBx+gKL2MswDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDcwMzEzNTM0MVoXDTM2MDYz
MDEzNTM0MVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAhf3zqFeac7mRJTkyoPMwXUtvgnKcY3ydON4Q3cMrxrd0
qn2leXJObMP846YgGBtKYu3cDo01qK+cN1rY4l/3iNqa4VOYJ3ckmUTEQhmCG78i
XIxR9+488rWsxrhJ4GtGj/jd7UaJM9RMs2bb+7KzSj8t6t+Q1MEKsPeqQZ1wBW9S
wgYLMmrP5eNYFgEgt8KI2r/p+Lf2rbGqu/OdzWkekDbuJq+wqUsEtEnE4x5ELJEE
axEv+savJVWGSvBUkU6sWU8s0iLNiQKMBjAd/vTbqD+NVGihNrE0S0o0S4oxtHhu
wwPbfk3bkGV2Z5QwTMI48AhrcoELMuQjO9wZygLHKQIDAQABo4GSMIGPMB0GA1Ud
DgQWBBT8yAuXKconl4iNVuGmhUJIuVZW5zAfBgNVHSMEGDAWgBT8yAuXKconl4iN
VuGmhUJIuVZW5zAaBgNVHREEEzARgglsb2NhbGhvc3SHBH8AAAEwDAYDVR0TAQH/
BAIwADAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDQYJKoZI
hvcNAQELBQADggEBAESMmK/ln9SXy8uevLxfdf0oKE4UC9CyyMj2FPOWSnpvwLJ4
KI5axpyV3uP4Afd/lH6W47OcvQ9Ah0hSEVY/Xi+sAfLdjPmp3YpTtHP605Bj0y+A
O2F21JkBh/ZVA2SbI9MCg13XBPfrmqarPxIVlye4kxbD4ZDN5Zp0DLjoIIWWGv2n
6MuVnlvftL6nyPvc8EyPLM6wxiisxlB/D7jx9tL+GuLHcvXDuxQIkjB7MMWWfERM
hpwf7QVVYCCnRNdlxk/xa6pr54CMysA75BlDBaVjyqK8Uy74DHL7APCN9opoV5ws
vX1BONgh2gSRGBFiii6imzEAwefkUtYAvAQy1xw=
-----END CERTIFICATE-----
";

    const TEST_KEY: &str = r"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCF/fOoV5pzuZEl
OTKg8zBdS2+CcpxjfJ043hDdwyvGt3SqfaV5ck5sw/zjpiAYG0pi7dwOjTWor5w3
WtjiX/eI2prhU5gndySZRMRCGYIbvyJcjFH37jzytazGuEnga0aP+N3tRokz1Eyz
Ztv7srNKPy3q35DUwQqw96pBnXAFb1LCBgsyas/l41gWASC3wojav+n4t/atsaq7
853NaR6QNu4mr7CpSwS0ScTjHkQskQRrES/6xq8lVYZK8FSRTqxZTyzSIs2JAowG
MB3+9NuoP41UaKE2sTRLSjRLijG0eG7DA9t+TduQZXZnlDBMwjjwCGtygQsy5CM7
3BnKAscpAgMBAAECggEAPjqsP+G3rMlhHJ2M4u0u6BVRy465DQdh6XhQ8v1ixl6L
g2bpRBcPTzpSp9OOkkOSb5Gyott4MUilz5uUoMYbK2cDiWSOhL2ztK8YSu6X25UQ
O1U7+F6f1cUEYiJSxTRtSA4326vnqreNi8BYqHPdCr1+8Nc152lkMr5DR0f8L7lQ
8v7nLryHxGyKZb6Pu75m8Fm8hV4OGG6n1e4jo83+arS3LAppRZVukQkjShHD9+ol
lPKcYsc9hbqojE8gXyOk4xyvlqxdxXuq/tDpfxMxfH5jbsIqnYZ4NDBGOWtT4Hzh
q+pMcRj3iPwbvTybPUTNJHDB8MyqG/hRRvC58NeLpQKBgQC8OV8fG7Za+6FiBQel
2IVYyBEAwpqchyhvKPNUnGz+0h5dJ2q2ANWcLwU56/1U6dpPLNJj42Sjq97fUdX9
156JmFUMT2YKY3ffsR31WFvA91FXRSAkR/g8uXLAEKIr0mYsRB7yopY31f/QWH25
RvD+UTUf1r0g7m+3T7ezyXrrLwKBgQC2PW1MWFhnjPiArJVYXkiC6+3O4nkAPByl
lm7VNw+AKquJu3TgSCHNsuHQXqG2WOisJndfvWyOScOke9W+KvCFNFfo/OV71SW9
Rqn61Cl87p3SOwGF15eR62EPVicaAwBvlnhOX5zA1p5MPs7M/8cqi5ld6gOx8XhW
xF4OOv19JwKBgQCX7idd0NytLBfkKvM1Z0SbmUJAPtTWLDLzJzbiwTEprylbQAne
x2WlID8ztc1S0UCqUB+zCUWe54iK8l+s+nK51gAwY5aWJBwKr8ji1WOaqwc5Tk7X
elBhk7+QUNzWSoq2iHYCnEJs54wJ/KPe/ehhH+Olw4v+HPiIGwzJToSteQKBgFiJ
v3A3+7tTYegh8Ozd4Zy5wu+gV+klS0WnsHEmLwG1uWFREZdldAbbwZnaX/aXe3Mn
vRdmkDcQ31wqTc32TqRoqc0oENX42Dz899hE+2MXCtX4lOTRuXHLSXyJ/rVEgBG2
qPxqt114569jVFWEbt7cs8ZMyz7Icg61mHyRbFZBAoGBAKiV5tDUJewK9oZluSsV
jiIVN0rJ1/EWIoJClBZEQ+uZHiAbwEevcPjJD6Pp9xFjfujebQDLep3RKIMuyi7o
s1BW++ZOOL/nM71C5A1D2kYi9etevjp2qg/P2FOhhKSBAM+oyy6KR2HR3OnRpBfF
VODOlcdwgEkE3j5MxS0brpI9
-----END PRIVATE KEY-----
";

    fn test_server_config() -> Arc<rustls::ServerConfig> {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
        let certs = CertificateDer::pem_slice_iter(TEST_CERT.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = PrivateKeyDer::from_pem_slice(TEST_KEY.as_bytes()).unwrap();
        Arc::new(crate::tls::server_config_from_memory(certs, key).unwrap())
    }

    fn test_client_hello_bytes_with(
        versions: &[&'static rustls::SupportedProtocolVersion],
        alpn_protocols: Vec<Vec<u8>>,
    ) -> Vec<u8> {
        let root_store = rustls::RootCertStore::empty();
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(versions)
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();
        config.alpn_protocols = alpn_protocols;
        let mut conn = rustls::ClientConnection::new(
            Arc::new(config),
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        let mut out = Vec::new();
        conn.write_tls(&mut out).unwrap();
        out
    }

    fn test_client_hello_bytes() -> Vec<u8> {
        test_client_hello_bytes_with(
            &[&rustls::version::TLS13],
            vec![uk_proto::ALPN_PROTOCOL.to_vec()],
        )
    }

    #[tokio::test]
    async fn admit_prehello_commit_collision_records_replay_and_emits_zero_bytes() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (server, peer) = listener.accept().await.unwrap();
        set_zero_linger(&server).unwrap();

        let keys = MaskKeys::derive(b"k1", b"0123456789abcdef0123456789abcdef");
        let identity = 0x1234_5678_9abc_def0;
        let counter = 5;
        let prelude = keys
            .encode_prelude(
                PreludePolicy::Full8,
                &mut rand::rngs::OsRng,
                identity,
                counter,
            )
            .unwrap();

        let mut wire = Vec::with_capacity(PRELUDE_LEN + NONCE_LEN);
        wire.extend_from_slice(&prelude.bytes);
        wire.extend_from_slice(&prelude.nonce);
        client.write_all(&wire).await.unwrap();

        let hello = test_client_hello_bytes();
        let mut masked_client = MaskedStream::new_client(client, &keys, &prelude.nonce);
        masked_client.write_all(&hello).await.unwrap();
        masked_client.flush().await.unwrap();

        let metrics = Arc::new(ServerMetrics::default());
        let limiter = AuthRateLimiter::new(crate::rate_limit::AuthRateLimitConfig {
            max_failures: 1,
            ..Default::default()
        });
        let (_tx, shutdown_rx) = watch::channel(false);
        let state = MaskingState::new(Some(16), None);
        let now = time::Instant::now();
        let deadline = now + Duration::from_secs(2);

        // Simulate a concurrent racer committing the same (identity, counter)
        // between prehello_accept/into_connection and commit.
        let registry_ref = Arc::clone(state.registry.as_ref().unwrap());
        let res = state
            .admit_prehello_inner(
                server,
                &[keys],
                test_server_config(),
                &metrics,
                &limiter,
                peer,
                now,
                Duration::from_millis(20),
                deadline,
                shutdown_rx,
                |d| d,
                move || {
                    let mut guard = registry_ref.lock().unwrap();
                    assert_eq!(guard.commit(identity, counter), ReplayDecision::Accepted);
                },
            )
            .await;

        assert!(res.is_err(), "commit collision must reject connection");
        let mut response = Vec::new();
        let read_res = masked_client.read_to_end(&mut response).await;
        assert!(
            matches!(read_res, Ok(0) | Err(_)) && response.is_empty(),
            "zero bytes may be emitted on commit collision, got {} bytes ({read_res:?})",
            response.len()
        );
        let rendered = metrics.render();
        assert!(
            rendered
                .contains("uncrowned_king_server_handshake_failures_total{reason=\"replay\"} 1\n")
        );
        assert!(rendered.contains("uncrowned_king_server_mask_replay_rejects_total 1\n"));
        assert!(
            rendered
                .contains("uncrowned_king_server_handshake_failures_total{reason=\"auth\"} 0\n")
        );
        assert!(
            !limiter.check(peer.ip()),
            "commit collision must record a failure in AuthRateLimiter"
        );
    }

    #[tokio::test]
    async fn prehello_accept_accepts_fragmented_hello_and_preserves_trailing_record() {
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        let hello = test_client_hello_bytes();
        let trailing = [0x17_u8, 0x03, 0x03, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef];

        let split = hello.len() / 2;
        let first_half = hello[..split].to_vec();
        let second_half = hello[split..].to_vec();

        let writer = tokio::spawn(async move {
            client.write_all(&first_half).await.unwrap();
            client.flush().await.unwrap();
            tokio::task::yield_now().await;
            client.write_all(&second_half).await.unwrap();
            client.write_all(&trailing).await.unwrap();
            client.flush().await.unwrap();
            client
        });

        let accepted = prehello_accept(&mut server)
            .await
            .unwrap()
            .expect("fragmented ClientHello must parse cleanly");
        let _client = writer.await.unwrap();

        let tls_acceptor = TlsAcceptor::from(crate::security::test_tls_acceptor().config().clone());
        // Hand off Accepted + remaining stream (with buffered trailing bytes inside Accepted).
        // StartHandshake::from_parts accepts without needing another ClientHello read.
        let _start = tokio_rustls::StartHandshake::from_parts(accepted, server);
        drop(tls_acceptor);
    }

    #[tokio::test]
    async fn prehello_accept_swallows_alert_invalid_data_and_eof_with_zero_output() {
        // Case 1: garbage TLS record (triggers TLS alert inside Acceptor)
        let (mut client, mut server) = tokio::io::duplex(4096);
        client
            .write_all(&[22_u8, 3, 1, 0, 5, 1, 2, 3, 4, 5])
            .await
            .unwrap();
        let accepted = prehello_accept(&mut server).await.unwrap();
        assert!(
            accepted.is_none(),
            "malformed TLS record must yield Ok(None)"
        );
        drop(server);
        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.unwrap();
        assert!(resp.is_empty(), "Acceptor must emit zero bytes on alert");

        // Case 2: clean EOF mid-ClientHello
        let (mut client, mut server) = tokio::io::duplex(4096);
        let hello = test_client_hello_bytes();
        client.write_all(&hello[..10]).await.unwrap();
        drop(client);
        let accepted = prehello_accept(&mut server).await.unwrap();
        assert!(
            accepted.is_none(),
            "EOF mid-ClientHello must yield Ok(None)"
        );
    }

    #[tokio::test]
    async fn prehello_accept_enforces_64kib_cap_without_reading_byte_65537() {
        let (mut client, server) = tokio::io::duplex(256 * 1024);
        let bytes_read = Arc::new(AtomicUsize::new(0));
        let mut counting = CountingStream {
            inner: server,
            bytes_read: Arc::clone(&bytes_read),
        };

        // Construct five 16,384-byte TLS Handshake records carrying a fragmented
        // 80,000-byte ClientHello handshake message header (`msg_type=1`, `len=80000`).
        let writer = tokio::spawn(async move {
            let mut payload = vec![0_u8; 5 * 16_384];
            payload[0] = 1; // ClientHello
            let total_len: u32 = 80_000;
            payload[1] = ((total_len >> 16) & 0xff) as u8;
            payload[2] = ((total_len >> 8) & 0xff) as u8;
            payload[3] = (total_len & 0xff) as u8;
            for chunk in payload.chunks(16_384) {
                let mut record = Vec::with_capacity(5 + chunk.len());
                record.push(22);
                record.extend_from_slice(&[3, 3]);
                record.extend_from_slice(&(u16::try_from(chunk.len()).unwrap()).to_be_bytes());
                record.extend_from_slice(chunk);
                if client.write_all(&record).await.is_err() {
                    break;
                }
            }
        });

        let result = prehello_accept(&mut counting).await.unwrap();
        assert!(
            result.is_none(),
            "oversized pre-ClientHello stream must be rejected silently"
        );
        let read_total = bytes_read.load(Ordering::Relaxed);
        assert!(
            read_total <= PREHELLO_BUFFER_MAX,
            "prehello_accept must never read past 64 KiB cap (read {read_total})"
        );
        let _ = writer.await;
    }

    #[tokio::test]
    async fn finish_authentication_double_check_preserves_zero_linger_when_expired() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        set_zero_linger(&server).unwrap();
        assert_eq!(
            SockRef::from(&server).linger().unwrap(),
            Some(Duration::ZERO)
        );

        let expired = time::Instant::now() - Duration::from_millis(1);
        assert!(
            !finish_authentication(&server, expired).unwrap(),
            "expired deadline must return Ok(false)"
        );
        assert_eq!(
            SockRef::from(&server).linger().unwrap(),
            Some(Duration::ZERO),
            "SO_LINGER=0 must remain armed when deadline already expired"
        );

        let future = time::Instant::now() + Duration::from_secs(10);
        assert!(
            finish_authentication(&server, future).unwrap(),
            "active deadline must clear SO_LINGER and return Ok(true)"
        );
        assert_eq!(
            SockRef::from(&server).linger().unwrap(),
            None,
            "SO_LINGER must be cleared after successful auth within deadline"
        );
    }

    #[tokio::test]
    async fn admit_prehello_expired_deadline_rejects_immediately_with_zero_linger() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (server, peer) = listener.accept().await.unwrap();
        set_zero_linger(&server).unwrap();

        let keys = MaskKeys::derive(b"k1", b"0123456789abcdef0123456789abcdef");
        let metrics = Arc::new(ServerMetrics::default());
        let limiter = AuthRateLimiter::new(crate::rate_limit::AuthRateLimitConfig {
            max_failures: 1,
            ..Default::default()
        });
        let (_tx, shutdown_rx) = watch::channel(false);
        let state = MaskingState::new(Some(16), None);
        let past = time::Instant::now() - Duration::from_secs(1);

        let res = state
            .admit_prehello(
                server,
                &[keys],
                test_server_config(),
                &metrics,
                &limiter,
                peer,
                past,
                Duration::from_secs(5),
                past,
                shutdown_rx,
            )
            .await;

        assert!(res.is_err());
        let mut buf = [0_u8; 16];
        let read = client.read(&mut buf).await;
        assert!(
            matches!(read, Ok(0) | Err(_)),
            "expired deadline must drop with RST immediately"
        );
        let rendered = metrics.render();
        assert!(
            rendered
                .contains("uncrowned_king_server_handshake_failures_total{reason=\"timeout\"} 1\n")
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
        let limiter = AuthRateLimiter::new(crate::rate_limit::AuthRateLimitConfig {
            max_failures: 1,
            ..Default::default()
        });
        let (_tx, shutdown_rx) = watch::channel(false);
        let state = MaskingState::new(Some(16), None);

        let rejection = Rejection {
            tcp: server,
            metrics: &metrics,
            limiter: &limiter,
            peer: addr,
            drain_deadline: time::Instant::now() + Duration::from_millis(1),
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

    async fn assert_admit_prehello_rejects_silently_without_commit(hello: Vec<u8>, label: &str) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (server, peer) = listener.accept().await.unwrap();
        set_zero_linger(&server).unwrap();

        let keys = MaskKeys::derive(b"k1", b"0123456789abcdef0123456789abcdef");
        let identity = 0xfeed_face_cafe_0001;
        let counter = 7;
        let prelude = keys
            .encode_prelude(
                PreludePolicy::Full8,
                &mut rand::rngs::OsRng,
                identity,
                counter,
            )
            .unwrap();

        let mut wire = Vec::with_capacity(PRELUDE_LEN + NONCE_LEN);
        wire.extend_from_slice(&prelude.bytes);
        wire.extend_from_slice(&prelude.nonce);
        client.write_all(&wire).await.unwrap();

        let mut masked_client = MaskedStream::new_client(client, &keys, &prelude.nonce);
        masked_client.write_all(&hello).await.unwrap();
        masked_client.flush().await.unwrap();

        let metrics = Arc::new(ServerMetrics::default());
        let limiter = AuthRateLimiter::new(crate::rate_limit::AuthRateLimitConfig {
            max_failures: 1,
            ..Default::default()
        });
        let (_tx, shutdown_rx) = watch::channel(false);
        let state = MaskingState::new(Some(16), None);
        let now = time::Instant::now();
        let deadline = now + Duration::from_secs(2);

        let res = state
            .admit_prehello(
                server,
                &[keys],
                test_server_config(),
                &metrics,
                &limiter,
                peer,
                now,
                Duration::from_millis(20),
                deadline,
                shutdown_rx,
            )
            .await;
        assert!(res.is_err(), "{label}: must be rejected at admit_prehello");

        let mut response = Vec::new();
        let read_res = masked_client.read_to_end(&mut response).await;
        assert!(
            matches!(read_res, Ok(0) | Err(_)) && response.is_empty(),
            "{label}: must emit zero wire bytes, got {} bytes ({read_res:?})",
            response.len()
        );

        let precheck = state
            .registry
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .precheck(identity, counter);
        assert_eq!(
            precheck,
            ReplayDecision::Accepted,
            "{label}: replay counter must remain uncommitted"
        );

        let rendered = metrics.render();
        assert!(
            rendered.contains("uncrowned_king_server_handshake_failures_total{reason=\"tls\"} 1\n"),
            "{label}: expected tls failure metric, got:\n{rendered}"
        );
        assert!(
            rendered.contains("uncrowned_king_server_mask_replay_rejects_total 0\n"),
            "{label}: expected 0 replay rejects"
        );
        assert!(
            !limiter.check(peer.ip()),
            "{label}: must record failure in AuthRateLimiter"
        );
    }

    #[tokio::test]
    async fn admit_prehello_rejects_tls12_only_client_hello_silently_without_committing_counter() {
        let hello = test_client_hello_bytes_with(
            &[&rustls::version::TLS12],
            vec![uk_proto::ALPN_PROTOCOL.to_vec()],
        );
        assert_admit_prehello_rejects_silently_without_commit(hello, "tls12_only").await;
    }

    #[tokio::test]
    async fn admit_prehello_rejects_wrong_alpn_client_hello_silently_without_committing_counter() {
        let hello = test_client_hello_bytes_with(&[&rustls::version::TLS13], vec![b"h2".to_vec()]);
        assert_admit_prehello_rejects_silently_without_commit(hello, "wrong_alpn").await;
    }

    #[tokio::test]
    async fn admit_prehello_rejects_missing_alpn_client_hello_silently_without_committing_counter()
    {
        let hello = test_client_hello_bytes_with(&[&rustls::version::TLS13], Vec::new());
        assert_admit_prehello_rejects_silently_without_commit(hello, "missing_alpn").await;
    }

    struct OneByteStream {
        data: Vec<u8>,
        pos: usize,
    }

    impl AsyncRead for OneByteStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.pos < self.data.len() && buf.remaining() > 0 {
                buf.put_slice(&[self.data[self.pos]]);
                self.pos += 1;
            }
            Poll::Ready(Ok(()))
        }
    }

    fn padded_client_hello_wire_bytes(target_wire_bytes: usize) -> Vec<u8> {
        let base = test_client_hello_bytes();
        assert_eq!(base[0], 0x16);
        let mut hs = base[5..].to_vec();
        assert_eq!(hs[0], 0x01);

        let mut pos = 4 + 2 + 32;
        let sid_len = usize::from(hs[pos]);
        pos += 1 + sid_len;
        let cs_len = usize::from(u16::from_be_bytes([hs[pos], hs[pos + 1]]));
        pos += 2 + cs_len;
        let comp_len = usize::from(hs[pos]);
        pos += 1 + comp_len;
        let ext_len_pos = pos;
        let ext_len = usize::from(u16::from_be_bytes([hs[pos], hs[pos + 1]]));

        let num_records = 4_usize;
        let target_hs_len = target_wire_bytes - 5 * num_records;
        let extra = target_hs_len - hs.len();
        assert!(extra >= 4);
        let pad_data_len = extra - 4;
        hs.extend_from_slice(&[0x00, 0x15]);
        hs.extend_from_slice(&u16::try_from(pad_data_len).unwrap().to_be_bytes());
        hs.resize(hs.len() + pad_data_len, 0);

        let new_ext_len = u16::try_from(ext_len + extra).unwrap().to_be_bytes();
        hs[ext_len_pos..ext_len_pos + 2].copy_from_slice(&new_ext_len);
        let hs_body_len = u32::try_from(hs.len() - 4).unwrap();
        hs[1] = ((hs_body_len >> 16) & 0xff) as u8;
        hs[2] = ((hs_body_len >> 8) & 0xff) as u8;
        hs[3] = (hs_body_len & 0xff) as u8;

        let mut wire = Vec::with_capacity(target_wire_bytes);
        for chunk in hs.chunks(16_384) {
            wire.extend_from_slice(&[0x16, 0x03, 0x03]);
            wire.extend_from_slice(&u16::try_from(chunk.len()).unwrap().to_be_bytes());
            wire.extend_from_slice(chunk);
        }
        assert_eq!(wire.len(), target_wire_bytes);
        wire
    }

    #[tokio::test]
    async fn prehello_accept_handles_one_byte_fragmented_client_hello() {
        let hello = test_client_hello_bytes();
        let mut stream = OneByteStream {
            data: hello,
            pos: 0,
        };
        let accepted = prehello_accept(&mut stream)
            .await
            .unwrap()
            .expect("1-byte fragmented ClientHello must parse cleanly");
        assert!(accepted.into_connection(test_server_config()).is_ok());
    }

    #[tokio::test]
    async fn prehello_accept_enforces_exact_65535_65536_and_65537_byte_boundaries() {
        // 65,535 bytes complete ClientHello: accepted.
        let hello_65535 = padded_client_hello_wire_bytes(65_535);
        let mut cursor = io::Cursor::new(hello_65535);
        let accepted = prehello_accept(&mut cursor)
            .await
            .unwrap()
            .expect("65535B ClientHello must be accepted");
        assert!(accepted.into_connection(test_server_config()).is_ok());

        // 65,536 bytes: rejected silently (exceeds rustls's 65,535B deframer limit
        // / hits PREHELLO_BUFFER_MAX) with zero bytes past 65,536 read.
        let hello_65536 = padded_client_hello_wire_bytes(65_536);
        let read_65536 = Arc::new(AtomicUsize::new(0));
        let (mut cli_65536, srv_65536) = tokio::io::duplex(128 * 1024);
        let mut counting_65536 = CountingStream {
            inner: srv_65536,
            bytes_read: Arc::clone(&read_65536),
        };
        let writer_65536 = tokio::spawn(async move {
            let _ = cli_65536.write_all(&hello_65536).await;
            cli_65536
        });
        let res_65536 = prehello_accept(&mut counting_65536).await.unwrap();
        assert!(
            res_65536.is_none(),
            "65536B ClientHello must be rejected silently"
        );
        assert!(read_65536.load(Ordering::Relaxed) <= PREHELLO_BUFFER_MAX);
        let _ = writer_65536.await;

        let (mut cli_incomplete, srv_incomplete) = tokio::io::duplex(128 * 1024);
        let read_incomplete = Arc::new(AtomicUsize::new(0));
        let mut counting_incomplete = CountingStream {
            inner: srv_incomplete,
            bytes_read: Arc::clone(&read_incomplete),
        };
        let hello_65537 = padded_client_hello_wire_bytes(65_537);
        let prefix_65536 = hello_65537[..65_536].to_vec();
        let writer_incomplete = tokio::spawn(async move {
            cli_incomplete.write_all(&prefix_65536).await.unwrap();
            cli_incomplete
        });
        let res_incomplete = prehello_accept(&mut counting_incomplete).await.unwrap();
        assert!(
            res_incomplete.is_none(),
            "incomplete 65536B input must be rejected at cap"
        );
        assert!(read_incomplete.load(Ordering::Relaxed) <= PREHELLO_BUFFER_MAX);
        let _ = writer_incomplete.await;

        // 65,537 bytes valid ClientHello: capped at <= 65,536 bytes read, rejected silently.
        let (mut cli_over, srv_over) = tokio::io::duplex(128 * 1024);
        let read_over = Arc::new(AtomicUsize::new(0));
        let mut counting_over = CountingStream {
            inner: srv_over,
            bytes_read: Arc::clone(&read_over),
        };
        let writer_over = tokio::spawn(async move {
            let _ = cli_over.write_all(&hello_65537).await;
            cli_over
        });
        let res_over = prehello_accept(&mut counting_over).await.unwrap();
        assert!(
            res_over.is_none(),
            "65537B ClientHello must be rejected silently at 64 KiB cap"
        );
        assert!(
            read_over.load(Ordering::Relaxed) <= PREHELLO_BUFFER_MAX,
            "must never read byte 65,537"
        );
        let _ = writer_over.await;
    }

    #[tokio::test]
    async fn admit_prehello_prelude_read_timeout_drains_silently() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (server, peer) = listener.accept().await.unwrap();
        set_zero_linger(&server).unwrap();

        // Send only 20 bytes of prelude so read_exact stalls until deadline.
        client.write_all(&[0x5a_u8; 20]).await.unwrap();

        let keys = MaskKeys::derive(b"k1", b"0123456789abcdef0123456789abcdef");
        let metrics = Arc::new(ServerMetrics::default());
        let limiter = AuthRateLimiter::new(crate::rate_limit::AuthRateLimitConfig {
            max_failures: 1,
            ..Default::default()
        });
        let (_tx, shutdown_rx) = watch::channel(false);
        let state = MaskingState::new(Some(16), None);
        let now = time::Instant::now();
        let deadline = now + Duration::from_millis(30);

        let res = state
            .admit_prehello(
                server,
                &[keys],
                test_server_config(),
                &metrics,
                &limiter,
                peer,
                now,
                Duration::from_millis(30),
                deadline,
                shutdown_rx,
            )
            .await;
        assert!(res.is_err());

        let mut buf = Vec::new();
        let read = client.read_to_end(&mut buf).await;
        assert!(matches!(read, Ok(0) | Err(_)) && buf.is_empty());
        let rendered = metrics.render();
        assert!(rendered.contains("uncrowned_king_server_mask_prelude_rejects_total 1\n"));
        assert!(
            rendered
                .contains("uncrowned_king_server_handshake_failures_total{reason=\"auth\"} 1\n")
        );
        assert!(!limiter.check(peer.ip()));
    }

    #[tokio::test]
    async fn admit_prehello_prehello_timeout_records_timeout_without_replay_commit() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, peer) = listener.accept().await.unwrap();
        set_zero_linger(&server).unwrap();

        let keys = MaskKeys::derive(b"k1", b"0123456789abcdef0123456789abcdef");
        let identity = 0x1122_3344_5566_7788;
        let counter = 3;
        let prelude = keys
            .encode_prelude(
                PreludePolicy::Full8,
                &mut rand::rngs::OsRng,
                identity,
                counter,
            )
            .unwrap();
        let hello = test_client_hello_bytes();
        let mut masked_client = MaskedStream::new_client_with_prelude(client, &keys, &prelude);
        // Send valid 76B prelude + partial ClientHello so prehello_accept stalls.
        masked_client.write_all(&hello[..10]).await.unwrap();
        masked_client.flush().await.unwrap();
        let mut client = masked_client.into_inner();

        let metrics = Arc::new(ServerMetrics::default());
        let limiter = AuthRateLimiter::new(crate::rate_limit::AuthRateLimitConfig {
            max_failures: 1,
            ..Default::default()
        });
        let (_tx, shutdown_rx) = watch::channel(false);
        let state = MaskingState::new(Some(16), None);
        let now = time::Instant::now();
        let deadline = now + Duration::from_millis(30);

        let res = state
            .admit_prehello(
                server,
                &[keys],
                test_server_config(),
                &metrics,
                &limiter,
                peer,
                now,
                Duration::from_millis(30),
                deadline,
                shutdown_rx,
            )
            .await;
        assert!(res.is_err());

        let mut buf = Vec::new();
        let read = client.read_to_end(&mut buf).await;
        assert!(matches!(read, Ok(0) | Err(_)) && buf.is_empty());

        let precheck = state
            .registry
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .precheck(identity, counter);
        assert_eq!(
            precheck,
            ReplayDecision::Accepted,
            "prehello timeout must not commit replay counter"
        );

        let rendered = metrics.render();
        assert!(
            rendered
                .contains("uncrowned_king_server_handshake_failures_total{reason=\"timeout\"} 1\n")
        );
        assert!(rendered.contains("uncrowned_king_server_mask_prelude_rejects_total 0\n"));
        assert!(rendered.contains("uncrowned_king_server_mask_replay_rejects_total 0\n"));
        assert!(!limiter.check(peer.ip()));
    }

    #[tokio::test]
    async fn admit_prehello_expired_deadline_after_into_connection_rejects_without_replay_commit() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, peer) = listener.accept().await.unwrap();
        set_zero_linger(&server).unwrap();

        let keys = MaskKeys::derive(b"k1", b"0123456789abcdef0123456789abcdef");
        let identity = 0x8877_6655_4433_2211;
        let counter = 9;
        let prelude = keys
            .encode_prelude(
                PreludePolicy::Full8,
                &mut rand::rngs::OsRng,
                identity,
                counter,
            )
            .unwrap();
        let hello = test_client_hello_bytes();
        let mut masked_client = MaskedStream::new_client_with_prelude(client, &keys, &prelude);
        masked_client.write_all(&hello).await.unwrap();
        masked_client.flush().await.unwrap();
        let mut client = masked_client.into_inner();

        let metrics = Arc::new(ServerMetrics::default());
        let limiter = AuthRateLimiter::new(crate::rate_limit::AuthRateLimitConfig {
            max_failures: 1,
            ..Default::default()
        });
        let (_tx, shutdown_rx) = watch::channel(false);
        let state = MaskingState::new(Some(16), None);
        let now = time::Instant::now();
        let deadline = now + Duration::from_secs(2);

        let res = state
            .admit_prehello_inner(
                server,
                &[keys],
                test_server_config(),
                &metrics,
                &limiter,
                peer,
                now,
                Duration::from_millis(20),
                deadline,
                shutdown_rx,
                |_deadline| time::Instant::now(),
                || panic!("before_commit must not run when deadline expired after into_connection"),
            )
            .await;
        assert!(res.is_err());

        let mut buf = Vec::new();
        let read = client.read_to_end(&mut buf).await;
        assert!(matches!(read, Ok(0) | Err(_)) && buf.is_empty());

        let precheck = state
            .registry
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .precheck(identity, counter);
        assert_eq!(
            precheck,
            ReplayDecision::Accepted,
            "expired deadline after into_connection must not commit replay counter"
        );
        let rendered = metrics.render();
        assert!(
            rendered
                .contains("uncrowned_king_server_handshake_failures_total{reason=\"timeout\"} 1\n")
        );
        assert!(rendered.contains("uncrowned_king_server_mask_replay_rejects_total 0\n"));
        assert!(!limiter.check(peer.ip()));
    }
}
