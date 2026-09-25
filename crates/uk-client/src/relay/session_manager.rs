#![allow(unused_imports, clippy::wildcard_imports)]

use std::{
    collections::{HashMap, hash_map::Entry},
    error::Error,
    fmt,
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use rand::Rng;

use bytes::{Bytes, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore, mpsc, watch},
    task::{Id, JoinError, JoinSet},
    time,
};
use tracing::{Instrument, debug, error, info, info_span, warn};
use uk_auth::{AuthenticatedIdentity, unix_now};
use uk_proto::{
    BoxedCarrierReader, BoxedCarrierWriter, BoxedDatagramChannel, DatagramSendOutcome, ErrorCode,
    ErrorPayload, FIRST_CLIENT_FLOW_ID, FLOW_ID_STEP, Frame, FrameIoError, FrameLimits, FrameType,
    NegotiatedSettings, TCP_CLOSE_ERROR, TCP_CLOSE_NORMAL, TCP_OPEN_FLAGS_NONE, Target, TcpClose,
    TcpOpen, UDP_CLOSE_ERROR, UDP_CLOSE_NORMAL, UdpClose, UdpOpen, datagram,
    is_client_initiated_flow_id, read_frame, validate_connection_frame, varint::MAX_VARINT,
    write_frame,
};

use super::carrier::*;
use super::context::*;
use super::listener::*;
use super::tcp::*;
use super::udp::*;
use crate::{
    ClientReloadReceiver, ClientReloadRequest,
    config::{ClientConfig, validate_endpoint},
    config_state::{ClientConfigSnapshot, ClientConfigState},
    observability::{ActiveFlowGuard, ClientMetrics, RelayDirection, RelayProtocol},
    session, socks5,
};
pub(crate) struct ClientSession {
    pub(crate) correlation_id: u64,
    pub(crate) config_generation: u64,
    pub(crate) writer: CarrierWriter,
    pub(crate) flows: FlowTable,
    pub(crate) limits: FrameLimits,
    pub(crate) data_frame_size: usize,
    pub(crate) max_streams: u64,
    pub(crate) max_udp_flows: u64,
    pub(crate) admission: FlowAdmissionControl,
    pub(crate) supports_udp_stream_fallback: bool,
    pub(crate) supports_udp_datagram: bool,
    pub(crate) datagrams: Option<BoxedDatagramChannel>,
    pub(crate) max_pending_open_bytes: usize,
    pub(crate) max_buffered_bytes_per_session: usize,
    pub(crate) max_buffered_bytes_per_flow: usize,
    pub(crate) session_buffer: ClientSessionBufferControl,
    pub(crate) open_timeout: Option<Duration>,
    pub(crate) task_shutdown_timeout: Option<Duration>,
    pub(crate) tasks: Mutex<ClientSessionTasks>,
    pub(crate) shutdown: ClientSessionShutdown,
    pub(crate) draining: AtomicBool,
    pub(crate) metrics: Arc<ClientMetrics>,
    pub(crate) metric_state: StdMutex<ClientSessionMetricState>,
    pub(crate) next_flow_id: AtomicU64,
    pub(crate) next_ping_nonce: AtomicU64,
    pub(crate) outstanding_ping_nonce: AtomicU64,
    pub(crate) last_pong_nonce: AtomicU64,
    pub(crate) pong_notify: Notify,
}

pub(crate) struct ClientSessionManager {
    pub(crate) config: ClientConfigState,
    pub(crate) metrics: Arc<ClientMetrics>,
    /// Bounded pool of live authenticated carrier sessions of the current
    /// config generation. New flows are placed least-loaded across the pool so
    /// a bulk flow's shedding on one carrier does not stall latency-sensitive
    /// flows on the others (whitepaper §13). Draining sessions are removed here
    /// and kept alive only by their remaining flows.
    pub(crate) pool: Mutex<Vec<Arc<ClientSession>>>,
    pub(crate) connect_lock: Mutex<()>,
    pub(crate) config_publish_lock: Mutex<()>,
    pub(crate) recent_connect_failure: Mutex<Option<CachedConnectFailure>>,
    pub(crate) consecutive_connect_failures: AtomicU32,
    /// Background teardown of sessions pruned from the pool, kept off the
    /// flow-open path. Drained by [`ClientSessionManager::shutdown`].
    pub(crate) reapers: Mutex<JoinSet<()>>,
    pub(crate) closed: AtomicBool,
}

#[derive(Clone)]
pub(crate) struct SocksConnectionRuntime {
    pub(crate) sessions: Arc<ClientSessionManager>,
    pub(crate) metrics: Arc<ClientMetrics>,
    pub(crate) connection_slots: Arc<Semaphore>,
    pub(crate) handshake_timeout: Option<Duration>,
    pub(crate) max_connections: usize,
}

impl SocksConnectionRuntime {
    pub(crate) async fn spawn_accepted(
        &self,
        connections: &mut JoinSet<()>,
        mut local: TcpStream,
        peer: SocketAddr,
        shutdown_rx: watch::Receiver<bool>,
    ) {
        self.metrics.record_accepted_socks_connection();
        let Ok(permit) = Arc::clone(&self.connection_slots).try_acquire_owned() else {
            self.metrics.record_rejected_socks_connection();
            warn!(
                event = "socks5.connection.limit",
                peer = %peer,
                max_connections = self.max_connections
            );
            if let Err(err) = local.shutdown().await {
                debug!(
                    event = "socks5.connection.limit_shutdown_error",
                    peer = %peer,
                    error = %err
                );
            }
            return;
        };

        let sessions = Arc::clone(&self.sessions);
        let metrics = Arc::clone(&self.metrics);
        let handshake_timeout = self.handshake_timeout;
        let connection_id = NEXT_SOCKS_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
        let connection = async move {
            let _permit = permit;
            let _active_connection = metrics.begin_socks_connection();
            if let Err(err) =
                handle_socks_connection(local, sessions, handshake_timeout, shutdown_rx).await
            {
                if is_clean_socks_disconnect(&err) {
                    debug!(event = "socks5.connection.closed", peer = %peer);
                } else {
                    warn!(event = "socks5.connection.error", peer = %peer, error = %err);
                }
            }
        };
        connections.spawn(connection.instrument(info_span!(
            "socks5.connection",
            connection_id,
            peer = %peer
        )));
    }
}

impl ClientSessionManager {
    pub(crate) fn new(config: ClientConfig, metrics: Arc<ClientMetrics>) -> Self {
        let config = ClientConfigState::new(config);
        metrics.set_config_generation(config.generation());
        Self {
            config,
            metrics,
            pool: Mutex::new(Vec::new()),
            connect_lock: Mutex::new(()),
            config_publish_lock: Mutex::new(()),
            recent_connect_failure: Mutex::new(None),
            consecutive_connect_failures: AtomicU32::new(0),
            reapers: Mutex::new(JoinSet::new()),
            closed: AtomicBool::new(false),
        }
    }

    pub(crate) async fn reload(&self, candidate: ClientConfig) -> Result<u64, AnyError> {
        let result = async {
            // `check_config` reads and parses the CA bundle synchronously, and
            // this runs on the listener's accept-loop task. A slow or hung
            // filesystem (an NFS or automount CA path) would otherwise stall
            // the loop and stop the client accepting SOCKS connections.
            let validated = candidate.clone();
            tokio::task::spawn_blocking(move || crate::check_config(&validated))
                .await
                .map_err(|err| -> AnyError {
                    format!("config validation task failed: {err}").into()
                })??;
            let _publish_guard = self.config_publish_lock.lock().await;
            let current = self.config.snapshot();
            ensure_reload_compatible(&current.config, &candidate)?;
            let ca_path = candidate.ca_cert_path.clone();
            tokio::task::spawn_blocking(move || crate::tls::refresh_client_config(&ca_path))
                .await
                .map_err(|err| -> AnyError {
                    format!("failed to refresh TLS CA cache: {err}").into()
                })??;
            let generation = self.config.replace(candidate);
            self.clear_connect_failure().await;
            let previous: Vec<Arc<ClientSession>> = self.pool.lock().await.drain(..).collect();
            for session in previous {
                session.begin_drain().await;
            }
            Ok(generation)
        }
        .await;
        match &result {
            Ok(generation) => self.metrics.record_reload_success(*generation),
            Err(_) => self.metrics.record_reload_failure(),
        }
        result
    }

    pub(crate) async fn open_flow(
        &self,
        target: Target,
        local: &mut TcpStream,
        shutdown_rx: &mut watch::Receiver<bool>,
    ) -> Result<OpenOutcome, AnyError> {
        self.metrics.record_flow_open_request(RelayProtocol::Tcp);
        if *shutdown_rx.borrow() {
            return Ok(OpenOutcome::Cancelled);
        }
        let mut pending_local_data = PendingOpenLocalData::default();
        let mut last_error = None;
        for attempt in 0..2 {
            let admission = tokio::select! {
                result = self.admission_for_new_flow(FlowProtocol::Tcp) => result?,
                changed = shutdown_rx.changed() => {
                    let _ = changed;
                    return Ok(OpenOutcome::Cancelled);
                }
            };
            let Some(admission) = admission else {
                warn!(
                    event = "client.session.open.capacity_exhausted",
                    attempt,
                    max_carrier_sessions = self.max_pool_size()
                );
                return Ok(OpenOutcome::Rejected(socks5::Reply::GeneralFailure));
            };
            let session = Arc::clone(&admission.session);
            match session
                .open_flow(
                    target.clone(),
                    admission,
                    local,
                    &mut pending_local_data,
                    shutdown_rx,
                )
                .await
            {
                Ok(outcome) => return Ok(outcome),
                Err(err) => {
                    warn!(
                        event = "client.session.open.error",
                        attempt,
                        error = %err
                    );
                    if !is_session_draining_error(&err) {
                        self.invalidate(&session).await;
                    }
                    last_error = Some(err);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| "failed to open uk flow".into()))
    }

    pub(crate) async fn open_udp_flow(
        &self,
        target: Target,
        local: &mut TcpStream,
        tcp_buf: &mut [u8; 1],
        shutdown_rx: &mut watch::Receiver<bool>,
    ) -> Result<OpenOutcome, AnyError> {
        self.metrics.record_flow_open_request(RelayProtocol::Udp);
        let mut last_error = None;
        for attempt in 0..2 {
            if *shutdown_rx.borrow() {
                return Ok(OpenOutcome::Cancelled);
            }
            let admission = tokio::select! {
                result = self.admission_for_new_flow(FlowProtocol::Udp) => result?,
                changed = shutdown_rx.changed() => {
                    let _ = changed;
                    return Ok(OpenOutcome::Cancelled);
                }
            };
            let Some(admission) = admission else {
                warn!(
                    event = "client.session.udp_open.capacity_exhausted",
                    attempt,
                    max_carrier_sessions = self.max_pool_size()
                );
                return Ok(OpenOutcome::Rejected(socks5::Reply::GeneralFailure));
            };
            let session = Arc::clone(&admission.session);
            match session
                .open_udp_flow(target.clone(), admission, local, tcp_buf, shutdown_rx)
                .await
            {
                Ok(outcome) => return Ok(outcome),
                Err(err) => {
                    warn!(
                        event = "client.session.udp_open.error",
                        attempt,
                        error = %err
                    );
                    if !is_session_draining_error(&err) {
                        self.invalidate(&session).await;
                    }
                    last_error = Some(err);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| "failed to open uk udp flow".into()))
    }

    /// Returns any live session, connecting a new one only if the pool is empty.
    ///
    /// Used for session-wide capability queries and as the connect primitive.
    /// Flow placement goes through [`Self::admission_for_new_flow`] instead.
    pub(crate) async fn current_session(&self) -> Result<Arc<ClientSession>, AnyError> {
        loop {
            if self.is_closed() {
                return Err("client session manager is shutting down".into());
            }
            if let Some(session) = self.first_live_session().await {
                return Ok(session);
            }
            if let Some(failure) = self.recent_connect_failure_if_active().await {
                return Err(cached_connect_failure_error(failure));
            }

            let _connect_guard = self.connect_lock.lock().await;
            if self.is_closed() {
                return Err("client session manager is shutting down".into());
            }
            if let Some(session) = self.first_live_session().await {
                return Ok(session);
            }
            if let Some(failure) = self.recent_connect_failure_if_active().await {
                return Err(cached_connect_failure_error(failure));
            }

            if let Some(session) = self.connect_and_pool().await? {
                return Ok(session);
            }
        }
    }

    /// Reserves a slot for a new flow, growing the pool up to
    /// `max_carrier_sessions` when every live session is at its ceiling.
    ///
    /// Returns `Ok(None)` when no session can take the flow and growing the
    /// pool would not help: the pool is already at `max_carrier_sessions` and
    /// saturated, or a live session is at the per-session `max_udp_flows`. That
    /// is genuine capacity exhaustion rather than a lost race, so the caller
    /// rejects the request instead of retrying.
    pub(crate) async fn admission_for_new_flow(
        &self,
        protocol: FlowProtocol,
    ) -> Result<Option<FlowAdmission>, AnyError> {
        loop {
            if self.is_closed() {
                return Err("client session manager is shutting down".into());
            }
            match self.admit_flow(protocol).await {
                Ok(admission) => return Ok(Some(admission)),
                Err(PoolAdmissionRefusal::UdpFlowLimit) => return Ok(None),
                Err(PoolAdmissionRefusal::StreamLimit) => {}
            }

            let _connect_guard = self.connect_lock.lock().await;
            if self.is_closed() {
                return Err("client session manager is shutting down".into());
            }
            // Re-check under the connect lock: another task may have added a
            // session or freed capacity while we waited.
            match self.admit_flow(protocol).await {
                Ok(admission) => return Ok(Some(admission)),
                Err(PoolAdmissionRefusal::UdpFlowLimit) => return Ok(None),
                Err(PoolAdmissionRefusal::StreamLimit) => {}
            }

            // `live_sessions` has just pruned closed sessions, so a full pool
            // here really is `max_carrier_sessions` saturated live carriers.
            if self.live_sessions().await.len() >= self.max_pool_size() {
                return Ok(None);
            }

            if let Some(failure) = self.recent_connect_failure_if_active().await {
                return Err(cached_connect_failure_error(failure));
            }

            if let Some(session) = self.connect_and_pool().await? {
                match session.try_admit(protocol) {
                    Ok(admission) => return Ok(Some(admission)),
                    Err(AdmissionRefusal::UdpFlowLimit) => return Ok(None),
                    // The fresh session was drained or filled before we could
                    // use it; loop, which finds capacity or hits the pool cap.
                    Err(AdmissionRefusal::StreamLimit | AdmissionRefusal::Unavailable) => {}
                }
            }
        }
    }

    /// Connects a new carrier session and publishes it into the pool.
    ///
    /// Must be called while holding `connect_lock` so dials are serialized.
    /// Returns `Ok(None)` when the connect should be retried (transient connect
    /// failure with retry disabled, or the config generation changed underneath).
    pub(crate) async fn connect_and_pool(&self) -> Result<Option<Arc<ClientSession>>, AnyError> {
        let snapshot = self.config.snapshot();
        info!(
            event = "client.session.connect",
            config_generation = snapshot.generation
        );
        self.metrics.record_session_connect_attempt();
        let pending = match ClientSession::connect(&snapshot, Arc::clone(&self.metrics)).await {
            Ok(session) => PendingClientSession::new(session),
            Err(err) => {
                self.metrics.record_session_connect_failure();
                if self.remember_connect_failure(&snapshot, &err).await {
                    return Err(err);
                }
                return Ok(None);
            }
        };

        let publish_guard = self.config_publish_lock.lock().await;
        if self.config.generation() != snapshot.generation {
            drop(publish_guard);
            // Let the PendingClientSession's Drop impl clean up in the
            // background rather than blocking here while holding connect_lock.
            drop(pending);
            return Ok(None);
        }
        self.clear_connect_failure().await;
        if self.is_closed() {
            drop(publish_guard);
            drop(pending);
            return Err("client session manager is shutting down".into());
        }
        let mut pool = self.pool.lock().await;
        if self.is_closed() {
            drop(pool);
            drop(publish_guard);
            drop(pending);
            return Err("client session manager is shutting down".into());
        }
        // Take ownership only once publishing is certain: there is no `.await`
        // between here and the push, so the guard covers every cancellation
        // point on the way in.
        let session = pending.into_session();
        pool.push(Arc::clone(&session));
        Ok(Some(session))
    }

    /// Maximum number of pooled sessions for the current config generation.
    pub(crate) fn max_pool_size(&self) -> usize {
        usize::try_from(self.config.snapshot().config.max_carrier_sessions())
            .unwrap_or(usize::MAX)
            .max(1)
    }

    /// Returns the live (non-closed) pooled sessions, pruning and reaping any
    /// closed ones from the pool.
    pub(crate) async fn live_sessions(&self) -> Vec<Arc<ClientSession>> {
        let mut stale = Vec::new();
        let live = {
            let mut pool = self.pool.lock().await;
            pool.retain(|session| {
                if session.is_closed() {
                    stale.push(Arc::clone(session));
                    false
                } else {
                    true
                }
            });
            pool.clone()
        };
        // Reap off the request path. `close_and_wait` drains the session's
        // tasks, bounded by `shutdown_timeout_seconds` but still seconds long,
        // and this runs on every flow open — twice while holding `connect_lock`.
        // Awaiting it here let one dead carrier stall every new SOCKS
        // connection. The sessions are already closed, so this is pure cleanup.
        for session in stale {
            self.spawn_reaper(session).await;
        }
        live
    }

    /// Runs a stale session's teardown in the background, tracked so shutdown
    /// still waits for it rather than leaving detached tasks behind.
    pub(crate) async fn spawn_reaper(&self, session: Arc<ClientSession>) {
        let mut reapers = self.reapers.lock().await;
        while let Some(result) = reapers.try_join_next() {
            if let Err(err) = result {
                debug!(event = "client.session.reaper.join_error", error = %err);
            }
        }
        reapers.spawn(async move { session.close_and_wait().await });
    }

    /// Returns the first live pooled session, if any.
    pub(crate) async fn first_live_session(&self) -> Option<Arc<ClientSession>> {
        self.live_sessions().await.into_iter().next()
    }

    /// Atomically admits a flow on the least-loaded live, non-draining session
    /// that still has capacity, spreading load across the pool.
    ///
    /// Candidates are ranked by current load and then admitted with an atomic
    /// `try_admit`, so a session that fills up between the ranking and the
    /// reservation simply hands the slot to the next candidate instead of
    /// producing a spurious rejection. A refusal reports whether the pool could
    /// usefully grow (see [`PoolAdmissionRefusal`]).
    pub(crate) async fn admit_flow(
        &self,
        protocol: FlowProtocol,
    ) -> Result<FlowAdmission, PoolAdmissionRefusal> {
        let mut candidates = Vec::new();
        for session in self.live_sessions().await {
            if session.is_draining() {
                continue;
            }
            candidates.push((session.flow_count().await, session));
        }
        candidates.sort_by_key(|(load, _)| *load);

        let mut refusal = PoolAdmissionRefusal::StreamLimit;
        for (_, session) in &candidates {
            match session.try_admit(protocol) {
                Ok(admission) => return Ok(admission),
                Err(AdmissionRefusal::UdpFlowLimit) => {
                    refusal = PoolAdmissionRefusal::UdpFlowLimit;
                }
                Err(AdmissionRefusal::StreamLimit | AdmissionRefusal::Unavailable) => {}
            }
        }
        Err(refusal)
    }

    pub(crate) async fn recent_connect_failure_if_active(&self) -> Option<CachedConnectFailure> {
        let mut recent = self.recent_connect_failure.lock().await;
        let failure = recent.as_ref()?;
        if failure.generation != self.config.generation() {
            *recent = None;
            return None;
        }
        if let Some(expires_at) = failure.expires_at {
            if time::Instant::now() >= expires_at {
                *recent = None;
                return None;
            }
        }

        Some(failure.clone())
    }

    pub(crate) async fn remember_connect_failure(
        &self,
        snapshot: &ClientConfigSnapshot,
        error: &AnyError,
    ) -> bool {
        let _publish_guard = self.config_publish_lock.lock().await;
        if self.config.generation() != snapshot.generation {
            return false;
        }
        let base_delay_ms = snapshot.config.server_connect_retry_delay_millis();
        if retry_delay(base_delay_ms).is_none() {
            return true;
        }
        let consecutive_failures = self
            .consecutive_connect_failures
            .fetch_add(1, Ordering::Relaxed);
        let max_backoff_ms = SERVER_CONNECT_RETRY_MAX_MILLIS;
        let backoff_ms =
            calculate_reconnect_backoff_ms(base_delay_ms, consecutive_failures, max_backoff_ms);
        let (min_ms, max_ms) = calculate_reconnect_jitter_range(backoff_ms);
        let delay_ms = rand::thread_rng().gen_range(min_ms..=max_ms);
        let delay = Duration::from_millis(delay_ms);

        let mut recent = self.recent_connect_failure.lock().await;
        *recent = Some(CachedConnectFailure {
            generation: snapshot.generation,
            message: Arc::from(error.to_string()),
            expires_at: retry_delay_expires_at(delay),
        });
        true
    }

    pub(crate) async fn clear_connect_failure(&self) {
        self.consecutive_connect_failures
            .store(0, Ordering::Relaxed);
        *self.recent_connect_failure.lock().await = None;
    }

    pub(crate) async fn invalidate(&self, session: &Arc<ClientSession>) {
        let removed = {
            let mut pool = self.pool.lock().await;
            let before = pool.len();
            pool.retain(|pooled| !Arc::ptr_eq(pooled, session));
            pool.len() != before
        };
        if removed {
            // Tear down in the background so the SOCKS request path is not
            // blocked by `close_and_wait` (up to `shutdown_timeout_seconds`).
            self.spawn_reaper(Arc::clone(session)).await;
        } else {
            session.close().await;
        }
    }

    pub(crate) async fn shutdown(&self) {
        self.closed.store(true, Ordering::SeqCst);
        let sessions: Vec<Arc<ClientSession>> = { self.pool.lock().await.drain(..).collect() };
        for session in sessions {
            session.close_and_wait().await;
        }
        let mut reapers = self.reapers.lock().await;
        while reapers.join_next().await.is_some() {}
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    pub(crate) async fn supports_udp_relay(&self) -> Result<bool, AnyError> {
        Ok(self.current_session().await?.supports_udp_relay())
    }

    pub(crate) fn udp_flow_idle_timeout(&self) -> Option<Duration> {
        timeout(
            self.config
                .snapshot()
                .config
                .udp_flow_idle_timeout_seconds(),
        )
    }
}

pub(crate) fn calculate_reconnect_backoff_ms(
    base_delay_ms: u64,
    consecutive_failures: u32,
    max_backoff_ms: u64,
) -> u64 {
    std::cmp::min(
        max_backoff_ms,
        base_delay_ms.saturating_mul(1_u64 << std::cmp::min(consecutive_failures, 10)),
    )
}

pub(crate) fn calculate_reconnect_jitter_range(backoff_ms: u64) -> (u64, u64) {
    let min_ms = (backoff_ms / 2).max(1);
    let max_ms = (backoff_ms.saturating_mul(3) / 2).max(min_ms);
    (min_ms, max_ms)
}

pub(crate) fn ensure_reload_compatible(
    current: &ClientConfig,
    candidate: &ClientConfig,
) -> Result<(), AnyError> {
    let changed = if current.socks_handshake_timeout_seconds()
        != candidate.socks_handshake_timeout_seconds()
    {
        Some("socks_handshake_timeout_seconds")
    } else if current.shutdown_timeout_seconds() != candidate.shutdown_timeout_seconds() {
        Some("shutdown_timeout_seconds")
    } else if current.max_socks_connections() != candidate.max_socks_connections() {
        Some("max_socks_connections")
    } else if current.observability_listen != candidate.observability_listen {
        Some("observability_listen")
    } else {
        None
    };
    match changed {
        Some(field) => Err(format!("client config field `{field}` requires a restart").into()),
        None => Ok(()),
    }
}

impl ClientSession {
    pub(crate) async fn connect(
        snapshot: &ClientConfigSnapshot,
        metrics: Arc<ClientMetrics>,
    ) -> Result<Arc<Self>, AnyError> {
        let config = snapshot.config.as_ref();
        let (carrier, settings) = session::connect_authenticated_observed(config, |outcome| {
            metrics.record_endpoint_attempt(outcome);
        })
        .await?;
        let negotiated = settings.negotiated_v0_1()?;
        let limits = negotiated.frame_limits();
        let (carrier_reader, carrier_writer, datagrams) = carrier.into_parts();
        // Native UDP over QUIC DATAGRAM requires the peer to advertise it, a
        // datagram-capable carrier (QUIC), and UDP relay capacity.
        let datagrams = datagrams.filter(|channel| channel.max_datagram_size().is_some());
        let supports_udp_datagram = negotiated.supports_udp_datagram
            && datagrams.is_some()
            && negotiated.max_udp_flows != 0;
        let session_buffer = ClientSessionBufferControl::default();
        let correlation_id = NEXT_CLIENT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
        let session = Arc::new(Self {
            correlation_id,
            config_generation: snapshot.generation,
            writer: Arc::new(Mutex::new(carrier_writer)),
            flows: Arc::new(Mutex::new(HashMap::new())),
            limits,
            data_frame_size: tcp_data_frame_size(limits, Some(config.relay_buffer_size())),
            max_streams: negotiated.max_streams,
            max_udp_flows: negotiated.max_udp_flows,
            admission: FlowAdmissionControl::new(negotiated.max_streams, negotiated.max_udp_flows),
            supports_udp_stream_fallback: negotiated.udp_stream_fallback_enabled(),
            supports_udp_datagram,
            datagrams,
            max_pending_open_bytes: usize_limit(config.max_pending_open_bytes())?,
            max_buffered_bytes_per_session: usize_limit(config.max_buffered_bytes_per_session())?,
            max_buffered_bytes_per_flow: usize_limit(config.max_buffered_bytes_per_flow())?,
            session_buffer,
            open_timeout: timeout(config.tcp_open_timeout_seconds()),
            task_shutdown_timeout: timeout(config.shutdown_timeout_seconds()),
            tasks: Mutex::new(ClientSessionTasks::default()),
            shutdown: ClientSessionShutdown::default(),
            draining: AtomicBool::new(false),
            metrics: Arc::clone(&metrics),
            metric_state: StdMutex::new(ClientSessionMetricState::Active),
            next_flow_id: AtomicU64::new(FIRST_CLIENT_FLOW_ID),
            next_ping_nonce: AtomicU64::new(0),
            outstanding_ping_nonce: AtomicU64::new(0),
            last_pong_nonce: AtomicU64::new(0),
            pong_notify: Notify::new(),
        });
        metrics.record_session_established();
        info!(
            event = "client.session.established",
            correlation_id,
            config_generation = snapshot.generation
        );
        spawn_carrier_reader(carrier_reader, Arc::clone(&session)).await;
        spawn_datagram_reader(Arc::clone(&session)).await;
        if let Some(interval) = keepalive_interval(negotiated) {
            spawn_keepalive(Arc::clone(&session), interval).await;
        }
        Ok(session)
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.shutdown.is_closed()
    }

    pub(crate) fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire)
    }

    pub(crate) async fn begin_drain(&self) {
        if self.draining.swap(true, Ordering::AcqRel) {
            return;
        }
        {
            let mut state = self
                .metric_state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if *state == ClientSessionMetricState::Active {
                *state = ClientSessionMetricState::Draining;
                self.metrics.record_session_draining();
            }
        }
        info!(
            event = "client.session.draining",
            correlation_id = self.correlation_id,
            config_generation = self.config_generation
        );
        self.close_if_drained().await;
    }

    pub(crate) async fn remove_flow(&self, flow_id: u64) {
        let should_close = {
            let mut flows = self.flows.lock().await;
            let removed = flows.remove(&flow_id).is_some();
            removed && self.is_draining() && flows.is_empty()
        };
        if should_close {
            info!(
                event = "client.session.drain_complete",
                correlation_id = self.correlation_id,
                config_generation = self.config_generation
            );
            self.close().await;
        }
    }

    pub(crate) async fn close_if_drained(&self) {
        if self.is_draining() && self.flows.lock().await.is_empty() {
            info!(
                event = "client.session.drain_complete",
                correlation_id = self.correlation_id,
                config_generation = self.config_generation
            );
            self.close().await;
        }
    }

    pub(crate) async fn has_open_flows(&self) -> bool {
        !self.flows.lock().await.is_empty()
    }

    /// Current number of open flows on this session (its pool load).
    pub(crate) async fn flow_count(&self) -> usize {
        self.flows.lock().await.len()
    }

    /// Atomically admits one new flow on this session, or reports why it could
    /// not: unavailable (draining or closed), or at one of its ceilings.
    pub(crate) fn try_admit(
        self: &Arc<Self>,
        protocol: FlowProtocol,
    ) -> Result<FlowAdmission, AdmissionRefusal> {
        if self.is_draining() || self.is_closed() {
            return Err(AdmissionRefusal::Unavailable);
        }
        Ok(FlowAdmission {
            session: Arc::clone(self),
            slot: self.admission.try_admit(protocol)?,
        })
    }

    pub(crate) async fn close(&self) {
        if self.shutdown.close() {
            let was_draining = {
                let mut state = self
                    .metric_state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let was_draining = *state == ClientSessionMetricState::Draining;
                *state = ClientSessionMetricState::Closed;
                was_draining
            };
            self.metrics.record_session_closed(was_draining);
            self.pong_notify.notify_waiters();
            self.flows.lock().await.clear();
            self.shutdown_carrier().await;
        }
    }

    /// Closes the carrier write half, best-effort and bounded.
    ///
    /// A server that has stopped reading — or a host that blackholes packets
    /// without sending RST — cannot accept `close_notify`, and this runs on
    /// paths that must stay responsive: config reload drives it from the
    /// listener's accept loop, and `remove_flow` from a relay task. Waiting
    /// indefinitely there stops the client accepting new SOCKS connections.
    /// A missed `close_notify` only costs the peer a clean shutdown signal;
    /// dropping the writer still closes the socket.
    pub(crate) async fn shutdown_carrier(&self) {
        let close = async {
            let mut writer = self.writer.lock().await;
            if let Err(err) = writer.shutdown().await {
                debug!(event = "client.session.shutdown.error", error = %err);
            }
        };
        let Some(timeout) = self.task_shutdown_timeout else {
            close.await;
            return;
        };
        if time::timeout(timeout, close).await.is_err() {
            warn!(
                event = "client.session.shutdown.timeout",
                correlation_id = self.correlation_id,
                timeout_seconds = timeout.as_secs()
            );
        }
    }

    pub(crate) async fn close_and_wait(&self) {
        self.close().await;
        let mut tasks = self.tasks.lock().await;
        drain_client_session_tasks(&mut tasks, self.task_shutdown_timeout).await;
    }

    /// Opens a TCP flow against a slot already reserved by
    /// [`ClientSessionManager::admission_for_new_flow`].
    ///
    /// `admission` carries the session's capacity permit; it is moved into the
    /// returned [`ClientFlow`] on success and dropped — releasing the slot — on
    /// every rejection, error and cancellation path.
    pub(crate) async fn open_flow(
        self: &Arc<Self>,
        target: Target,
        admission: FlowAdmission,
        local: &mut TcpStream,
        pending_local_data: &mut PendingOpenLocalData,
        shutdown_rx: &mut watch::Receiver<bool>,
    ) -> Result<OpenOutcome, AnyError> {
        debug_assert!(
            Arc::ptr_eq(self, &admission.session),
            "flow admission belongs to another session"
        );
        if self.is_draining() {
            return Err(Box::new(SessionDrainingError));
        }
        if self.is_closed() {
            return Err("uk session is closed".into());
        }
        let Some((flow_id, frames)) = self.reserve_flow(FlowProtocol::Tcp).await? else {
            // Unreachable while the admission permit is held: the flow table
            // can never hold more routes than there are permits handed out.
            return Ok(OpenOutcome::Rejected(socks5::Reply::GeneralFailure));
        };
        if self.is_closed() {
            self.remove_flow(flow_id).await;
            return Err("uk session is closed".into());
        }

        let send_result = self.send_tcp_open(flow_id, target).await;
        if let Err(err) = send_result {
            self.remove_flow(flow_id).await;
            return Err(err);
        }

        let mut flow = ClientFlow {
            id: flow_id,
            frames,
            session: Arc::clone(self),
            pending_local_data: Vec::new(),
            metric_guard: None,
            _slot: admission.slot,
        };
        let frame = match self
            .wait_for_open_frame(
                flow_id,
                &mut flow.frames,
                local,
                pending_local_data,
                shutdown_rx,
            )
            .await?
        {
            OpenWaitOutcome::Frame(frame) => frame,
            OpenWaitOutcome::Cancelled => return Ok(OpenOutcome::Cancelled),
            OpenWaitOutcome::TimedOut | OpenWaitOutcome::LocalResourceLimit => {
                return Ok(OpenOutcome::Rejected(socks5::Reply::GeneralFailure));
            }
        };
        match decode_open_response(frame) {
            Ok(OpenResponse::Accepted) => {
                flow.pending_local_data = pending_local_data.take_chunks();
                flow.metric_guard =
                    Some(self.metrics.begin_flow(FlowProtocol::Tcp.metric_protocol()));
                Ok(OpenOutcome::Open(flow))
            }
            Ok(OpenResponse::Rejected(reply)) => {
                self.remove_flow(flow_id).await;
                Ok(OpenOutcome::Rejected(reply))
            }
            Err(err) => {
                self.remove_flow(flow_id).await;
                report_protocol_error(self).await;
                Err(err)
            }
        }
    }

    /// Opens a UDP flow against a slot already reserved by
    /// [`ClientSessionManager::admission_for_new_flow`]; see [`Self::open_flow`]
    /// for the admission ownership rules.
    pub(crate) async fn open_udp_flow(
        self: &Arc<Self>,
        target: Target,
        admission: FlowAdmission,
        local: &mut TcpStream,
        tcp_buf: &mut [u8; 1],
        shutdown_rx: &mut watch::Receiver<bool>,
    ) -> Result<OpenOutcome, AnyError> {
        debug_assert!(
            Arc::ptr_eq(self, &admission.session),
            "flow admission belongs to another session"
        );
        if self.is_draining() {
            return Err(Box::new(SessionDrainingError));
        }
        if self.is_closed() {
            return Err("uk session is closed".into());
        }
        if !self.supports_udp_relay() {
            return Ok(OpenOutcome::Rejected(socks5::Reply::CommandNotSupported));
        }
        let Some((flow_id, frames)) = self.reserve_flow(FlowProtocol::Udp).await? else {
            // Unreachable while the admission permit is held; see `open_flow`.
            return Ok(OpenOutcome::Rejected(socks5::Reply::GeneralFailure));
        };
        if self.is_closed() {
            self.remove_flow(flow_id).await;
            return Err("uk session is closed".into());
        }

        if let Err(err) = self.send_udp_open(flow_id, target).await {
            self.remove_flow(flow_id).await;
            return Err(err);
        }

        let mut flow = ClientFlow {
            id: flow_id,
            frames,
            session: Arc::clone(self),
            pending_local_data: Vec::new(),
            metric_guard: None,
            _slot: admission.slot,
        };
        let frame = match self
            .wait_for_udp_open_frame(flow_id, &mut flow.frames, local, tcp_buf, shutdown_rx)
            .await?
        {
            UdpOpenWaitOutcome::Frame(frame) => frame,
            UdpOpenWaitOutcome::Cancelled => return Ok(OpenOutcome::Cancelled),
            UdpOpenWaitOutcome::TimedOut => {
                return Ok(OpenOutcome::Rejected(socks5::Reply::GeneralFailure));
            }
        };
        match decode_udp_open_response(frame) {
            Ok(OpenResponse::Accepted) => {
                flow.metric_guard =
                    Some(self.metrics.begin_flow(FlowProtocol::Udp.metric_protocol()));
                Ok(OpenOutcome::Open(flow))
            }
            Ok(OpenResponse::Rejected(reply)) => {
                self.remove_flow(flow_id).await;
                Ok(OpenOutcome::Rejected(reply))
            }
            Err(err) => {
                self.remove_flow(flow_id).await;
                report_protocol_error(self).await;
                Err(err)
            }
        }
    }

    pub(crate) async fn wait_for_open_frame(
        &self,
        flow_id: u64,
        frames: &mut mpsc::Receiver<BufferedFlowFrame>,
        local: &mut TcpStream,
        pending_local_data: &mut PendingOpenLocalData,
        shutdown_rx: &mut watch::Receiver<bool>,
    ) -> Result<OpenWaitOutcome, AnyError> {
        if let Some(timeout) = self.open_timeout {
            if let Ok(result) = time::timeout(
                timeout,
                self.wait_for_open_frame_inner(
                    flow_id,
                    frames,
                    local,
                    pending_local_data,
                    shutdown_rx,
                ),
            )
            .await
            {
                result
            } else {
                warn!(event = "client.flow.open.timeout", flow_id);
                self.cancel_pending_open(flow_id).await;
                Ok(OpenWaitOutcome::TimedOut)
            }
        } else {
            self.wait_for_open_frame_inner(flow_id, frames, local, pending_local_data, shutdown_rx)
                .await
        }
    }

    pub(crate) async fn wait_for_udp_open_frame(
        &self,
        flow_id: u64,
        frames: &mut mpsc::Receiver<BufferedFlowFrame>,
        local: &mut TcpStream,
        tcp_buf: &mut [u8; 1],
        shutdown_rx: &mut watch::Receiver<bool>,
    ) -> Result<UdpOpenWaitOutcome, AnyError> {
        if let Some(timeout) = self.open_timeout {
            if let Ok(result) = time::timeout(
                timeout,
                self.wait_for_udp_open_frame_inner(flow_id, frames, local, tcp_buf, shutdown_rx),
            )
            .await
            {
                result
            } else {
                warn!(event = "client.udp_flow.open.timeout", flow_id);
                self.cancel_pending_udp_open(flow_id).await;
                Ok(UdpOpenWaitOutcome::TimedOut)
            }
        } else {
            self.wait_for_udp_open_frame_inner(flow_id, frames, local, tcp_buf, shutdown_rx)
                .await
        }
    }

    pub(crate) async fn wait_for_udp_open_frame_inner(
        &self,
        flow_id: u64,
        frames: &mut mpsc::Receiver<BufferedFlowFrame>,
        local: &mut TcpStream,
        tcp_buf: &mut [u8; 1],
        shutdown_rx: &mut watch::Receiver<bool>,
    ) -> Result<UdpOpenWaitOutcome, AnyError> {
        loop {
            tokio::select! {
                frame = frames.recv() => {
                    let Some(frame) = frame else {
                        return Err("uk session closed while opening udp flow".into());
                    };
                    return Ok(UdpOpenWaitOutcome::Frame(frame.into_frame()?));
                }
                read = local.read(tcp_buf) => {
                    match read {
                        Ok(0) => {
                            debug!(event = "client.udp_flow.open.cancelled", flow_id);
                            self.cancel_pending_udp_open(flow_id).await;
                            return Ok(UdpOpenWaitOutcome::Cancelled);
                        }
                        Ok(_) => {
                            debug!(event = "socks5.udp_associate.control_data_ignored");
                        }
                        Err(err) => {
                            debug!(
                                event = "client.udp_flow.open.control_read_error",
                                flow_id,
                                error = %err
                            );
                            self.cancel_pending_udp_open(flow_id).await;
                            return Ok(UdpOpenWaitOutcome::Cancelled);
                        }
                    }
                }
                changed = shutdown_rx.changed() => {
                    let _ = changed;
                    self.cancel_pending_udp_open(flow_id).await;
                    return Ok(UdpOpenWaitOutcome::Cancelled);
                }
            }
        }
    }

    pub(crate) async fn wait_for_open_frame_inner(
        &self,
        flow_id: u64,
        frames: &mut mpsc::Receiver<BufferedFlowFrame>,
        local: &mut TcpStream,
        pending_local_data: &mut PendingOpenLocalData,
        shutdown_rx: &mut watch::Receiver<bool>,
    ) -> Result<OpenWaitOutcome, AnyError> {
        loop {
            tokio::select! {
                frame = frames.recv() => {
                    let Some(frame) = frame else {
                        return Err("uk session closed while opening flow".into());
                    };
                    return Ok(OpenWaitOutcome::Frame(frame.into_frame()?));
                }
                read = pending_local_data.read_from(
                    local,
                    self.data_frame_size,
                    self.max_pending_open_bytes,
                ) => {
                    match read {
                        PendingOpenLocalRead::Buffered => {}
                        PendingOpenLocalRead::Closed => {
                            debug!(event = "client.flow.open.cancelled", flow_id);
                            self.cancel_pending_open(flow_id).await;
                            return Ok(OpenWaitOutcome::Cancelled);
                        }
                        PendingOpenLocalRead::ResourceLimit => {
                            warn!(
                                event = "client.flow.open.local_buffer_limit",
                                flow_id,
                                buffered_bytes = pending_local_data.queued_bytes()
                            );
                            self.cancel_pending_open(flow_id).await;
                            return Ok(OpenWaitOutcome::LocalResourceLimit);
                        }
                    }
                }
                changed = shutdown_rx.changed() => {
                    let _ = changed;
                    self.cancel_pending_open(flow_id).await;
                    return Ok(OpenWaitOutcome::Cancelled);
                }
            }
        }
    }

    pub(crate) async fn cancel_pending_open(&self, flow_id: u64) {
        let _ = self.send_tcp_close(flow_id, TCP_CLOSE_ERROR).await;
        self.remove_flow(flow_id).await;
    }

    pub(crate) async fn cancel_pending_udp_open(&self, flow_id: u64) {
        let _ = self.send_udp_close(flow_id, UDP_CLOSE_ERROR).await;
        self.remove_flow(flow_id).await;
    }

    pub(crate) async fn reserve_flow(
        &self,
        protocol: FlowProtocol,
    ) -> Result<Option<(u64, mpsc::Receiver<BufferedFlowFrame>)>, AnyError> {
        let (sender, frames) =
            mpsc::channel(flow_frame_queue_capacity(self.max_buffered_bytes_per_flow));
        let mut flows = self.flows.lock().await;
        if self.is_draining() {
            return Err(Box::new(SessionDrainingError));
        }
        let Some(flow_id) = reserve_flow_slot(
            &mut flows,
            self.max_streams,
            &self.next_flow_id,
            sender,
            protocol,
            self.max_udp_flows,
        )?
        else {
            return Ok(None);
        };
        Ok(Some((flow_id, frames)))
    }

    pub(crate) async fn send_tcp_open(&self, flow_id: u64, target: Target) -> Result<(), AnyError> {
        let open = TcpOpen::new(target, TCP_OPEN_FLAGS_NONE);
        let mut payload = BytesMut::new();
        open.encode(&mut payload)?;
        let frame = Frame::new(FrameType::TcpOpen, 0, flow_id, payload.freeze())?;
        self.write_frame(&frame).await
    }

    pub(crate) async fn send_udp_open(&self, flow_id: u64, target: Target) -> Result<(), AnyError> {
        let open = UdpOpen::new(target);
        let mut payload = BytesMut::new();
        open.encode(&mut payload)?;
        let frame = Frame::new(FrameType::UdpOpen, 0, flow_id, payload.freeze())?;
        self.write_frame(&frame).await
    }

    pub(crate) async fn send_tcp_data(&self, flow_id: u64, payload: Bytes) -> Result<(), AnyError> {
        let frame = Frame::new(FrameType::TcpData, 0, flow_id, payload)?;
        let payload_len = frame.payload.len();
        self.write_frame(&frame).await?;
        self.metrics.record_relay_bytes(
            RelayProtocol::Tcp,
            RelayDirection::LocalToServer,
            payload_len,
        );
        Ok(())
    }

    /// Whether this server offers UDP relay at all.
    ///
    /// A server may advertise the QUIC DATAGRAM data path without the reliable
    /// stream fallback (`uk-proto` treats the two settings independently), and
    /// flow *creation* always uses a `UDP_OPEN` frame regardless. Gating flows
    /// on the stream fallback alone conflated "can open a UDP flow" with "can
    /// carry UDP data on the stream" and refused UDP entirely against such a
    /// peer, leaving `try_send_udp_datagram` dead code.
    pub(crate) fn supports_udp_relay(&self) -> bool {
        self.supports_udp_stream_fallback || self.supports_udp_datagram
    }

    /// Largest UDP payload this session can carry to `flow_id`.
    ///
    /// With no stream fallback the datagram channel is the only data path, so
    /// its limit is the real one; otherwise a `UDP_DATA` frame can carry the
    /// rest.
    pub(crate) fn max_udp_payload_len_for(&self, flow_id: u64) -> usize {
        if self.supports_udp_stream_fallback {
            return self.data_frame_size;
        }
        let datagram_limit = self
            .datagrams
            .as_ref()
            .and_then(|channel| channel.max_datagram_size())
            .and_then(|max| {
                datagram::overhead(flow_id)
                    .ok()
                    .and_then(|overhead| max.checked_sub(overhead))
            })
            .unwrap_or(0);
        datagram_limit.min(self.data_frame_size)
    }

    pub(crate) async fn send_udp_data(&self, flow_id: u64, payload: Bytes) -> Result<(), AnyError> {
        let payload_len = payload.len();
        // Prefer the QUIC DATAGRAM path; fall back to a reliable UDP_DATA frame
        // when datagrams are unavailable or the payload is too large.
        if self.try_send_udp_datagram(flow_id, &payload) {
            self.metrics.record_relay_bytes(
                RelayProtocol::Udp,
                RelayDirection::LocalToServer,
                payload_len,
            );
            return Ok(());
        }
        if !self.supports_udp_stream_fallback {
            // Datagram-only peer: a UDP_DATA frame would be a protocol error,
            // so drop rather than send something the server cannot accept.
            return Err("uk udp datagram could not be sent and the server has no \
                        reliable UDP fallback"
                .into());
        }
        let frame = Frame::new(FrameType::UdpData, 0, flow_id, payload)?;
        self.write_frame(&frame).await?;
        self.metrics.record_relay_bytes(
            RelayProtocol::Udp,
            RelayDirection::LocalToServer,
            payload_len,
        );
        Ok(())
    }

    /// Attempts to send one UDP payload over the QUIC DATAGRAM channel. Returns
    /// `false` (fall back to the frame path) when datagrams are disabled,
    /// unavailable, or the payload is too large for the current datagram size.
    pub(crate) fn try_send_udp_datagram(&self, flow_id: u64, payload: &[u8]) -> bool {
        if !self.supports_udp_datagram {
            return false;
        }
        let Some(channel) = self.datagrams.as_ref() else {
            return false;
        };
        let Some(max_datagram_size) = channel.max_datagram_size() else {
            return false;
        };
        let Ok(overhead) = datagram::overhead(flow_id) else {
            return false;
        };
        if overhead.saturating_add(payload.len()) > max_datagram_size {
            return false;
        }
        let mut encoded = BytesMut::with_capacity(overhead + payload.len());
        if datagram::encode(flow_id, payload, &mut encoded).is_err() {
            return false;
        }
        matches!(channel.send(encoded.freeze()), DatagramSendOutcome::Sent)
    }

    pub(crate) async fn send_tcp_close(
        &self,
        flow_id: u64,
        close_code: u16,
    ) -> Result<(), AnyError> {
        let mut payload = BytesMut::new();
        TcpClose::new(close_code).encode(&mut payload)?;
        let frame = Frame::new(FrameType::TcpClose, 0, flow_id, payload.freeze())?;
        self.write_frame(&frame).await
    }

    pub(crate) async fn send_udp_close(
        &self,
        flow_id: u64,
        close_code: u16,
    ) -> Result<(), AnyError> {
        let mut payload = BytesMut::new();
        UdpClose::new(close_code).encode(&mut payload)?;
        let frame = Frame::new(FrameType::UdpClose, 0, flow_id, payload.freeze())?;
        self.write_frame(&frame).await
    }

    pub(crate) async fn send_resource_limit(&self, flow_id: u64) -> Result<(), AnyError> {
        self.send_status_frame(FrameType::ResourceLimit, flow_id, ErrorCode::ResourceLimit)
            .await
    }

    pub(crate) async fn send_connection_error(&self, code: ErrorCode) -> Result<(), AnyError> {
        self.send_status_frame(FrameType::Error, 0, code).await
    }

    pub(crate) async fn send_status_frame(
        &self,
        frame_type: FrameType,
        flow_id: u64,
        code: ErrorCode,
    ) -> Result<(), AnyError> {
        let frame = status_frame(frame_type, flow_id, code)?;
        self.write_frame(&frame).await
    }

    pub(crate) async fn write_pong(&self, request_frame: &Frame) -> Result<(), AnyError> {
        let pong_frame = Frame::new(
            FrameType::Pong,
            0,
            request_frame.header.id,
            request_frame.payload.clone(),
        )?;
        self.write_frame(&pong_frame).await
    }

    pub(crate) async fn write_ping(&self) -> Result<u64, AnyError> {
        let nonce =
            next_keepalive_nonce(&self.next_ping_nonce).ok_or("keepalive nonce space exhausted")?;
        self.outstanding_ping_nonce.store(nonce, Ordering::SeqCst);
        let frame = Frame::new(FrameType::Ping, 0, 0, keepalive_nonce_payload(nonce))?;
        if let Err(err) = self.write_frame(&frame).await {
            self.clear_outstanding_ping(nonce);
            return Err(err);
        }
        Ok(nonce)
    }

    pub(crate) fn observed_pong_nonce(&self) -> u64 {
        self.last_pong_nonce.load(Ordering::SeqCst)
    }

    pub(crate) fn record_pong(&self, payload: &Bytes) {
        match record_matching_pong(&self.outstanding_ping_nonce, &self.last_pong_nonce, payload) {
            KeepalivePong::Matched(_) => self.pong_notify.notify_waiters(),
            KeepalivePong::InvalidPayload => {
                debug!(
                    event = "client.session.keepalive.pong_ignored",
                    payload_len = payload.len()
                );
            }
            KeepalivePong::Unexpected {
                nonce,
                expected_nonce,
            } => {
                debug!(
                    event = "client.session.keepalive.pong_ignored",
                    nonce, expected_nonce
                );
            }
        }
    }

    pub(crate) fn clear_outstanding_ping(&self, nonce: u64) {
        let _ = self.outstanding_ping_nonce.compare_exchange(
            nonce,
            0,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
    }

    pub(crate) async fn wait_for_pong(&self, nonce: u64) -> bool {
        loop {
            let notified = self.pong_notify.notified();
            if self.is_closed() {
                return false;
            }
            if self.observed_pong_nonce() == nonce {
                return true;
            }
            notified.await;
        }
    }

    pub(crate) async fn write_frame(&self, frame: &Frame) -> Result<(), AnyError> {
        let result = write_frame_locked(
            &self.writer,
            frame,
            &self.shutdown,
            self.task_shutdown_timeout,
        )
        .await;
        if result.is_err() {
            self.close().await;
        }
        result
    }
}

pub(crate) fn reserve_flow_slot(
    flows: &mut HashMap<u64, ClientFlowRoute>,
    max_streams: u64,
    next_flow_id: &AtomicU64,
    sender: mpsc::Sender<BufferedFlowFrame>,
    protocol: FlowProtocol,
    max_udp_flows: u64,
) -> Result<Option<u64>, AnyError> {
    if flows.len() as u64 >= max_streams {
        return Ok(None);
    }
    let max_udp_flows = usize::try_from(max_udp_flows).unwrap_or(usize::MAX);
    if protocol == FlowProtocol::Udp && udp_route_count(flows) >= max_udp_flows {
        return Ok(None);
    }

    for _ in 0..FLOW_ID_ALLOCATION_ATTEMPTS {
        let Some(flow_id) = allocate_client_flow_id(next_flow_id) else {
            return Err("client flow id space exhausted".into());
        };
        if !is_client_initiated_flow_id(flow_id) {
            continue;
        }

        if let Entry::Vacant(entry) = flows.entry(flow_id) {
            entry.insert(ClientFlowRoute::new(sender, protocol));
            return Ok(Some(flow_id));
        }
    }

    Err("no available client flow id".into())
}

pub(crate) fn udp_route_count(flows: &HashMap<u64, ClientFlowRoute>) -> usize {
    flows
        .values()
        .filter(|route| route.protocol == FlowProtocol::Udp)
        .count()
}
