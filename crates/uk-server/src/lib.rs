//! Uncrowned King server library.

pub mod config;
pub(crate) mod masking;
mod observability;
pub mod quic;
pub mod rate_limit;
mod relay;
mod security;
mod tls;

use std::{
    error::Error,
    fmt, future,
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use bytes::BytesMut;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch},
    task::JoinSet,
    time,
};
use tokio_rustls::TlsAcceptor;
use tracing::{Instrument, debug, info, info_span, warn};
use uk_auth::{
    AuthChallenge, AuthResponse, AuthenticatedIdentity, ReplayCache, try_unix_now,
    verify_auth_response_identity_stateless,
};
use uk_proto::{
    BoxedCarrierReader, BoxedCarrierWriter, BoxedDatagramChannel, ErrorCode, ErrorPayload, Frame,
    FrameIoError, FrameLimits, FrameType, PROTOCOL_REVISION_V1_0, SettingKey, Settings, read_frame,
    validate_connection_frame, write_frame,
};

use crate::config::ServerConfig;
use crate::observability::{HandshakeFailureReason, ServerMetrics};
use crate::security::{AuthenticationSnapshot, SecurityState};

/// Server error type.
pub type AnyError = Box<dyn Error + Send + Sync>;

/// Carrier halves plus authenticated identity produced by a completed
/// carrier handshake (TLS/TCP or QUIC).
type HandshakeOutput = (
    BoxedCarrierReader,
    BoxedCarrierWriter,
    Option<BoxedDatagramChannel>,
    AuthenticatedIdentity,
);

const ACCEPT_RETRY_BASE_MILLIS: u64 = 10;
const ACCEPT_RETRY_MAX_MILLIS: u64 = 1_000;
const RELOAD_CHANNEL_CAPACITY: usize = 1;
static NEXT_CONNECTION_CORRELATION_ID: AtomicU64 = AtomicU64::new(1);

/// Sends validated security config reloads to a running server.
#[derive(Clone, Debug)]
pub struct ServerReloadHandle {
    tx: mpsc::Sender<ServerReloadRequest>,
}

/// Receives security config reloads inside the server listener loop.
#[derive(Debug)]
pub struct ServerReloadReceiver {
    rx: mpsc::Receiver<ServerReloadRequest>,
}

#[derive(Debug)]
struct ServerReloadRequest {
    config: Result<ServerConfig, String>,
    response: oneshot::Sender<Result<u64, String>>,
}

/// Error returned when a server config reload cannot be applied.
#[derive(Debug, PartialEq, Eq)]
pub enum ServerReloadError {
    /// The server stopped before it could apply the reload.
    ServerStopped,
    /// The candidate config was incompatible or invalid.
    Rejected(String),
}

impl fmt::Display for ServerReloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ServerStopped => formatter.write_str("server stopped before config reload"),
            Self::Rejected(reason) => write!(formatter, "server rejected config reload: {reason}"),
        }
    }
}

impl Error for ServerReloadError {}

impl ServerReloadHandle {
    /// Waits until the server atomically applies or rejects the candidate config.
    pub async fn reload(&self, config: ServerConfig) -> Result<u64, ServerReloadError> {
        let (response, result) = oneshot::channel();
        self.tx
            .send(ServerReloadRequest {
                config: Ok(config),
                response,
            })
            .await
            .map_err(|_| ServerReloadError::ServerStopped)?;
        result
            .await
            .map_err(|_| ServerReloadError::ServerStopped)?
            .map_err(ServerReloadError::Rejected)
    }

    /// Reports a disk-load or parse failure so the reload failure counter is incremented.
    pub async fn report_load_failure(&self, reason: String) -> Result<(), ServerReloadError> {
        let (response, result) = oneshot::channel();
        self.tx
            .send(ServerReloadRequest {
                config: Err(reason),
                response,
            })
            .await
            .map_err(|_| ServerReloadError::ServerStopped)?;
        result
            .await
            .map_err(|_| ServerReloadError::ServerStopped)?
            .map(|_| ())
            .map_err(ServerReloadError::Rejected)
    }
}

/// Creates a bounded server config reload channel.
pub fn server_reload_channel() -> (ServerReloadHandle, ServerReloadReceiver) {
    let (tx, rx) = mpsc::channel(RELOAD_CHANNEL_CAPACITY);
    (ServerReloadHandle { tx }, ServerReloadReceiver { rx })
}

#[derive(Default)]
struct ListenerAcceptBackoff {
    consecutive_failures: u32,
}

impl ListenerAcceptBackoff {
    fn next_delay(&mut self) -> Duration {
        let shift = self.consecutive_failures.min(7);
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        Duration::from_millis(
            ACCEPT_RETRY_BASE_MILLIS
                .saturating_mul(1_u64 << shift)
                .min(ACCEPT_RETRY_MAX_MILLIS),
        )
    }

    fn reset(&mut self) {
        self.consecutive_failures = 0;
    }
}

#[derive(Debug)]
struct HandshakePhaseError {
    phase: &'static str,
    failure_reason: HandshakeFailureReason,
    source: AnyError,
}

impl fmt::Display for HandshakePhaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} failed: {}", self.phase, self.source)
    }
}

impl Error for HandshakePhaseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

struct ServerRuntime {
    config: Arc<ServerConfig>,
    security: SecurityState,
    replay_cache: Arc<Mutex<ReplayCache>>,
    auth_rate_limiter: Arc<rate_limit::AuthRateLimiter>,
    max_sessions: usize,
    max_handshakes: usize,
    /// Built while the config still holds its credentials (before they are
    /// moved into the security state and zeroized in the config).
    masking: Option<Arc<masking::MaskingState>>,
}

#[derive(Clone)]
struct ConnectionRuntime {
    security: SecurityState,
    replay_cache: Arc<Mutex<ReplayCache>>,
    session_permits: Arc<Semaphore>,
    config: Arc<ServerConfig>,
    handshake_permits: Arc<Semaphore>,
    auth_rate_limiter: Arc<rate_limit::AuthRateLimiter>,
    max_sessions: usize,
    max_handshakes: usize,
    global_buffer: relay::GlobalBufferControl,
    global_flows: relay::GlobalFlowBudget,
    metrics: Arc<ServerMetrics>,
    /// Present only when `[masking] enabled = true`: the TLS/TCP admission
    /// gate with its prelude replay registry.
    masking: Option<Arc<masking::MaskingState>>,
}

impl ConnectionRuntime {
    /// Runs the admission checks shared by the TCP and QUIC accept paths:
    /// the handshake-DoS rate limiter, then session-permit availability.
    /// Metrics are recorded and rejections logged here; the caller only has
    /// to refuse the pending connection in its carrier-specific way (`drop`
    /// the TCP stream to send RST, `refuse()` the QUIC incoming).
    fn admit_precheck(&self, peer: SocketAddr, carrier: &'static str) -> bool {
        if !self.auth_rate_limiter.check(peer.ip()) {
            self.metrics.record_rate_limited_connection();
            warn!(
                event = "server.auth_rate_limit.rejected",
                peer = %peer,
                carrier = carrier,
                "IP is temporarily banned due to excessive authentication failures"
            );
            return false;
        }

        self.metrics.record_accepted_connection();
        if self.session_permits.available_permits() == 0 {
            self.metrics.record_rejected_session();
            warn!(
                event = "server.session.limit",
                peer = %peer,
                carrier = carrier,
                max_sessions = self.max_sessions
            );
            return false;
        }
        true
    }

    /// Takes a handshake permit, recording the rejection when none remain.
    fn acquire_handshake_permit(
        &self,
        peer: SocketAddr,
        carrier: &'static str,
    ) -> Option<OwnedSemaphorePermit> {
        let Ok(handshake_permit) = Arc::clone(&self.handshake_permits).try_acquire_owned() else {
            self.metrics.record_rejected_handshake();
            warn!(
                event = "server.handshake.limit",
                peer = %peer,
                carrier = carrier,
                max_handshakes = self.max_handshakes
            );
            return None;
        };
        Some(handshake_permit)
    }

    fn spawn_accepted(
        &self,
        connections: &mut JoinSet<()>,
        tcp: TcpStream,
        peer: SocketAddr,
        shutdown_rx: watch::Receiver<bool>,
    ) {
        // No handshake permit yet: when masking is enabled the connection
        // must clear the prelude gate first, so silently drained probes never
        // hold handshake budget. handle_connection takes the permit itself.
        if !self.admit_precheck(peer, "tcp") {
            // Drop the stream immediately (sending RST) instead of awaiting a
            // graceful shutdown. A malicious peer that holds the TCP half-close
            // open would otherwise block the entire accept loop.
            drop(tcp);
            return;
        }
        let runtime = self.clone();
        let connection_id = next_connection_correlation_id();
        let connection = async move {
            if let Err(err) = Box::pin(handle_connection(runtime, tcp, peer, shutdown_rx)).await {
                if is_clean_tls_handshake_disconnect(&err) {
                    debug!(event = "tls.handshake.closed", peer = %peer);
                } else {
                    warn!(event = "protocol.error", peer = %peer, error = %err);
                }
            }
        };
        connections.spawn(connection.instrument(info_span!(
            "server.connection",
            connection_id,
            peer = %peer
        )));
    }

    fn spawn_accepted_quic(
        &self,
        connections: &mut JoinSet<()>,
        incoming: quinn::Incoming,
        peer: SocketAddr,
        shutdown_rx: watch::Receiver<bool>,
    ) {
        // Validate the source address before it can consume any shared budget:
        // a Retry costs one stateless packet and proves the peer can receive
        // at the claimed address, so spoofed Initials never hold a permit.
        if !incoming.remote_address_validated() && incoming.may_retry() {
            if let Err(err) = incoming.retry() {
                err.into_incoming().ignore();
            }
            self.metrics.record_quic_retry();
            return;
        }
        if !self.admit_precheck(peer, "quic") {
            incoming.refuse();
            return;
        }
        let Some(handshake_permit) = self.acquire_handshake_permit(peer, "quic") else {
            incoming.refuse();
            return;
        };
        let runtime = self.clone();
        let connection_id = next_connection_correlation_id();
        let connection = async move {
            if let Err(err) = Box::pin(handle_quic_connection(
                runtime,
                incoming,
                handshake_permit,
                peer,
                shutdown_rx,
            ))
            .await
            {
                warn!(event = "protocol.error", peer = %peer, carrier = "quic", error = %err);
            }
        };
        connections.spawn(connection.instrument(info_span!(
            "server.connection",
            connection_id,
            peer = %peer,
            carrier = "quic"
        )));
    }
}

/// Runs the UK server listener until the task is cancelled or the listener fails.
pub async fn run(config: ServerConfig) -> Result<(), AnyError> {
    run_until_shutdown(config, future::pending()).await
}

/// Runs the UK server listener until `shutdown` resolves or the listener fails.
pub async fn run_until_shutdown<F>(config: ServerConfig, shutdown: F) -> Result<(), AnyError>
where
    F: Future<Output = ()> + Send,
{
    let runtime = prepare_server_runtime(config)?;
    let listener = TcpListener::bind(&runtime.config.listen).await?;
    run_on_listener_inner(runtime, listener, None, shutdown).await
}

/// Runs the UK server until shutdown and applies validated security config reloads.
pub async fn run_until_shutdown_with_reload<F>(
    config: ServerConfig,
    reload_rx: ServerReloadReceiver,
    shutdown: F,
) -> Result<(), AnyError>
where
    F: Future<Output = ()> + Send,
{
    let runtime = prepare_server_runtime(config)?;
    let listener = TcpListener::bind(&runtime.config.listen).await?;
    run_on_listener_inner(runtime, listener, Some(reload_rx), shutdown).await
}

/// Runs the UK server on an already-bound listener until the task is cancelled or the listener fails.
pub async fn run_on_listener(config: ServerConfig, listener: TcpListener) -> Result<(), AnyError> {
    run_on_listener_until_shutdown(config, listener, future::pending()).await
}

/// Runs the UK server on an already-bound listener until `shutdown` resolves or the listener fails.
pub async fn run_on_listener_until_shutdown<F>(
    mut config: ServerConfig,
    listener: TcpListener,
    shutdown: F,
) -> Result<(), AnyError>
where
    F: Future<Output = ()> + Send,
{
    config.listen = listener.local_addr()?.to_string();
    let runtime = prepare_server_runtime(config)?;
    run_on_listener_inner(runtime, listener, None, shutdown).await
}

/// Runs an already-bound server until shutdown and applies validated security config reloads.
pub async fn run_on_listener_until_shutdown_with_reload<F>(
    mut config: ServerConfig,
    listener: TcpListener,
    reload_rx: ServerReloadReceiver,
    shutdown: F,
) -> Result<(), AnyError>
where
    F: Future<Output = ()> + Send,
{
    config.listen = listener.local_addr()?.to_string();
    let runtime = prepare_server_runtime(config)?;
    run_on_listener_inner(runtime, listener, Some(reload_rx), shutdown).await
}

#[allow(clippy::too_many_lines)]
async fn run_on_listener_inner<F>(
    runtime: ServerRuntime,
    listener: TcpListener,
    mut reload_rx: Option<ServerReloadReceiver>,
    shutdown: F,
) -> Result<(), AnyError>
where
    F: Future<Output = ()> + Send,
{
    let ServerRuntime {
        config,
        security,
        replay_cache,
        auth_rate_limiter,
        max_sessions,
        max_handshakes,
        masking,
    } = runtime;
    let listen = listener.local_addr()?;
    let session_permits = Arc::new(Semaphore::new(max_sessions));
    let handshake_permits = Arc::new(Semaphore::new(max_handshakes));
    let shutdown_timeout = listener_shutdown_timeout(config.shutdown_timeout_seconds());
    let metrics = Arc::new(ServerMetrics::default());
    metrics.set_security_generation(security.generation());
    let global_buffer_limit = usize_limit(
        "max_total_buffered_bytes",
        config.max_total_buffered_bytes(),
    )?;
    let global_flow_limit = usize_limit("max_total_streams", config.max_total_streams())?;
    let (global_buffered_bytes, global_active_flows) = metrics.global_budget_counters();
    metrics.set_global_budget_limits(global_buffer_limit, global_flow_limit);
    let connection_runtime = ConnectionRuntime {
        security: security.clone(),
        replay_cache: Arc::clone(&replay_cache),
        session_permits: Arc::clone(&session_permits),
        config: Arc::clone(&config),
        handshake_permits,
        auth_rate_limiter,
        max_sessions,
        max_handshakes,
        global_buffer: relay::GlobalBufferControl::new(global_buffer_limit, global_buffered_bytes),
        global_flows: relay::GlobalFlowBudget::new(global_flow_limit, global_active_flows),
        metrics: Arc::clone(&metrics),
        masking,
    };

    info!(event = "server.listen", listen = %listen);

    let quic_endpoint = bind_and_log_quic_endpoint(&config, connection_runtime.masking.as_ref())?;

    let (shutdown_tx, _shutdown_rx) = watch::channel(false);
    let (observability_shutdown_tx, observability_shutdown_rx) = watch::channel(false);
    let observability_task =
        start_observability(&config, Arc::clone(&metrics), observability_shutdown_rx).await?;
    metrics.set_ready(true);
    let mut connections = JoinSet::new();
    let mut accept_backoff = ListenerAcceptBackoff::default();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            () = &mut shutdown => {
                info!(event = "server.shutdown");
                begin_server_shutdown(&metrics, &shutdown_tx);
                break;
            }
            reload = receive_reload(&mut reload_rx) => {
                if let Some(request) = reload {
                    handle_reload_request(
                        &config,
                        &security,
                        quic_endpoint.as_ref(),
                        &metrics,
                        request,
                    )
                    .await;
                } else {
                    reload_rx = None;
                    debug!(event = "server.config.reload_channel_closed");
                }
            }
            accepted = listener.accept() => {
                let (tcp, peer) = match accepted {
                    Ok(connection) => {
                        accept_backoff.reset();
                        connection
                    }
                    Err(err) => {
                        let retry_delay = accept_backoff.next_delay();
                        warn!(
                            event = "server.accept.error",
                            error = %err,
                            retry_delay_ms = retry_delay.as_millis()
                        );
                        time::sleep(retry_delay).await;
                        continue;
                    }
                };
                connection_runtime
                    .spawn_accepted(&mut connections, tcp, peer, shutdown_tx.subscribe());
            }
            incoming = accept_quic(quic_endpoint.as_ref()) => {
                if let Some(incoming) = incoming {
                    let peer = incoming.remote_address();
                    connection_runtime.spawn_accepted_quic(
                        &mut connections,
                        incoming,
                        peer,
                        shutdown_tx.subscribe(),
                    );
                }
            }
            joined = connections.join_next(), if !connections.is_empty() => {
                log_connection_task_result(joined);
            }
        }
    }

    drain_connection_tasks(&mut connections, shutdown_deadline(shutdown_timeout)).await;
    if let Some(endpoint) = &quic_endpoint {
        endpoint.close(0_u32.into(), b"server shutdown");
    }
    stop_observability(observability_shutdown_tx, observability_task).await;

    Ok(())
}

/// Converts the configured shutdown timeout into the single deadline shared
/// by the whole shutdown sequence.
///
/// Connection tasks drain their sessions against `session_task_shutdown_timeout`
/// internally, so the listener-level rejoin below must wait on the *same*
/// deadline rather than granting another full timeout on top — otherwise
/// worst-case shutdown would be ~2x the configured value.
/// Additional grace period granted to connection tasks so they can cleanly
/// finish internal teardown after session drainage before the server aborts them.
const SHUTDOWN_DRAIN_BUFFER: Duration = Duration::from_secs(2);

fn shutdown_deadline(shutdown_timeout: Option<Duration>) -> Option<time::Instant> {
    shutdown_timeout.and_then(|timeout| {
        let timeout = if timeout >= Duration::from_secs(1) {
            timeout
                .checked_add(SHUTDOWN_DRAIN_BUFFER)
                .unwrap_or(timeout)
        } else {
            timeout
        };
        time::Instant::now().checked_add(timeout)
    })
}

/// Builds the QUIC endpoint (when configured) and logs its listen address.
fn bind_and_log_quic_endpoint(
    config: &ServerConfig,
    masking: Option<&Arc<masking::MaskingState>>,
) -> Result<Option<quinn::Endpoint>, AnyError> {
    let endpoint = build_quic_endpoint(config, masking)?;
    if let Some(endpoint) = &endpoint {
        info!(event = "server.listen.quic", listen = %endpoint.local_addr()?);
    }
    Ok(endpoint)
}

/// Builds the QUIC server endpoint when `quic_listen` is configured. With
/// `masking.quic` enabled, the endpoint socket is wrapped in the masking
/// layer under the designated credential's keys.
fn build_quic_endpoint(
    config: &ServerConfig,
    masking: Option<&Arc<masking::MaskingState>>,
) -> Result<Option<quinn::Endpoint>, AnyError> {
    let Some(listen) = &config.quic_listen else {
        return Ok(None);
    };
    let addr: SocketAddr = listen
        .parse()
        .map_err(|err| format!("invalid quic_listen address {listen}: {err}"))?;
    let rustls_config = tls::server_config(&config.cert_path, &config.key_path)?;
    let masked_keys = masking.and_then(|state| state.quic_keys());
    let quic_config = quic::server_config_with_transport_params_masked(
        rustls_config,
        idle_timeout(config.idle_timeout_seconds()),
        config.quic_stream_receive_window(),
        config.quic_connection_receive_window(),
        masked_keys.is_some(),
    )?;
    let endpoint = quic::bind_endpoint_masked(quic_config, addr, masked_keys.cloned())?;
    Ok(Some(endpoint))
}

/// Accepts the next QUIC connection, or waits forever when QUIC is disabled.
async fn accept_quic(endpoint: Option<&quinn::Endpoint>) -> Option<quinn::Incoming> {
    match endpoint {
        Some(endpoint) => endpoint.accept().await,
        None => future::pending().await,
    }
}

async fn handle_reload_request(
    config: &ServerConfig,
    security: &SecurityState,
    quic_endpoint: Option<&quinn::Endpoint>,
    metrics: &ServerMetrics,
    request: ServerReloadRequest,
) {
    // Reload runs inline in the accept loop, so a wedged filesystem (certs on
    // a hung NFS mount) would otherwise stall accepting new connections for
    // as long as the blocking read takes. Bounded like the client's CA load.
    const RELOAD_TIMEOUT: Duration = Duration::from_secs(30);

    let current = config.clone();
    let security = security.clone();
    let quic_endpoint = quic_endpoint.cloned();

    let result: Result<u64, AnyError> = match request.config {
        Ok(candidate) => {
            let reload = tokio::task::spawn_blocking(move || {
                apply_security_reload(&current, &security, quic_endpoint.as_ref(), candidate)
            });
            match tokio::time::timeout(RELOAD_TIMEOUT, reload).await {
                Ok(joined) => joined.unwrap_or_else(|err| Err(Box::new(err))),
                Err(_) => Err(format!(
                    "security reload exceeded {}s; keeping the previous generation",
                    RELOAD_TIMEOUT.as_secs()
                )
                .into()),
            }
        }
        Err(reason) => Err(Box::<dyn std::error::Error + Send + Sync>::from(reason)),
    };

    match result {
        Ok(generation) => {
            metrics.record_config_reload_success(generation);
            info!(
                event = "server.config.reload_success",
                security_generation = generation
            );
            let _ = request.response.send(Ok(generation));
        }
        Err(err) => {
            metrics.record_config_reload_failure();
            warn!(event = "server.config.reload_failure", error = %err);
            let _ = request.response.send(Err(err.to_string()));
        }
    }
}

async fn receive_reload(
    reload_rx: &mut Option<ServerReloadReceiver>,
) -> Option<ServerReloadRequest> {
    match reload_rx {
        Some(reload_rx) => reload_rx.rx.recv().await,
        None => future::pending().await,
    }
}

fn begin_server_shutdown(metrics: &ServerMetrics, shutdown_tx: &watch::Sender<bool>) {
    metrics.set_ready(false);
    let _ = shutdown_tx.send(true);
}

fn next_connection_correlation_id() -> u64 {
    NEXT_CONNECTION_CORRELATION_ID.fetch_add(1, Ordering::Relaxed)
}

async fn start_observability(
    config: &ServerConfig,
    metrics: Arc<ServerMetrics>,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<Option<tokio::task::JoinHandle<()>>, AnyError> {
    let Some(listen) = &config.observability_listen else {
        return Ok(None);
    };
    // Bind the resolved — wildcard-checked — addresses rather than the raw
    // string: resolver semantics accept numeric forms ("0:9090") the static
    // validator cannot see, and those bind 0.0.0.0.
    let addrs = uk_proto::resolve_observability_bind("observability_listen", listen)?;
    let listener = TcpListener::bind(addrs.as_slice()).await?;
    Ok(Some(tokio::spawn(observability::serve(
        listener,
        metrics,
        shutdown_rx,
    ))))
}

async fn stop_observability(
    shutdown_tx: watch::Sender<bool>,
    task: Option<tokio::task::JoinHandle<()>>,
) {
    let _ = shutdown_tx.send(true);
    if let Some(task) = task {
        if let Err(err) = task.await {
            warn!(event = "server.observability.task_error", error = %err);
        }
    }
}

fn prepare_server_runtime(mut config: ServerConfig) -> Result<ServerRuntime, AnyError> {
    config.validate_network_endpoints()?;
    config.validate_limits()?;
    config.validate_sensitive_paths()?;
    let masking = build_masking_state(&config);
    let tls_config = tls::server_config(&config.cert_path, &config.key_path)?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let credentials = take_runtime_credentials(&mut config)?;
    let mask_keys = derive_mask_keys(&config, &credentials);
    let policy_set = config.policy_set()?;
    let security = SecurityState::new(
        tls_acceptor,
        credentials,
        mask_keys,
        policy_set,
        Duration::from_secs(config.auth_skew_seconds()),
    );
    let replay_cache = Arc::new(Mutex::new(ReplayCache::with_max_entries(
        Duration::from_secs(config.replay_cache_window_seconds()),
        usize_limit(
            "replay_cache_max_entries",
            config.replay_cache_max_entries(),
        )?,
    )));
    let auth_rate_limiter = Arc::new(rate_limit::AuthRateLimiter::with_allowlist(
        config.auth_rate_limit_config(),
        config.auth_rate_limit_allowlist_cidrs(),
    ));
    let max_sessions = usize_limit("max_sessions", config.max_sessions())?;
    let max_handshakes = usize_limit("max_handshakes", config.max_handshakes())?;

    Ok(ServerRuntime {
        config: Arc::new(config),
        security,
        replay_cache,
        auth_rate_limiter,
        max_sessions,
        max_handshakes,
        masking,
    })
}

fn take_runtime_credentials(
    config: &mut ServerConfig,
) -> Result<Vec<uk_auth::Credential>, uk_auth::AuthError> {
    let credentials = config.credentials();
    for credential in &mut config.credentials {
        credential.zeroize_secret();
    }
    config.credentials.clear();
    credentials
}

/// Derives the per-credential masking keys when masking is enabled. Key
/// rotation follows credential rotation for new connections only; established
/// connections keep the keystreams they were admitted with.
fn derive_mask_keys(
    config: &ServerConfig,
    credentials: &[uk_auth::Credential],
) -> Vec<uk_mask::MaskKeys> {
    if !config.masking_enabled() && !config.masking_quic_enabled() {
        return Vec::new();
    }
    credentials
        .iter()
        .map(|credential| uk_mask::MaskKeys::derive(&credential.key_id, &credential.secret))
        .collect()
}

/// Builds the masking admission state: the TCP prelude registry plus, when
/// `masking.quic` is on, the QUIC endpoint's designated credential keys.
fn build_masking_state(config: &ServerConfig) -> Option<Arc<masking::MaskingState>> {
    let masking_config = config.masking.as_ref()?;
    let quic_keys = if config.masking_quic_enabled() {
        let key_id = masking_config
            .quic_key_id
            .as_deref()
            .expect("validated in validate_limits");
        let credential = config
            .credentials
            .iter()
            .find(|credential| credential.key_id == key_id)
            .expect("validated in validate_limits");
        Some(uk_mask::MaskKeys::derive(
            credential.key_id.as_bytes(),
            credential.secret.as_bytes(),
        ))
    } else {
        None
    };
    if config.masking_enabled() {
        info!(
            event = "server.masking.enabled",
            replay_identities = config.masking_replay_identities(),
            quic = config.masking_quic_enabled(),
            "transport masking is active"
        );
    } else if config.masking_quic_enabled() {
        info!(
            event = "server.masking.enabled",
            quic = true,
            "transport masking is active on the QUIC listener"
        );
    }
    Some(Arc::new(masking::MaskingState::new(
        config.masking_replay_identities(),
        quic_keys,
    )))
}

fn apply_security_reload(
    current: &ServerConfig,
    security: &SecurityState,
    quic_endpoint: Option<&quinn::Endpoint>,
    mut candidate: ServerConfig,
) -> Result<u64, AnyError> {
    ensure_reload_compatible(current, &candidate)?;
    candidate.validate_network_endpoints()?;
    candidate.validate_limits()?;
    candidate.validate_sensitive_paths()?;
    // Build both carrier crypto configs before touching any live state so an
    // invalid certificate or key fails the reload atomically, leaving the
    // running TLS and QUIC identities in place.
    let (certs, key) = tls::load_identity(&candidate.cert_path, &candidate.key_path)?;
    let tls_server_config = tls::server_config_from_memory(certs.clone(), key.clone_key())?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_server_config));
    let quic_config = if quic_endpoint.is_some() {
        let quic_tls_config = tls::server_config_from_memory(certs, key)?;
        Some(quic::server_config_with_transport_params(
            quic_tls_config,
            idle_timeout(candidate.idle_timeout_seconds()),
            candidate.quic_stream_receive_window(),
            candidate.quic_connection_receive_window(),
        )?)
    } else {
        None
    };
    let credentials = take_runtime_credentials(&mut candidate)?;
    let mask_keys = derive_mask_keys(&candidate, &credentials);
    let policy_set = candidate.policy_set()?;
    let generation = security.replace(
        tls_acceptor,
        credentials,
        mask_keys,
        policy_set,
        Duration::from_secs(candidate.auth_skew_seconds()),
    );
    // Rotate the QUIC identity for new connections; existing QUIC connections
    // keep the config they were accepted with.
    if let (Some(endpoint), Some(quic_config)) = (quic_endpoint, quic_config) {
        endpoint.set_server_config(Some(quic_config));
    }
    Ok(generation)
}

fn ensure_reload_compatible(
    current: &ServerConfig,
    candidate: &ServerConfig,
) -> Result<(), AnyError> {
    if let Some(field) = changed_static_config_field(current, candidate) {
        return Err(reload_requires_restart(field));
    }
    if current.auth_rate_limit_allowlist() != candidate.auth_rate_limit_allowlist() {
        return Err(reload_requires_restart("auth_rate_limit_allowlist"));
    }
    for ((name, current), (_, candidate)) in reload_static_limits(current)
        .into_iter()
        .zip(reload_static_limits(candidate))
    {
        if current != candidate {
            return Err(reload_requires_restart(name));
        }
    }
    Ok(())
}

fn changed_static_config_field(
    current: &ServerConfig,
    candidate: &ServerConfig,
) -> Option<&'static str> {
    if current.listen != candidate.listen {
        Some("listen")
    } else if current.quic_listen != candidate.quic_listen {
        Some("quic_listen")
    } else if current.observability_listen != candidate.observability_listen {
        Some("observability_listen")
    } else if current.masking != candidate.masking {
        Some("masking")
    } else {
        None
    }
}

fn reload_static_limits(config: &ServerConfig) -> [(&'static str, u64); 27] {
    [
        ("max_pre_auth_bytes", config.max_pre_auth_bytes()),
        ("max_frame_size", config.max_frame_size()),
        ("max_sessions", config.max_sessions()),
        ("max_handshakes", config.max_handshakes()),
        ("max_streams", config.max_streams()),
        ("max_udp_flows", config.max_udp_flows()),
        (
            "max_outbound_dials_per_session",
            config.max_outbound_dials_per_session(),
        ),
        (
            "max_buffered_bytes_per_session",
            config.max_buffered_bytes_per_session(),
        ),
        ("idle_timeout_seconds", config.idle_timeout_seconds()),
        (
            "max_buffered_bytes_per_flow",
            config.max_buffered_bytes_per_flow(),
        ),
        ("max_total_streams", config.max_total_streams()),
        (
            "max_total_buffered_bytes",
            config.max_total_buffered_bytes(),
        ),
        (
            "handshake_timeout_seconds",
            config.handshake_timeout_seconds(),
        ),
        (
            "target_connect_timeout_seconds",
            config.target_connect_timeout_seconds(),
        ),
        (
            "tcp_half_close_timeout_seconds",
            config.tcp_half_close_timeout_seconds(),
        ),
        (
            "carrier_write_timeout_seconds",
            config.carrier_write_timeout_seconds(),
        ),
        ("tcp_keepalive_seconds", config.tcp_keepalive_seconds()),
        (
            "udp_flow_idle_timeout_seconds",
            config.udp_flow_idle_timeout_seconds(),
        ),
        (
            "shutdown_timeout_seconds",
            config.shutdown_timeout_seconds(),
        ),
        (
            "replay_cache_window_seconds",
            config.replay_cache_window_seconds(),
        ),
        (
            "replay_cache_max_entries",
            config.replay_cache_max_entries(),
        ),
        ("relay_buffer_size", config.relay_buffer_size() as u64),
        (
            "auth_rate_limit_failures",
            u64::from(config.auth_rate_limit_config().max_failures),
        ),
        (
            "auth_rate_limit_window_seconds",
            config.auth_rate_limit_config().window_secs,
        ),
        (
            "auth_rate_limit_ban_seconds",
            config.auth_rate_limit_config().ban_secs,
        ),
        (
            "quic_stream_receive_window",
            u64::from(config.quic_stream_receive_window()),
        ),
        (
            "quic_connection_receive_window",
            u64::from(config.quic_connection_receive_window()),
        ),
    ]
}

fn reload_requires_restart(field: &str) -> AnyError {
    format!("server config field {field} changed and requires a restart").into()
}

fn log_connection_task_result(result: Option<Result<(), tokio::task::JoinError>>) {
    if let Some(Err(err)) = result {
        warn!(event = "server.connection.task_error", error = %err);
    }
}

async fn drain_connection_tasks(
    connections: &mut JoinSet<()>,
    shutdown_deadline: Option<time::Instant>,
) {
    if let Some(deadline) = shutdown_deadline {
        if time::timeout_at(deadline, join_connection_tasks(connections))
            .await
            .is_err()
        {
            warn!(
                event = "server.shutdown.timeout",
                remaining_connections = connections.len(),
                "shutdown deadline exceeded; aborting remaining connection tasks"
            );
            connections.abort_all();
            join_connection_tasks(connections).await;
        }
    } else {
        join_connection_tasks(connections).await;
    }
}

async fn join_connection_tasks(connections: &mut JoinSet<()>) {
    while let Some(joined) = connections.join_next().await {
        log_connection_task_result(Some(joined));
    }
}

async fn handle_connection(
    runtime: ConnectionRuntime,
    tcp: tokio::net::TcpStream,
    peer: SocketAddr,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<(), AnyError> {
    tcp.set_nodelay(true)?;
    apply_tcp_keepalive(&tcp, runtime.config.tcp_keepalive_seconds(), peer);
    if *shutdown_rx.borrow() {
        return Ok(());
    }
    // The masking gate runs before the handshake permit: a rejected prelude
    // is silently drained and abortively closed without ever holding
    // handshake budget or reaching rustls.
    let shutdown_rx = shutdown_rx;
    // The handshake future is boxed because the masked and plain branches
    // wrap the TCP stream in different types.
    let authentication = runtime.security.authentication_snapshot();
    let replay_cache = Arc::clone(&runtime.replay_cache);
    let config = Arc::clone(&runtime.config);
    let handshake: Pin<Box<dyn Future<Output = Result<HandshakeOutput, AnyError>> + Send>> =
        if let Some(masking) = &runtime.masking {
            let mask_keys = Arc::clone(&authentication.mask_keys);
            let metrics = Arc::clone(&runtime.metrics);
            let limiter = Arc::clone(&runtime.auth_rate_limiter);
            let admission_timeout = Duration::from_secs(runtime.config.handshake_timeout_seconds());
            match masking
                .admit(
                    tcp,
                    &mask_keys,
                    &metrics,
                    &limiter,
                    peer,
                    admission_timeout,
                    shutdown_rx.clone(),
                )
                .await
            {
                Ok(masked) => Box::pin(async move {
                    complete_handshake(masked, authentication, replay_cache, &config).await
                }),
                Err(rejected) => {
                    debug!(
                        event = "server.mask.rejected",
                        peer = %peer,
                        reason = %rejected,
                        "masking admission rejected the connection"
                    );
                    return Ok(());
                }
            }
        } else {
            Box::pin(
                async move { complete_handshake(tcp, authentication, replay_cache, &config).await },
            )
        };
    let Some(handshake_permit) = runtime.acquire_handshake_permit(peer, "tcp") else {
        return Ok(());
    };
    Box::pin(serve_authenticated_carrier(
        runtime,
        handshake_permit,
        peer,
        shutdown_rx,
        handshake,
    ))
    .await
}

async fn handle_quic_connection(
    runtime: ConnectionRuntime,
    incoming: quinn::Incoming,
    handshake_permit: OwnedSemaphorePermit,
    peer: SocketAddr,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<(), AnyError> {
    if *shutdown_rx.borrow() {
        return Ok(());
    }
    let authentication = runtime.security.authentication_snapshot();
    let replay_cache = Arc::clone(&runtime.replay_cache);
    let config = Arc::clone(&runtime.config);
    let handshake = async move {
        let connection = incoming
            .await
            .map_err(|err| phase_error("quic accept", HandshakeFailureReason::Tls, err))?;
        let (reader, writer, exporter, datagrams) = quic::accept_carrier(&connection)
            .await
            .map_err(|err| phase_error("quic carrier", HandshakeFailureReason::Tls, err))?;
        authenticate_carrier(
            reader,
            writer,
            exporter,
            Some(datagrams),
            authentication,
            replay_cache,
            &config,
        )
        .await
    };
    Box::pin(serve_authenticated_carrier(
        runtime,
        handshake_permit,
        peer,
        shutdown_rx,
        handshake,
    ))
    .await
}

/// Applies the handshake timeout, races the handshake against shutdown, and
/// runs the authenticated relay session. Carrier-neutral: both the TLS/TCP and
/// QUIC handlers build a handshake future that yields authenticated channel
/// halves and hand it here.
async fn serve_authenticated_carrier<H>(
    runtime: ConnectionRuntime,
    handshake_permit: OwnedSemaphorePermit,
    peer: SocketAddr,
    mut shutdown_rx: watch::Receiver<bool>,
    handshake: H,
) -> Result<(), AnyError>
where
    H: Future<
        Output = Result<
            (
                BoxedCarrierReader,
                BoxedCarrierWriter,
                Option<BoxedDatagramChannel>,
                AuthenticatedIdentity,
            ),
            AnyError,
        >,
    >,
{
    let timeout = handshake_timeout(runtime.config.handshake_timeout_seconds());
    let handshake = async move {
        if let Some(timeout) = timeout {
            match time::timeout(timeout, handshake).await {
                Ok(result) => result,
                Err(_) => Err(phase_error(
                    "handshake",
                    HandshakeFailureReason::Timeout,
                    "deadline exceeded",
                )),
            }
        } else {
            handshake.await
        }
    };

    let handshake_guard = runtime.metrics.begin_handshake();
    let handshake_result = tokio::select! {
        result = handshake => Some(result),
        changed = shutdown_rx.changed() => {
            let _ = changed;
            None
        }
    };
    let Some(handshake_result) = handshake_result else {
        return Ok(());
    };
    let (carrier_reader, carrier_writer, datagrams, identity) = match handshake_result {
        Ok(handshake) => {
            runtime.auth_rate_limiter.record_success(peer.ip());
            handshake
        }
        Err(err) => {
            let reason = handshake_failure_reason(&err);
            runtime.metrics.record_failed_handshake(reason);
            if matches!(reason, HandshakeFailureReason::Auth)
                && runtime.auth_rate_limiter.record_failure(peer.ip())
            {
                warn!(
                    event = "server.auth_rate_limit.banned_after_failure",
                    peer = %peer,
                    "IP has been temporarily banned after exceeding auth failure threshold"
                );
            }
            return Err(err);
        }
    };
    drop(handshake_guard);
    drop(handshake_permit);
    if *shutdown_rx.borrow() {
        return Ok(());
    }

    run_authenticated_session(
        carrier_reader,
        carrier_writer,
        datagrams,
        identity,
        runtime.security,
        &runtime.config,
        runtime.session_permits,
        runtime.max_sessions,
        runtime.global_buffer,
        runtime.global_flows,
        peer,
        shutdown_rx,
        runtime.metrics,
    )
    .await
}

/// Acquires a session slot, sends SETTINGS, and runs the relay loop for an
/// authenticated carrier session.
#[allow(clippy::too_many_arguments)]
async fn run_authenticated_session(
    carrier_reader: BoxedCarrierReader,
    mut carrier_writer: BoxedCarrierWriter,
    datagrams: Option<BoxedDatagramChannel>,
    identity: AuthenticatedIdentity,
    security: SecurityState,
    config: &ServerConfig,
    session_permits: Arc<Semaphore>,
    max_sessions: usize,
    global_buffer: relay::GlobalBufferControl,
    global_flows: relay::GlobalFlowBudget,
    peer: SocketAddr,
    shutdown_rx: watch::Receiver<bool>,
    metrics: Arc<ServerMetrics>,
) -> Result<(), AnyError> {
    let write_timeout = carrier_write_timeout(config.carrier_write_timeout_seconds());
    let Ok(session_permit) = session_permits.try_acquire_owned() else {
        metrics.record_rejected_session();
        warn!(event = "server.session.limit", peer = %peer, max_sessions);
        reject_over_limit_session(&mut carrier_writer, write_timeout, &shutdown_rx).await;
        return Err("authenticated session limit exceeded".into());
    };
    let _session_permit = session_permit;
    let _active_session = metrics.begin_session();

    // Native UDP over QUIC DATAGRAM is available only when the carrier exposes
    // a datagram channel (QUIC) and the peer enabled the datagram extension.
    let datagrams = datagrams.filter(|channel| channel.max_datagram_size().is_some());
    let supports_udp_datagram = datagrams.is_some();
    let settings_timeout = write_timeout;
    {
        let mut shutdown_watch = shutdown_rx.clone();
        let wait_shutdown = async {
            if *shutdown_watch.borrow() {
                return;
            }
            while let Ok(()) = shutdown_watch.changed().await {
                if *shutdown_watch.borrow() {
                    return;
                }
            }
        };
        let write_settings =
            write_server_settings(&mut carrier_writer, config, supports_udp_datagram);
        tokio::pin!(write_settings);
        tokio::pin!(wait_shutdown);

        let write_result: Result<(), AnyError> = match settings_timeout {
            Some(timeout) => {
                tokio::select! {
                    res = &mut write_settings => res,
                    () = &mut wait_shutdown => {
                        Err("session cancelled by server shutdown while writing SETTINGS".into())
                    }
                    () = tokio::time::sleep(timeout) => {
                        Err(io::Error::new(io::ErrorKind::TimedOut, "timed out writing server settings").into())
                    }
                }
            }
            None => {
                tokio::select! {
                    res = &mut write_settings => res,
                    () = &mut wait_shutdown => {
                        Err("session cancelled by server shutdown while writing SETTINGS".into())
                    }
                }
            }
        };
        write_result?;
    }

    let carrier = relay::ServerCarrier::new(carrier_reader, carrier_writer, datagrams);

    relay::relay_session(
        carrier,
        identity,
        security,
        relay::RelayLimits::new(relay::RelayLimitConfig {
            frame: FrameLimits {
                max_frame_size: config.max_frame_size(),
            },
            max_streams: config.max_streams(),
            max_udp_flows: config.max_udp_flows(),
            max_outbound_dials_per_session: usize_limit(
                "max_outbound_dials_per_session",
                config.max_outbound_dials_per_session(),
            )?,
            max_buffered_bytes_per_session: usize_limit(
                "max_buffered_bytes_per_session",
                config.max_buffered_bytes_per_session(),
            )?,
            max_buffered_bytes_per_flow: usize_limit(
                "max_buffered_bytes_per_flow",
                config.max_buffered_bytes_per_flow(),
            )?,
            target_connect_timeout: target_connect_timeout(config.target_connect_timeout_seconds()),
            tcp_half_close_timeout: tcp_half_close_timeout(config.tcp_half_close_timeout_seconds()),
            carrier_write_timeout: carrier_write_timeout(config.carrier_write_timeout_seconds()),
            udp_flow_idle_timeout: udp_flow_idle_timeout(config.udp_flow_idle_timeout_seconds()),
            session_task_shutdown_timeout: listener_shutdown_timeout(
                config.shutdown_timeout_seconds(),
            ),
            relay_buffer_size: Some(config.relay_buffer_size()),
        }),
        global_buffer,
        global_flows,
        idle_timeout(config.idle_timeout_seconds()),
        shutdown_rx,
        metrics,
    )
    .await
}

/// Validates server config, credentials, policy, and TLS material.
pub fn check_config(config: &ServerConfig) -> Result<(), AnyError> {
    config.validate_network_endpoints()?;
    config.validate_limits()?;
    config.validate_sensitive_paths()?;
    let _credentials = config.credentials()?;
    let _policy_set = config.policy_set()?;
    let tls_config = tls::server_config(&config.cert_path, &config.key_path)?;
    if config.quic_listen.is_some() {
        let _quic_config = quic::server_config_with_transport_params(
            tls_config,
            idle_timeout(config.idle_timeout_seconds()),
            config.quic_stream_receive_window(),
            config.quic_connection_receive_window(),
        )?;
    }
    Ok(())
}

async fn complete_handshake<S>(
    stream: S,
    authentication: AuthenticationSnapshot,
    replay_cache: Arc<Mutex<ReplayCache>>,
    config: &ServerConfig,
) -> Result<
    (
        BoxedCarrierReader,
        BoxedCarrierWriter,
        Option<BoxedDatagramChannel>,
        AuthenticatedIdentity,
    ),
    AnyError,
>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let stream = authentication
        .tls_acceptor
        .accept(stream)
        .await
        .map_err(|err| phase_error("tls accept", HandshakeFailureReason::Tls, err))?;
    tls::verify_alpn(&stream)
        .map_err(|err| phase_error("tls alpn verify", HandshakeFailureReason::Tls, err))?;
    let exporter = tls::exporter(&stream)
        .map_err(|err| phase_error("tls exporter", HandshakeFailureReason::Tls, err))?;
    let (reader, writer) = tokio::io::split(stream);
    // The TLS/TCP carrier has no datagram channel.
    authenticate_carrier(
        Box::new(reader),
        Box::new(writer),
        exporter,
        None,
        authentication,
        replay_cache,
        config,
    )
    .await
}

async fn send_auth_challenge(
    writer: &mut BoxedCarrierWriter,
    now: u64,
) -> Result<AuthChallenge, AnyError> {
    let challenge = AuthChallenge::generate(now);
    let mut payload = BytesMut::new();
    challenge
        .encode(&mut payload)
        .map_err(|err| phase_error("encode auth challenge", HandshakeFailureReason::Auth, err))?;
    let challenge_frame =
        Frame::new(FrameType::AuthChallenge, 0, 0, payload.freeze()).map_err(|err| {
            phase_error(
                "build auth challenge frame",
                HandshakeFailureReason::Auth,
                err,
            )
        })?;
    write_frame(writer, &challenge_frame).await.map_err(|err| {
        let reason = frame_io_failure_reason(&err);
        phase_error("write auth challenge", reason, err)
    })?;
    Ok(challenge)
}

/// Runs the UK challenge-response authentication over an established,
/// ALPN-verified carrier. This is carrier-neutral: the TLS/TCP and QUIC
/// acceptors both establish their transport, derive the exporter binding, and
/// then delegate the identical frame exchange to this function.
pub(crate) async fn authenticate_carrier(
    mut reader: BoxedCarrierReader,
    mut writer: BoxedCarrierWriter,
    exporter: [u8; 32],
    datagrams: Option<BoxedDatagramChannel>,
    authentication: AuthenticationSnapshot,
    replay_cache: Arc<Mutex<ReplayCache>>,
    config: &ServerConfig,
) -> Result<
    (
        BoxedCarrierReader,
        BoxedCarrierWriter,
        Option<BoxedDatagramChannel>,
        AuthenticatedIdentity,
    ),
    AnyError,
> {
    // Refuse to authenticate rather than stamping the challenge with a
    // placeholder: every downstream check (credential validity windows, skew
    // bounds, replay expiry) is only meaningful against a real clock.
    let now = try_unix_now().ok_or_else(|| {
        phase_error(
            "read system clock",
            HandshakeFailureReason::Auth,
            "system clock is before the Unix epoch",
        )
    })?;
    let challenge = send_auth_challenge(&mut writer, now).await?;

    let response_frame = match read_frame(
        &mut reader,
        FrameLimits {
            max_frame_size: config.max_pre_auth_bytes(),
        },
    )
    .await
    {
        Ok(frame) => frame,
        Err(err) => {
            report_handshake_frame_io_error(&mut writer, &err).await;
            let reason = frame_io_failure_reason(&err);
            return Err(phase_error("read auth response", reason, err));
        }
    };

    if let Err(err) = validate_connection_frame(&response_frame, FrameType::AuthResponse) {
        let _ = write_connection_error(&mut writer, ErrorCode::Protocol).await;
        return Err(phase_error(
            "validate auth response",
            HandshakeFailureReason::Protocol,
            err,
        ));
    }

    let mut response_payload = response_frame.payload;
    let response = match AuthResponse::decode(&mut response_payload) {
        Ok(response) => response,
        Err(err) => {
            let _ = write_connection_error(&mut writer, ErrorCode::AuthFailed).await;
            return Err(phase_error(
                "decode auth response",
                HandshakeFailureReason::Auth,
                err,
            ));
        }
    };
    let verify_now = try_unix_now().ok_or_else(|| {
        phase_error(
            "read system clock",
            HandshakeFailureReason::Auth,
            "system clock error",
        )
    })?;
    let identity = match verify_auth_response_identity_stateless(
        &authentication.credentials,
        &exporter,
        &challenge,
        &response,
        verify_now,
        authentication.auth_skew,
    ) {
        Ok(identity) => identity,
        Err(err) => {
            let _ = write_connection_error(&mut writer, ErrorCode::AuthFailed).await;
            return Err(phase_error(
                "verify auth response",
                HandshakeFailureReason::Auth,
                err,
            ));
        }
    };

    let replay_result = {
        let mut replay_cache = replay_cache.lock().await;
        replay_cache.check_and_insert(challenge.server_nonce, response.client_nonce)
    };
    if let Err(err) = replay_result {
        let _ = write_connection_error(&mut writer, ErrorCode::AuthFailed).await;
        return Err(phase_error(
            "verify auth response replay",
            HandshakeFailureReason::Auth,
            err,
        ));
    }

    info!(
        event = "auth.success",
        key_id_hex = %hex_encode(&identity.key_id),
        security_generation = authentication.generation
    );

    Ok((reader, writer, datagrams, identity))
}

async fn write_server_settings<W>(
    stream: &mut W,
    config: &ServerConfig,
    supports_udp_datagram: bool,
) -> Result<(), AnyError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let settings = server_settings(config, supports_udp_datagram);
    let mut settings_payload = BytesMut::new();
    settings
        .encode(&mut settings_payload)
        .map_err(|err| phase_error("encode server settings", HandshakeFailureReason::Other, err))?;
    let settings_frame =
        Frame::new(FrameType::Settings, 0, 0, settings_payload.freeze()).map_err(|err| {
            phase_error(
                "build server settings frame",
                HandshakeFailureReason::Other,
                err,
            )
        })?;
    write_frame(stream, &settings_frame).await.map_err(|err| {
        let reason = frame_io_failure_reason(&err);
        phase_error("write server settings", reason, err)
    })?;
    Ok(())
}

const CARRIER_ERROR_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

async fn reject_over_limit_session(
    carrier_writer: &mut BoxedCarrierWriter,
    write_timeout: Option<Duration>,
    shutdown_rx: &watch::Receiver<bool>,
) {
    let mut shutdown_watch = shutdown_rx.clone();
    let wait_shutdown = async {
        if *shutdown_watch.borrow() {
            return;
        }
        while let Ok(()) = shutdown_watch.changed().await {
            if *shutdown_watch.borrow() {
                return;
            }
        }
    };
    let reject_session = async {
        let _ = write_connection_error(carrier_writer, ErrorCode::ResourceLimit).await;
        let _ = carrier_writer.shutdown().await;
    };
    tokio::pin!(reject_session);
    tokio::pin!(wait_shutdown);
    match write_timeout {
        Some(timeout) => {
            tokio::select! {
                () = &mut reject_session => {}
                () = &mut wait_shutdown => {}
                () = tokio::time::sleep(timeout) => {}
            }
        }
        None => {
            tokio::select! {
                () = &mut reject_session => {}
                () = &mut wait_shutdown => {}
            }
        }
    }
}

async fn write_connection_error<W>(stream: &mut W, code: ErrorCode) -> Result<(), AnyError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let frame = connection_error_frame(code)?;
    time::timeout(CARRIER_ERROR_WRITE_TIMEOUT, write_frame(stream, &frame)).await??;
    Ok(())
}

async fn report_handshake_frame_io_error<W>(stream: &mut W, error: &FrameIoError)
where
    W: tokio::io::AsyncWrite + Unpin,
{
    if let FrameIoError::Protocol(error) = error {
        let _ = write_connection_error(stream, ErrorCode::from_protocol_error(error)).await;
    }
}

fn connection_error_frame(code: ErrorCode) -> Result<Frame, AnyError> {
    let mut payload = BytesMut::new();
    ErrorPayload::new(code).encode(&mut payload)?;
    Ok(Frame::new(FrameType::Error, 0, 0, payload.freeze())?)
}

fn server_settings(config: &ServerConfig, supports_udp_datagram: bool) -> Settings {
    let mut settings = Settings::default();
    settings.set(SettingKey::ProtocolRevision, PROTOCOL_REVISION_V1_0);
    settings.set(SettingKey::MaxFrameSize, config.max_frame_size());
    settings.set(SettingKey::MaxStreams, config.max_streams());
    settings.set(SettingKey::MaxUdpFlows, config.max_udp_flows());
    settings.set(
        SettingKey::SupportsUdpDatagram,
        u64::from(supports_udp_datagram && config.max_udp_flows() != 0),
    );
    settings.set(
        SettingKey::SupportsUdpStreamFallback,
        u64::from(config.max_udp_flows() != 0),
    );
    settings.set(
        SettingKey::IdleTimeoutSeconds,
        config.idle_timeout_seconds(),
    );
    settings
}

fn idle_timeout(seconds: u64) -> Option<Duration> {
    (seconds != 0).then(|| Duration::from_secs(seconds))
}

fn handshake_timeout(seconds: u64) -> Option<Duration> {
    (seconds != 0).then(|| Duration::from_secs(seconds))
}

fn target_connect_timeout(seconds: u64) -> Option<Duration> {
    (seconds != 0).then(|| Duration::from_secs(seconds))
}

fn tcp_half_close_timeout(seconds: u64) -> Option<Duration> {
    (seconds != 0).then(|| Duration::from_secs(seconds))
}

/// Enables TCP keepalive on an accepted carrier.
///
/// A peer that disappears without closing (power loss, a NAT dropping the
/// mapping) leaves a half-open connection that reads never complete on, so the
/// session and its slot are otherwise held until `idle_timeout_seconds` — five
/// minutes by default. Keepalive turns that into a transport-level error. This
/// is best-effort: a socket that rejects the option is still usable, so a
/// failure is logged rather than failing the connection.
fn apply_tcp_keepalive(tcp: &TcpStream, seconds: u64, peer: SocketAddr) {
    if seconds == 0 {
        return;
    }
    let idle = Duration::from_secs(seconds);
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(idle)
        .with_interval(idle);
    if let Err(err) = socket2::SockRef::from(tcp).set_tcp_keepalive(&keepalive) {
        debug!(
            event = "server.tcp.keepalive_error",
            peer = %peer,
            error = %err
        );
    }
}

fn carrier_write_timeout(seconds: u64) -> Option<Duration> {
    (seconds != 0).then(|| Duration::from_secs(seconds))
}

fn udp_flow_idle_timeout(seconds: u64) -> Option<Duration> {
    (seconds != 0).then(|| Duration::from_secs(seconds))
}

fn listener_shutdown_timeout(seconds: u64) -> Option<Duration> {
    (seconds != 0).then(|| Duration::from_secs(seconds))
}

fn phase_error<E>(
    phase: &'static str,
    failure_reason: HandshakeFailureReason,
    source: E,
) -> AnyError
where
    E: Into<AnyError>,
{
    Box::new(HandshakePhaseError {
        phase,
        failure_reason,
        source: source.into(),
    })
}

fn handshake_failure_reason(error: &AnyError) -> HandshakeFailureReason {
    let mut current = Some(error.as_ref() as &(dyn Error + 'static));
    while let Some(source) = current {
        if let Some(error) = source.downcast_ref::<HandshakePhaseError>() {
            return error.failure_reason;
        }
        current = source.source();
    }
    if let Some(error) = find_frame_io_error(error.as_ref()) {
        return frame_io_failure_reason(error);
    }
    if find_io_error(error.as_ref()).is_some() {
        return HandshakeFailureReason::Io;
    }
    HandshakeFailureReason::Other
}

fn frame_io_failure_reason(error: &FrameIoError) -> HandshakeFailureReason {
    match error {
        FrameIoError::Protocol(_) => HandshakeFailureReason::Protocol,
        FrameIoError::Closed | FrameIoError::Io(_) => HandshakeFailureReason::Io,
    }
}

fn find_frame_io_error<'a>(error: &'a (dyn Error + 'static)) -> Option<&'a FrameIoError> {
    let mut current = Some(error);
    while let Some(error) = current {
        if let Some(error) = error.downcast_ref::<FrameIoError>() {
            return Some(error);
        }
        current = error.source();
    }
    None
}

fn is_clean_tls_handshake_disconnect(error: &AnyError) -> bool {
    find_io_error(error.as_ref()).is_some_and(|error| {
        matches!(
            error.kind(),
            io::ErrorKind::UnexpectedEof
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::BrokenPipe
                | io::ErrorKind::NotConnected
        ) || is_tls_handshake_eof(error)
    }) || error.to_string() == TLS_HANDSHAKE_EOF_MESSAGE
}

fn find_io_error<'a>(error: &'a (dyn Error + 'static)) -> Option<&'a io::Error> {
    let mut current = Some(error);
    while let Some(error) = current {
        if let Some(error) = error.downcast_ref::<io::Error>() {
            return Some(error);
        }
        current = error.source();
    }
    None
}

/// Message of the `io::Error` produced when a client disconnects mid-TLS-handshake.
///
/// This string is produced by the TLS stack (tokio-rustls maps a peer EOF
/// during the handshake to `io::ErrorKind::UnexpectedEof` with this message;
/// see `tokio_rustls::common`), not by this crate, so it cannot be matched by
/// type alone — and it can also arrive re-wrapped as a plain string through
/// error conversions. It is centralized here so the dependency on the exact
/// wording lives in exactly one place; if a tokio-rustls upgrade changes the
/// wording, only this constant needs updating (the
/// `classifies_clean_tls_handshake_disconnects` test pins it).
const TLS_HANDSHAKE_EOF_MESSAGE: &str = "tls handshake eof";

fn is_tls_handshake_eof(error: &io::Error) -> bool {
    error.to_string() == TLS_HANDSHAKE_EOF_MESSAGE
}

fn usize_limit(name: &str, value: u64) -> Result<usize, AnyError> {
    usize::try_from(value).map_err(|_| format!("{name} is too large for this platform").into())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CredentialConfig, LimitConfig};
    use crate::security::test_tls_acceptor;

    /// Keepalive must actually reach the socket — a silent no-op would leave
    /// half-open sessions holding their slot until the idle timeout.
    #[tokio::test]
    async fn applies_tcp_keepalive_to_accepted_carriers() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move { TcpStream::connect(addr).await });
        let (accepted, peer) = listener.accept().await.unwrap();
        let _client = client.await.unwrap().unwrap();

        assert!(!socket2::SockRef::from(&accepted).keepalive().unwrap());
        apply_tcp_keepalive(&accepted, 42, peer);
        assert!(socket2::SockRef::from(&accepted).keepalive().unwrap());
    }

    #[tokio::test]
    async fn zero_disables_tcp_keepalive() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move { TcpStream::connect(addr).await });
        let (accepted, peer) = listener.accept().await.unwrap();
        let _client = client.await.unwrap().unwrap();

        apply_tcp_keepalive(&accepted, 0, peer);

        assert!(!socket2::SockRef::from(&accepted).keepalive().unwrap());
    }

    fn minimal_config() -> ServerConfig {
        ServerConfig {
            listen: "127.0.0.1:1".to_owned(),
            quic_listen: None,
            observability_listen: None,
            cert_path: "cert.pem".to_owned(),
            key_path: "key.pem".to_owned(),
            auth_skew_seconds: None,
            limits: None,
            policy_path: None,
            credentials: vec![CredentialConfig {
                key_id: "client".to_owned(),
                secret: "0123456789abcdef0123456789abcdef".to_owned(),
                status: Some("active".to_owned()),
                not_before: None,
                not_after: None,
                policy_group: None,
            }],
            masking: None,
        }
    }

    #[test]
    fn server_settings_are_negotiable_by_clients() {
        let mut config = minimal_config();
        config.limits = None;
        assert!(server_settings(&config, false).negotiated_v1_0().is_ok());

        config.limits = Some(LimitConfig {
            max_streams: Some(uk_proto::MAX_NEGOTIATED_FLOWS),
            max_udp_flows: Some(uk_proto::MAX_NEGOTIATED_FLOWS),
            idle_timeout_seconds: Some(uk_proto::MAX_NEGOTIATED_IDLE_TIMEOUT_SECONDS),
            ..LimitConfig::default()
        });
        assert!(server_settings(&config, true).negotiated_v1_0().is_ok());

        config.limits = Some(LimitConfig {
            max_streams: Some(1),
            max_udp_flows: Some(0),
            idle_timeout_seconds: Some(0),
            ..LimitConfig::default()
        });
        assert!(server_settings(&config, false).negotiated_v1_0().is_ok());
    }

    #[test]
    fn server_settings_include_protocol_and_limits() {
        let mut config = minimal_config();
        config.limits = Some(LimitConfig {
            max_frame_size: Some(32_768),
            max_streams: Some(17),
            max_udp_flows: Some(11),
            idle_timeout_seconds: Some(42),
            ..LimitConfig::default()
        });

        let settings = server_settings(&config, false);

        assert_eq!(
            settings.get(SettingKey::ProtocolRevision),
            Some(PROTOCOL_REVISION_V1_0)
        );
        assert_eq!(settings.get(SettingKey::MaxFrameSize), Some(32_768));
        assert_eq!(settings.get(SettingKey::MaxStreams), Some(17));
        assert_eq!(settings.get(SettingKey::MaxUdpFlows), Some(11));
        assert_eq!(settings.get(SettingKey::SupportsUdpDatagram), Some(0));
        assert_eq!(settings.get(SettingKey::SupportsUdpStreamFallback), Some(1));
        assert_eq!(settings.get(SettingKey::IdleTimeoutSeconds), Some(42));
    }

    #[test]
    fn server_settings_advertise_udp_datagram_on_quic_sessions() {
        let config = minimal_config();

        let settings = server_settings(&config, true);

        assert_eq!(settings.get(SettingKey::SupportsUdpDatagram), Some(1));
    }

    #[test]
    fn server_settings_withhold_udp_datagram_without_udp_flows() {
        let mut config = minimal_config();
        config.limits = Some(LimitConfig {
            max_udp_flows: Some(0),
            ..LimitConfig::default()
        });

        let settings = server_settings(&config, true);

        assert_eq!(settings.get(SettingKey::SupportsUdpDatagram), Some(0));
    }

    #[test]
    fn runtime_credentials_remove_secrets_from_server_config() {
        let mut config = minimal_config();

        let credentials = take_runtime_credentials(&mut config).unwrap();

        assert_eq!(credentials.len(), 1);
        assert_eq!(credentials[0].key_id, b"client");
        assert!(config.credentials.is_empty());
    }

    #[test]
    fn invalid_runtime_credentials_still_clear_server_config_secrets() {
        let mut config = minimal_config();
        config.credentials[0].secret = "too-short".to_owned();

        assert_eq!(
            take_runtime_credentials(&mut config),
            Err(uk_auth::AuthError::SecretTooShort)
        );
        assert!(config.credentials.is_empty());
    }

    #[test]
    fn security_reload_rejects_static_runtime_changes() {
        let current = minimal_config();
        let security = SecurityState::new(
            test_tls_acceptor(),
            current.credentials().unwrap(),
            Vec::new(),
            current.policy_set().unwrap(),
            Duration::from_secs(current.auth_skew_seconds()),
        );
        let mut candidate = current.clone();
        candidate.listen = "127.0.0.1:2".to_owned();

        let error = apply_security_reload(&current, &security, None, candidate)
            .unwrap_err()
            .to_string();

        assert!(error.contains("listen"));
        assert!(error.contains("requires a restart"));
        assert_eq!(security.generation(), 1);
    }

    #[test]
    fn security_reload_failure_preserves_current_generation() {
        let current = minimal_config();
        let security = SecurityState::new(
            test_tls_acceptor(),
            current.credentials().unwrap(),
            Vec::new(),
            current.policy_set().unwrap(),
            Duration::from_secs(current.auth_skew_seconds()),
        );
        let mut candidate = current.clone();
        candidate.credentials[0].secret = "too-short".to_owned();

        assert!(apply_security_reload(&current, &security, None, candidate).is_err());
        assert_eq!(security.generation(), 1);
        assert_eq!(
            security.authentication_snapshot().credentials[0].key_id,
            b"client"
        );
    }

    #[test]
    fn security_reload_rejects_invalid_endpoints_and_limits() {
        let current = minimal_config();
        let security = SecurityState::new(
            test_tls_acceptor(),
            current.credentials().unwrap(),
            Vec::new(),
            current.policy_set().unwrap(),
            Duration::from_secs(current.auth_skew_seconds()),
        );

        // Invalid observability bind address
        let mut candidate = current.clone();
        candidate.observability_listen = Some("0.0.0.0:9090".to_owned());
        assert!(apply_security_reload(&current, &security, None, candidate).is_err());
        assert_eq!(security.generation(), 1);

        // Invalid reloadable auth_skew_seconds (0 is rejected by validate_limits)
        let mut candidate = current.clone();
        candidate.auth_skew_seconds = Some(0);
        assert!(apply_security_reload(&current, &security, None, candidate).is_err());
        assert_eq!(security.generation(), 1);
        assert_eq!(
            security.authentication_snapshot().auth_skew,
            Duration::from_secs(30)
        );

        // Invalid reloadable auth_skew_seconds (2 * 200 > 300s replay cache window)
        let mut candidate = current.clone();
        candidate.auth_skew_seconds = Some(200);
        assert!(apply_security_reload(&current, &security, None, candidate).is_err());
        assert_eq!(security.generation(), 1);
        assert_eq!(
            security.authentication_snapshot().auth_skew,
            Duration::from_secs(30)
        );
    }

    #[tokio::test]
    async fn handle_reload_request_load_failure_increments_metric() {
        let current = minimal_config();
        let security = SecurityState::new(
            test_tls_acceptor(),
            current.credentials().unwrap(),
            Vec::new(),
            current.policy_set().unwrap(),
            Duration::from_secs(current.auth_skew_seconds()),
        );
        let metrics = ServerMetrics::default();
        let (response, rx) = oneshot::channel();
        let request = ServerReloadRequest {
            config: Err("disk read failed".to_string()),
            response,
        };

        handle_reload_request(&current, &security, None, &metrics, request).await;

        let result = rx.await.unwrap();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "disk read failed");
        assert!(
            metrics
                .render()
                .contains("uncrowned_king_server_config_reload_failures_total 1")
        );
        assert_eq!(security.generation(), 1);
    }

    #[test]
    fn security_reload_accepts_equivalent_effective_limits() {
        let current = minimal_config();
        let mut candidate = current.clone();
        candidate.limits = Some(LimitConfig {
            max_sessions: Some(current.max_sessions()),
            ..LimitConfig::default()
        });

        assert!(ensure_reload_compatible(&current, &candidate).is_ok());
    }

    #[test]
    fn security_reload_rejects_relay_buffer_size_changes() {
        let current = minimal_config();
        let mut candidate = current.clone();
        candidate.limits = Some(LimitConfig {
            relay_buffer_size: Some(32 * 1024),
            ..LimitConfig::default()
        });

        let error = ensure_reload_compatible(&current, &candidate)
            .unwrap_err()
            .to_string();
        assert!(error.contains("relay_buffer_size"));
        assert!(error.contains("requires a restart"));
    }

    #[test]
    fn security_reload_rejects_auth_rate_limit_changes() {
        let current = minimal_config();
        let mut candidate = current.clone();
        candidate.limits = Some(LimitConfig {
            auth_rate_limit_failures: Some(10),
            ..LimitConfig::default()
        });

        let error = ensure_reload_compatible(&current, &candidate)
            .unwrap_err()
            .to_string();
        assert!(error.contains("auth_rate_limit_failures"));
        assert!(error.contains("requires a restart"));
    }

    #[test]
    fn security_reload_rejects_quic_receive_window_changes() {
        let current = minimal_config();
        let mut candidate_stream = current.clone();
        candidate_stream.limits = Some(LimitConfig {
            quic_stream_receive_window: Some(2 * 1024 * 1024),
            quic_connection_receive_window: Some(2 * 1024 * 1024),
            ..LimitConfig::default()
        });

        let error = ensure_reload_compatible(&current, &candidate_stream)
            .unwrap_err()
            .to_string();
        assert!(error.contains("quic_stream_receive_window"));
        assert!(error.contains("requires a restart"));

        let mut candidate_conn = current.clone();
        candidate_conn.limits = Some(LimitConfig {
            quic_connection_receive_window: Some(4 * 1024 * 1024),
            ..LimitConfig::default()
        });
        let error = ensure_reload_compatible(&current, &candidate_conn)
            .unwrap_err()
            .to_string();
        assert!(error.contains("quic_connection_receive_window"));
        assert!(error.contains("requires a restart"));
    }

    #[test]
    fn server_settings_disable_udp_stream_fallback_without_udp_flows() {
        let mut config = minimal_config();
        config.limits = Some(LimitConfig {
            max_udp_flows: Some(0),
            ..LimitConfig::default()
        });

        let settings = server_settings(&config, false);

        assert_eq!(settings.get(SettingKey::MaxUdpFlows), Some(0));
        assert_eq!(settings.get(SettingKey::SupportsUdpStreamFallback), Some(0));
    }

    #[test]
    fn connection_error_frame_encodes_error_code() {
        let frame = connection_error_frame(ErrorCode::AuthFailed).unwrap();

        assert_eq!(frame.header.frame_type, FrameType::Error);
        assert_eq!(frame.header.id, 0);
        let mut payload = frame.payload;
        assert_eq!(
            ErrorPayload::decode(&mut payload).unwrap().code,
            ErrorCode::AuthFailed
        );
    }

    #[test]
    fn hex_encode_keeps_opaque_key_ids_log_safe() {
        assert_eq!(hex_encode(b"client"), "636c69656e74");
        assert_eq!(hex_encode(&[0x00, 0x1f, 0x7f, 0x80, 0xff]), "001f7f80ff");
    }

    #[test]
    fn listener_accept_backoff_grows_caps_and_resets() {
        let mut backoff = ListenerAcceptBackoff::default();

        assert_eq!(backoff.next_delay(), Duration::from_millis(10));
        assert_eq!(backoff.next_delay(), Duration::from_millis(20));
        assert_eq!(backoff.next_delay(), Duration::from_millis(40));
        for _ in 0..16 {
            let delay = backoff.next_delay();
            assert!(delay <= Duration::from_secs(1));
        }
        assert_eq!(backoff.next_delay(), Duration::from_secs(1));

        backoff.reset();
        assert_eq!(backoff.next_delay(), Duration::from_millis(10));
    }

    #[test]
    fn classifies_clean_tls_handshake_disconnects() {
        // Pin the exact rustls wording: if a dependency upgrade changes it,
        // this test fails loudly instead of the classifier silently
        // misclassifying handshake EOFs as handshake failures.
        assert_eq!(TLS_HANDSHAKE_EOF_MESSAGE, "tls handshake eof");
        let unexpected_eof: AnyError =
            io::Error::new(io::ErrorKind::UnexpectedEof, "client closed").into();
        let connection_reset: AnyError =
            io::Error::new(io::ErrorKind::ConnectionReset, "client reset").into();
        let broken_pipe: AnyError =
            io::Error::new(io::ErrorKind::BrokenPipe, "client pipe closed").into();
        let not_connected: AnyError =
            io::Error::new(io::ErrorKind::NotConnected, "client gone").into();
        let rustls_eof: AnyError =
            io::Error::new(io::ErrorKind::UnexpectedEof, TLS_HANDSHAKE_EOF_MESSAGE).into();
        // The same message re-wrapped as a plain string (e.g. through error
        // conversions that lose the io::Error): only the string comparison
        // catches this one.
        let rewrapped_eof: AnyError = io::Error::other(TLS_HANDSHAKE_EOF_MESSAGE).into();
        let protocol_error: AnyError =
            io::Error::new(io::ErrorKind::InvalidData, "invalid certificate").into();

        assert!(is_clean_tls_handshake_disconnect(&unexpected_eof));
        assert!(is_clean_tls_handshake_disconnect(&connection_reset));
        assert!(is_clean_tls_handshake_disconnect(&broken_pipe));
        assert!(is_clean_tls_handshake_disconnect(&not_connected));
        assert!(is_clean_tls_handshake_disconnect(&rustls_eof));
        assert!(is_clean_tls_handshake_disconnect(&rewrapped_eof));
        assert!(!is_clean_tls_handshake_disconnect(&protocol_error));
    }

    #[test]
    fn handshake_phase_error_reports_phase_and_source() {
        let error = phase_error("tls accept", HandshakeFailureReason::Tls, "client closed");

        assert_eq!(error.to_string(), "tls accept failed: client closed");
        assert!(error.source().is_some());
        assert_eq!(
            handshake_failure_reason(&error),
            HandshakeFailureReason::Tls
        );
    }

    #[test]
    fn classifies_clean_disconnects_through_handshake_phase_error() {
        let error = phase_error(
            "tls accept",
            HandshakeFailureReason::Tls,
            io::Error::new(io::ErrorKind::UnexpectedEof, "client closed"),
        );

        assert!(is_clean_tls_handshake_disconnect(&error));
    }

    #[test]
    fn classifies_unwrapped_frame_and_io_failures() {
        let closed: AnyError = Box::new(FrameIoError::Closed);
        let io: AnyError = io::Error::new(io::ErrorKind::ConnectionReset, "reset").into();

        assert_eq!(
            handshake_failure_reason(&closed),
            HandshakeFailureReason::Io
        );
        assert_eq!(handshake_failure_reason(&io), HandshakeFailureReason::Io);
    }

    #[tokio::test]
    async fn server_shutdown_timeout_aborts_pending_connection_tasks() {
        let mut connections = JoinSet::new();
        connections.spawn(std::future::pending::<()>());

        tokio::time::timeout(
            Duration::from_secs(1),
            drain_connection_tasks(
                &mut connections,
                shutdown_deadline(Some(Duration::from_millis(10))),
            ),
        )
        .await
        .unwrap();

        assert!(connections.is_empty());
    }

    #[tokio::test]
    async fn server_shutdown_drain_waits_for_completed_connection_tasks() {
        let mut connections = JoinSet::new();
        connections.spawn(async {});

        drain_connection_tasks(
            &mut connections,
            shutdown_deadline(Some(Duration::from_secs(1))),
        )
        .await;

        assert!(connections.is_empty());
    }

    #[tokio::test]
    async fn server_shutdown_deadline_in_past_aborts_without_waiting() {
        let mut connections = JoinSet::new();
        connections.spawn(std::future::pending::<()>());

        // The shared deadline may already be exhausted when the listener
        // reaches the rejoin (sessions drained against it internally); the
        // rejoin must abort immediately rather than granting more time.
        let past = time::Instant::now() - Duration::from_secs(1);
        tokio::time::timeout(
            Duration::from_secs(1),
            drain_connection_tasks(&mut connections, Some(past)),
        )
        .await
        .unwrap();

        assert!(connections.is_empty());
    }

    #[tokio::test]
    async fn connection_rejected_before_handshake_when_session_permits_exhausted() {
        use tokio::io::AsyncReadExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client_sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server_sock, peer) = listener.accept().await.unwrap();

        let config = Arc::new(minimal_config());
        let metrics = Arc::new(ServerMetrics::default());
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);

        let session_permits = Arc::new(Semaphore::new(0));
        let handshake_permits = Arc::new(Semaphore::new(10));
        let auth_rate_limiter = Arc::new(rate_limit::AuthRateLimiter::new(
            rate_limit::AuthRateLimitConfig::default(),
        ));
        let replay_cache = Arc::new(Mutex::new(ReplayCache::new(Duration::from_secs(60))));

        let security = SecurityState::new(
            crate::security::test_tls_acceptor(),
            vec![],
            Vec::new(),
            uk_policy::PolicySet::default(),
            Duration::from_secs(30),
        );

        let runtime = ConnectionRuntime {
            security,
            replay_cache,
            session_permits,
            config,
            handshake_permits: Arc::clone(&handshake_permits),
            auth_rate_limiter,
            max_sessions: 0,
            max_handshakes: 10,
            global_buffer: relay::GlobalBufferControl::default(),
            global_flows: relay::GlobalFlowBudget::default(),
            metrics: Arc::clone(&metrics),
            masking: None,
        };

        let mut connections = JoinSet::new();
        runtime.spawn_accepted(&mut connections, server_sock, peer, shutdown_rx);

        assert!(
            connections.is_empty(),
            "task should not be spawned when session permits are exhausted"
        );
        assert_eq!(
            handshake_permits.available_permits(),
            10,
            "handshake permit should not be acquired"
        );
        let mut client_sock = client_sock;
        let mut buf = [0u8; 16];
        let n = client_sock.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "connection should be closed immediately");
    }

    #[tokio::test]
    async fn handshake_timestamp_freshness_accepts_legitimate_latency() {
        use uk_proto::FrameReader;

        let (client_transport, server_transport) = tokio::io::duplex(65536);
        let (server_reader, server_writer) = tokio::io::split(server_transport);
        let (client_reader, mut client_writer) = tokio::io::split(client_transport);

        let exporter = [7u8; 32];
        let cred = uk_auth::Credential::active(
            b"client".to_vec(),
            b"0123456789abcdef0123456789abcdef".to_vec(),
        )
        .unwrap();

        let authentication = AuthenticationSnapshot {
            generation: 1,
            tls_acceptor: test_tls_acceptor(),
            credentials: Arc::new(vec![cred.clone()]),
            mask_keys: Arc::new(Vec::new()),
            auth_skew: Duration::from_secs(5),
        };
        let replay_cache = Arc::new(Mutex::new(ReplayCache::new(Duration::from_secs(60))));
        let config = minimal_config();

        let server_task = tokio::spawn(async move {
            authenticate_carrier(
                Box::new(server_reader),
                Box::new(server_writer),
                exporter,
                None,
                authentication,
                replay_cache,
                &config,
            )
            .await
        });

        let mut client_frame_reader =
            FrameReader::new(Box::pin(client_reader), FrameLimits::default());
        let challenge_frame = client_frame_reader.read_frame().await.unwrap();
        assert_eq!(challenge_frame.header.frame_type, FrameType::AuthChallenge);

        let mut payload = challenge_frame.payload;
        let challenge = AuthChallenge::decode(&mut payload).unwrap();

        let client_now = uk_auth::unix_now();
        let response = AuthResponse::for_challenge(
            b"client".to_vec(),
            b"0123456789abcdef0123456789abcdef",
            &exporter,
            &challenge,
            client_now,
            vec![],
        )
        .unwrap();

        let mut resp_payload = BytesMut::new();
        response.encode(&mut resp_payload).unwrap();
        let resp_frame = Frame::new(FrameType::AuthResponse, 0, 0, resp_payload.freeze()).unwrap();
        write_frame(&mut client_writer, &resp_frame).await.unwrap();

        let server_result = server_task.await.unwrap();
        assert!(
            server_result.is_ok(),
            "authentication within auth_skew should succeed"
        );
        let (_, _, _, identity) = server_result.unwrap();
        assert_eq!(identity.key_id, b"client");
    }

    #[tokio::test]
    async fn handshake_timestamp_freshness_rejects_expired_challenge() {
        use uk_proto::FrameReader;

        let (client_transport, server_transport) = tokio::io::duplex(65536);
        let (server_reader, server_writer) = tokio::io::split(server_transport);
        let (client_reader, mut client_writer) = tokio::io::split(client_transport);

        let exporter = [7u8; 32];
        let cred = uk_auth::Credential::active(
            b"client".to_vec(),
            b"0123456789abcdef0123456789abcdef".to_vec(),
        )
        .unwrap();

        let authentication = AuthenticationSnapshot {
            generation: 1,
            tls_acceptor: test_tls_acceptor(),
            credentials: Arc::new(vec![cred.clone()]),
            mask_keys: Arc::new(Vec::new()),
            auth_skew: Duration::from_secs(1),
        };
        let replay_cache = Arc::new(Mutex::new(ReplayCache::new(Duration::from_secs(60))));
        let config = minimal_config();

        let server_task = tokio::spawn(async move {
            authenticate_carrier(
                Box::new(server_reader),
                Box::new(server_writer),
                exporter,
                None,
                authentication,
                replay_cache,
                &config,
            )
            .await
        });

        let mut client_frame_reader =
            FrameReader::new(Box::pin(client_reader), FrameLimits::default());
        let challenge_frame = client_frame_reader.read_frame().await.unwrap();
        assert_eq!(challenge_frame.header.frame_type, FrameType::AuthChallenge);

        let mut payload = challenge_frame.payload;
        let challenge = AuthChallenge::decode(&mut payload).unwrap();

        // Sleep 2100ms so challenge expires relative to server arrival time (> 1s skew)
        tokio::time::sleep(Duration::from_millis(2100)).await;

        let client_now = uk_auth::unix_now();
        let response = AuthResponse::for_challenge(
            b"client".to_vec(),
            b"0123456789abcdef0123456789abcdef",
            &exporter,
            &challenge,
            client_now,
            vec![],
        )
        .unwrap();

        let mut resp_payload = BytesMut::new();
        response.encode(&mut resp_payload).unwrap();
        let resp_frame = Frame::new(FrameType::AuthResponse, 0, 0, resp_payload.freeze()).unwrap();
        write_frame(&mut client_writer, &resp_frame).await.unwrap();

        let server_result = server_task.await.unwrap();
        match server_result {
            Err(error) => {
                assert_eq!(
                    handshake_failure_reason(&error),
                    HandshakeFailureReason::Auth,
                    "expired challenge failure reason must be Auth"
                );
            }
            Ok(_) => panic!("challenge expired relative to real arrival time must be rejected"),
        }
    }
}

#[cfg(test)]
mod settings_write_tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    struct Stall;

    impl tokio::io::AsyncWrite for Stall {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    #[tokio::test]
    async fn settings_write_exits_on_shutdown_and_reclaims_permit() {
        let config: ServerConfig =
            toml::from_str(include_str!("../../../examples/server.toml")).unwrap();
        let cred = uk_auth::Credential::active(
            b"client".to_vec(),
            b"0123456789abcdef0123456789abcdef".to_vec(),
        )
        .unwrap();
        let identity = AuthenticatedIdentity::from(&cred);
        let security = SecurityState::new(
            crate::security::test_tls_acceptor(),
            vec![cred],
            Vec::new(),
            uk_policy::PolicySet::default(),
            Duration::from_secs(30),
        );
        let permits = Arc::new(Semaphore::new(1));
        let task_permits = permits.clone();
        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(async move {
            run_authenticated_session(
                Box::new(tokio::io::empty()),
                Box::new(Stall),
                None,
                identity,
                security,
                &config,
                task_permits,
                1,
                relay::GlobalBufferControl::default(),
                relay::GlobalFlowBudget::default(),
                "127.0.0.1:1000".parse().unwrap(),
                rx,
                Arc::new(ServerMetrics::default()),
            )
            .await
        });
        tokio::task::yield_now().await;
        assert_eq!(permits.available_permits(), 0);
        tx.send(true).unwrap();
        let result = time::timeout(Duration::from_millis(100), handle).await;
        assert!(
            result.is_ok(),
            "session did not exit within 100ms after shutdown; the SETTINGS write must observe shutdown and the slot must be released"
        );
        let session_res = result.unwrap().unwrap();
        assert!(
            session_res.is_err(),
            "session should exit with cancellation error"
        );
        assert_eq!(
            permits.available_permits(),
            1,
            "session permit must be reclaimed after shutdown cancellation"
        );
    }

    #[tokio::test]
    async fn settings_write_timeout_reclaims_permit() {
        let mut config: ServerConfig =
            toml::from_str(include_str!("../../../examples/server.toml")).unwrap();
        // Configure carrier write timeout to 1 second for fast empirical verification
        config
            .limits
            .get_or_insert_with(Default::default)
            .carrier_write_timeout_seconds = Some(1);
        let cred = uk_auth::Credential::active(
            b"client".to_vec(),
            b"0123456789abcdef0123456789abcdef".to_vec(),
        )
        .unwrap();
        let identity = AuthenticatedIdentity::from(&cred);
        let security = SecurityState::new(
            crate::security::test_tls_acceptor(),
            vec![cred],
            Vec::new(),
            uk_policy::PolicySet::default(),
            Duration::from_secs(30),
        );
        let permits = Arc::new(Semaphore::new(1));
        let task_permits = permits.clone();
        let (_tx, rx) = watch::channel(false);
        let handle = tokio::spawn(async move {
            run_authenticated_session(
                Box::new(tokio::io::empty()),
                Box::new(Stall),
                None,
                identity,
                security,
                &config,
                task_permits,
                1,
                relay::GlobalBufferControl::default(),
                relay::GlobalFlowBudget::default(),
                "127.0.0.1:1000".parse().unwrap(),
                rx,
                Arc::new(ServerMetrics::default()),
            )
            .await
        });
        tokio::task::yield_now().await;
        assert_eq!(permits.available_permits(), 0);
        // Do NOT send shutdown; wait for 1-second timeout to fire
        let result = time::timeout(Duration::from_millis(1500), handle).await;
        assert!(
            result.is_ok(),
            "SETTINGS write did not time out as expected"
        );
        let session_res = result.unwrap().unwrap();
        assert!(session_res.is_err(), "session should fail on timeout");
        let err = session_res.unwrap_err();
        assert!(
            err.to_string().contains("timed out")
                || err
                    .downcast_ref::<io::Error>()
                    .is_some_and(|e| e.kind() == io::ErrorKind::TimedOut),
            "expected timed out error, got: {err}"
        );
        assert_eq!(
            permits.available_permits(),
            1,
            "session permit must be reclaimed after write timeout"
        );
    }

    #[tokio::test]
    async fn settings_write_pre_shutdown_cancels_immediately_and_reclaims_permit() {
        let config: ServerConfig =
            toml::from_str(include_str!("../../../examples/server.toml")).unwrap();
        let cred = uk_auth::Credential::active(
            b"client".to_vec(),
            b"0123456789abcdef0123456789abcdef".to_vec(),
        )
        .unwrap();
        let identity = AuthenticatedIdentity::from(&cred);
        let security = SecurityState::new(
            crate::security::test_tls_acceptor(),
            vec![cred],
            Vec::new(),
            uk_policy::PolicySet::default(),
            Duration::from_secs(30),
        );
        let permits = Arc::new(Semaphore::new(1));
        let task_permits = permits.clone();
        let (_tx, rx) = watch::channel(true); // Already shut down!
        let result = run_authenticated_session(
            Box::new(tokio::io::empty()),
            Box::new(Stall),
            None,
            identity,
            security,
            &config,
            task_permits,
            1,
            relay::GlobalBufferControl::default(),
            relay::GlobalFlowBudget::default(),
            "127.0.0.1:1000".parse().unwrap(),
            rx,
            Arc::new(ServerMetrics::default()),
        )
        .await;
        assert!(
            result.is_err(),
            "session should fail immediately when server is already shut down"
        );
        assert_eq!(
            permits.available_permits(),
            1,
            "permit must be reclaimed immediately when server is already shut down"
        );
    }
}
