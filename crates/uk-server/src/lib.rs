//! Uncrowned King server library.

pub mod config;

mod observability;
pub mod quic;
mod relay;
mod security;
mod tls;

use std::{
    error::Error,
    fmt, future,
    future::Future,
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use bytes::BytesMut;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch},
    task::JoinSet,
    time,
};
use tokio_rustls::TlsAcceptor;
use tracing::{Instrument, debug, info, info_span, warn};
use uk_auth::{
    AuthChallenge, AuthResponse, AuthenticatedIdentity, ReplayCache, unix_now,
    verify_auth_response_identity,
};
use uk_proto::{
    BoxedCarrierReader, BoxedCarrierWriter, ErrorCode, ErrorPayload, Frame, FrameIoError,
    FrameLimits, FrameType, SettingKey, Settings, read_frame, validate_connection_frame,
    write_frame,
};

use crate::config::ServerConfig;
use crate::observability::{HandshakeFailureReason, ServerMetrics};
use crate::security::{AuthenticationSnapshot, SecurityState};

/// Server error type.
pub type AnyError = Box<dyn Error + Send + Sync>;

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
    config: ServerConfig,
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
            .send(ServerReloadRequest { config, response })
            .await
            .map_err(|_| ServerReloadError::ServerStopped)?;
        result
            .await
            .map_err(|_| ServerReloadError::ServerStopped)?
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
    max_sessions: usize,
    max_handshakes: usize,
}

#[derive(Clone)]
struct ConnectionRuntime {
    security: SecurityState,
    replay_cache: Arc<Mutex<ReplayCache>>,
    session_permits: Arc<Semaphore>,
    config: Arc<ServerConfig>,
    handshake_permits: Arc<Semaphore>,
    max_sessions: usize,
    max_handshakes: usize,
    metrics: Arc<ServerMetrics>,
}

impl ConnectionRuntime {
    async fn spawn_accepted(
        &self,
        connections: &mut JoinSet<()>,
        mut tcp: TcpStream,
        peer: SocketAddr,
        shutdown_rx: watch::Receiver<bool>,
    ) {
        self.metrics.record_accepted_connection();
        let Ok(handshake_permit) = Arc::clone(&self.handshake_permits).try_acquire_owned() else {
            self.metrics.record_rejected_handshake();
            warn!(
                event = "server.handshake.limit",
                peer = %peer,
                max_handshakes = self.max_handshakes
            );
            if let Err(err) = tcp.shutdown().await {
                debug!(
                    event = "server.handshake.limit_shutdown_error",
                    peer = %peer,
                    error = %err
                );
            }
            return;
        };
        let runtime = self.clone();
        let connection_id = next_connection_correlation_id();
        let connection = async move {
            if let Err(err) =
                handle_connection(runtime, tcp, handshake_permit, peer, shutdown_rx).await
            {
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
        self.metrics.record_accepted_connection();
        let Ok(handshake_permit) = Arc::clone(&self.handshake_permits).try_acquire_owned() else {
            self.metrics.record_rejected_handshake();
            warn!(
                event = "server.handshake.limit",
                peer = %peer,
                carrier = "quic",
                max_handshakes = self.max_handshakes
            );
            incoming.refuse();
            return;
        };
        let runtime = self.clone();
        let connection_id = next_connection_correlation_id();
        let connection = async move {
            if let Err(err) =
                handle_quic_connection(runtime, incoming, handshake_permit, peer, shutdown_rx).await
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
        max_sessions,
        max_handshakes,
    } = runtime;
    let listen = listener.local_addr()?;
    let session_permits = Arc::new(Semaphore::new(max_sessions));
    let handshake_permits = Arc::new(Semaphore::new(max_handshakes));
    let shutdown_timeout = listener_shutdown_timeout(config.shutdown_timeout_seconds());
    let metrics = Arc::new(ServerMetrics::default());
    metrics.set_security_generation(security.generation());
    let connection_runtime = ConnectionRuntime {
        security: security.clone(),
        replay_cache: Arc::clone(&replay_cache),
        session_permits: Arc::clone(&session_permits),
        config: Arc::clone(&config),
        handshake_permits,
        max_sessions,
        max_handshakes,
        metrics: Arc::clone(&metrics),
    };

    info!(event = "server.listen", listen = %listen);

    let quic_endpoint = build_quic_endpoint(&config)?;
    if let Some(endpoint) = &quic_endpoint {
        info!(event = "server.listen.quic", listen = %endpoint.local_addr()?);
    }

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
                    handle_reload_request(&config, &security, &metrics, request);
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
                    .spawn_accepted(&mut connections, tcp, peer, shutdown_tx.subscribe())
                    .await;
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

    if let Some(endpoint) = &quic_endpoint {
        endpoint.close(0_u32.into(), b"server shutdown");
    }
    drain_connection_tasks(&mut connections, shutdown_timeout).await;
    stop_observability(observability_shutdown_tx, observability_task).await;

    Ok(())
}

/// Builds the QUIC server endpoint when `quic_listen` is configured.
fn build_quic_endpoint(config: &ServerConfig) -> Result<Option<quinn::Endpoint>, AnyError> {
    let Some(listen) = &config.quic_listen else {
        return Ok(None);
    };
    let addr: SocketAddr = listen
        .parse()
        .map_err(|err| format!("invalid quic_listen address {listen}: {err}"))?;
    let rustls_config = tls::server_config(&config.cert_path, &config.key_path)?;
    let quic_config = quic::server_config(rustls_config)?;
    let endpoint = quic::bind_endpoint(quic_config, addr)?;
    Ok(Some(endpoint))
}

/// Accepts the next QUIC connection, or waits forever when QUIC is disabled.
async fn accept_quic(endpoint: Option<&quinn::Endpoint>) -> Option<quinn::Incoming> {
    match endpoint {
        Some(endpoint) => endpoint.accept().await,
        None => future::pending().await,
    }
}

fn handle_reload_request(
    config: &ServerConfig,
    security: &SecurityState,
    metrics: &ServerMetrics,
    request: ServerReloadRequest,
) {
    match apply_security_reload(config, security, request.config) {
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
    let listener = TcpListener::bind(listen).await?;
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
    let tls_config = tls::server_config(&config.cert_path, &config.key_path)?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let credentials = take_runtime_credentials(&mut config)?;
    let policy_set = config.policy_set()?;
    let security = SecurityState::new(
        tls_acceptor,
        credentials,
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
    let max_sessions = usize_limit("max_sessions", config.max_sessions())?;
    let max_handshakes = usize_limit("max_handshakes", config.max_handshakes())?;

    Ok(ServerRuntime {
        config: Arc::new(config),
        security,
        replay_cache,
        max_sessions,
        max_handshakes,
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

fn apply_security_reload(
    current: &ServerConfig,
    security: &SecurityState,
    mut candidate: ServerConfig,
) -> Result<u64, AnyError> {
    ensure_reload_compatible(current, &candidate)?;
    candidate.validate_sensitive_paths()?;
    let tls_config = tls::server_config(&candidate.cert_path, &candidate.key_path)?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let credentials = take_runtime_credentials(&mut candidate)?;
    let policy_set = candidate.policy_set()?;
    Ok(security.replace(
        tls_acceptor,
        credentials,
        policy_set,
        Duration::from_secs(candidate.auth_skew_seconds()),
    ))
}

fn ensure_reload_compatible(
    current: &ServerConfig,
    candidate: &ServerConfig,
) -> Result<(), AnyError> {
    if let Some(field) = changed_static_config_field(current, candidate) {
        return Err(reload_requires_restart(field));
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
    } else {
        None
    }
}

fn reload_static_limits(config: &ServerConfig) -> [(&'static str, u64); 17] {
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

async fn drain_connection_tasks(connections: &mut JoinSet<()>, shutdown_timeout: Option<Duration>) {
    if let Some(timeout) = shutdown_timeout {
        if time::timeout(timeout, join_connection_tasks(connections))
            .await
            .is_err()
        {
            warn!(
                event = "server.shutdown.timeout",
                remaining_connections = connections.len(),
                timeout_seconds = timeout.as_secs()
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
    handshake_permit: OwnedSemaphorePermit,
    peer: SocketAddr,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<(), AnyError> {
    tcp.set_nodelay(true)?;
    if *shutdown_rx.borrow() {
        return Ok(());
    }
    let authentication = runtime.security.authentication_snapshot();
    let replay_cache = Arc::clone(&runtime.replay_cache);
    let config = Arc::clone(&runtime.config);
    let handshake =
        async move { complete_handshake(tcp, authentication, replay_cache, &config).await };
    serve_authenticated_carrier(runtime, handshake_permit, peer, shutdown_rx, handshake).await
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
        let (reader, writer, exporter) = quic::accept_carrier(&connection)
            .await
            .map_err(|err| phase_error("quic carrier", HandshakeFailureReason::Tls, err))?;
        authenticate_carrier(
            reader,
            writer,
            exporter,
            authentication,
            replay_cache,
            &config,
        )
        .await
    };
    serve_authenticated_carrier(runtime, handshake_permit, peer, shutdown_rx, handshake).await
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
    let (carrier_reader, carrier_writer, identity) = match handshake_result {
        Ok(handshake) => handshake,
        Err(err) => {
            runtime
                .metrics
                .record_failed_handshake(handshake_failure_reason(&err));
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
        identity,
        runtime.security,
        &runtime.config,
        runtime.session_permits,
        runtime.max_sessions,
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
    identity: AuthenticatedIdentity,
    security: SecurityState,
    config: &ServerConfig,
    session_permits: Arc<Semaphore>,
    max_sessions: usize,
    peer: SocketAddr,
    shutdown_rx: watch::Receiver<bool>,
    metrics: Arc<ServerMetrics>,
) -> Result<(), AnyError> {
    let Ok(session_permit) = session_permits.try_acquire_owned() else {
        metrics.record_rejected_session();
        warn!(event = "server.session.limit", peer = %peer, max_sessions);
        let _ = write_connection_error(&mut carrier_writer, ErrorCode::ResourceLimit).await;
        let _ = carrier_writer.shutdown().await;
        return Err("authenticated session limit exceeded".into());
    };
    let _session_permit = session_permit;
    let _active_session = metrics.begin_session();

    write_server_settings(&mut carrier_writer, config).await?;

    let carrier = relay::ServerCarrier::new(carrier_reader, carrier_writer);

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
            udp_flow_idle_timeout: udp_flow_idle_timeout(config.udp_flow_idle_timeout_seconds()),
            session_task_shutdown_timeout: listener_shutdown_timeout(
                config.shutdown_timeout_seconds(),
            ),
        }),
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
    let _tls_config = tls::server_config(&config.cert_path, &config.key_path)?;
    Ok(())
}

async fn complete_handshake(
    tcp: tokio::net::TcpStream,
    authentication: AuthenticationSnapshot,
    replay_cache: Arc<Mutex<ReplayCache>>,
    config: &ServerConfig,
) -> Result<
    (
        BoxedCarrierReader,
        BoxedCarrierWriter,
        AuthenticatedIdentity,
    ),
    AnyError,
> {
    let stream = authentication
        .tls_acceptor
        .accept(tcp)
        .await
        .map_err(|err| phase_error("tls accept", HandshakeFailureReason::Tls, err))?;
    tls::verify_alpn(&stream)
        .map_err(|err| phase_error("tls alpn verify", HandshakeFailureReason::Tls, err))?;
    let exporter = tls::exporter(&stream)
        .map_err(|err| phase_error("tls exporter", HandshakeFailureReason::Tls, err))?;
    let (reader, writer) = tokio::io::split(stream);
    authenticate_carrier(
        Box::new(reader),
        Box::new(writer),
        exporter,
        authentication,
        replay_cache,
        config,
    )
    .await
}

/// Runs the UK challenge-response authentication over an established,
/// ALPN-verified carrier. This is carrier-neutral: the TLS/TCP and QUIC
/// acceptors both establish their transport, derive the exporter binding, and
/// then delegate the identical frame exchange to this function.
async fn authenticate_carrier(
    mut reader: BoxedCarrierReader,
    mut writer: BoxedCarrierWriter,
    exporter: [u8; 32],
    authentication: AuthenticationSnapshot,
    replay_cache: Arc<Mutex<ReplayCache>>,
    config: &ServerConfig,
) -> Result<
    (
        BoxedCarrierReader,
        BoxedCarrierWriter,
        AuthenticatedIdentity,
    ),
    AnyError,
> {
    let challenge = AuthChallenge::generate(unix_now());

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
    write_frame(&mut writer, &challenge_frame)
        .await
        .map_err(|err| {
            let reason = frame_io_failure_reason(&err);
            phase_error("write auth challenge", reason, err)
        })?;

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
    let now = unix_now();
    let verification = {
        let mut replay_cache = replay_cache.lock().await;
        verify_auth_response_identity(
            &authentication.credentials,
            &exporter,
            &challenge,
            &response,
            now,
            authentication.auth_skew,
            &mut replay_cache,
        )
    };
    let identity = match verification {
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

    info!(
        event = "auth.success",
        key_id_hex = %hex_encode(&identity.key_id),
        security_generation = authentication.generation
    );

    Ok((reader, writer, identity))
}

async fn write_server_settings<W>(stream: &mut W, config: &ServerConfig) -> Result<(), AnyError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let settings = server_settings(config);
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

async fn write_connection_error<W>(stream: &mut W, code: ErrorCode) -> Result<(), AnyError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let frame = connection_error_frame(code)?;
    write_frame(stream, &frame).await?;
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

fn server_settings(config: &ServerConfig) -> Settings {
    let mut settings = Settings::default();
    settings.set(SettingKey::ProtocolRevision, 1);
    settings.set(SettingKey::MaxFrameSize, config.max_frame_size());
    settings.set(SettingKey::MaxStreams, config.max_streams());
    settings.set(SettingKey::MaxUdpFlows, config.max_udp_flows());
    settings.set(SettingKey::SupportsUdpDatagram, 0);
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
    }) || error.to_string() == "tls handshake eof"
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

fn is_tls_handshake_eof(error: &io::Error) -> bool {
    error.to_string() == "tls handshake eof"
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
        }
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

        let settings = server_settings(&config);

        assert_eq!(settings.get(SettingKey::ProtocolRevision), Some(1));
        assert_eq!(settings.get(SettingKey::MaxFrameSize), Some(32_768));
        assert_eq!(settings.get(SettingKey::MaxStreams), Some(17));
        assert_eq!(settings.get(SettingKey::MaxUdpFlows), Some(11));
        assert_eq!(settings.get(SettingKey::SupportsUdpDatagram), Some(0));
        assert_eq!(settings.get(SettingKey::SupportsUdpStreamFallback), Some(1));
        assert_eq!(settings.get(SettingKey::IdleTimeoutSeconds), Some(42));
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
            current.policy_set().unwrap(),
            Duration::from_secs(current.auth_skew_seconds()),
        );
        let mut candidate = current.clone();
        candidate.listen = "127.0.0.1:2".to_owned();

        let error = apply_security_reload(&current, &security, candidate)
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
            current.policy_set().unwrap(),
            Duration::from_secs(current.auth_skew_seconds()),
        );
        let mut candidate = current.clone();
        candidate.credentials[0].secret = "too-short".to_owned();

        assert!(apply_security_reload(&current, &security, candidate).is_err());
        assert_eq!(security.generation(), 1);
        assert_eq!(
            security.authentication_snapshot().credentials[0].key_id,
            b"client"
        );
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
    fn server_settings_disable_udp_stream_fallback_without_udp_flows() {
        let mut config = minimal_config();
        config.limits = Some(LimitConfig {
            max_udp_flows: Some(0),
            ..LimitConfig::default()
        });

        let settings = server_settings(&config);

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
        let unexpected_eof: AnyError =
            io::Error::new(io::ErrorKind::UnexpectedEof, "client closed").into();
        let connection_reset: AnyError =
            io::Error::new(io::ErrorKind::ConnectionReset, "client reset").into();
        let broken_pipe: AnyError =
            io::Error::new(io::ErrorKind::BrokenPipe, "client pipe closed").into();
        let not_connected: AnyError =
            io::Error::new(io::ErrorKind::NotConnected, "client gone").into();
        let rustls_eof: AnyError =
            io::Error::new(io::ErrorKind::InvalidData, "tls handshake eof").into();
        let protocol_error: AnyError =
            io::Error::new(io::ErrorKind::InvalidData, "invalid certificate").into();

        assert!(is_clean_tls_handshake_disconnect(&unexpected_eof));
        assert!(is_clean_tls_handshake_disconnect(&connection_reset));
        assert!(is_clean_tls_handshake_disconnect(&broken_pipe));
        assert!(is_clean_tls_handshake_disconnect(&not_connected));
        assert!(is_clean_tls_handshake_disconnect(&rustls_eof));
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
            drain_connection_tasks(&mut connections, Some(Duration::from_millis(10))),
        )
        .await
        .unwrap();

        assert!(connections.is_empty());
    }

    #[tokio::test]
    async fn server_shutdown_drain_waits_for_completed_connection_tasks() {
        let mut connections = JoinSet::new();
        connections.spawn(async {});

        drain_connection_tasks(&mut connections, Some(Duration::from_secs(1))).await;

        assert!(connections.is_empty());
    }
}
