//! SOCKS5-to-UK TCP and UDP relay.

use std::{
    collections::{HashMap, hash_map::Entry},
    error::Error,
    fmt,
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore, mpsc, watch},
    task::{Id, JoinError, JoinSet},
    time,
};
use tracing::{Instrument, debug, info, info_span, warn};
use uk_proto::{
    BoxedCarrierReader, BoxedCarrierWriter, BoxedDatagramChannel, DatagramSendOutcome, ErrorCode,
    ErrorPayload, FIRST_CLIENT_FLOW_ID, FLOW_ID_STEP, Frame, FrameIoError, FrameLimits, FrameType,
    NegotiatedSettings, TCP_CLOSE_ERROR, TCP_CLOSE_NORMAL, TCP_OPEN_FLAGS_NONE, Target, TcpClose,
    TcpOpen, UDP_CLOSE_ERROR, UDP_CLOSE_NORMAL, UdpClose, UdpOpen, datagram,
    is_client_initiated_flow_id, read_frame, validate_connection_frame, varint::MAX_VARINT,
    write_frame,
};

use crate::{
    ClientReloadReceiver, ClientReloadRequest,
    config::{ClientConfig, validate_endpoint},
    config_state::{ClientConfigSnapshot, ClientConfigState},
    observability::{ActiveFlowGuard, ClientMetrics, RelayDirection, RelayProtocol},
    session, socks5,
};

const FLOW_ID_ALLOCATION_ATTEMPTS: usize = 1024;
/// Floor, ceiling, and nominal frame size used to size a flow's inbound frame
/// queue from its byte limit (see [`flow_frame_queue_capacity`]).
const FLOW_FRAME_QUEUE_MIN_CAPACITY: usize = 64;
const FLOW_FRAME_QUEUE_MAX_CAPACITY: usize = 8192;
const FLOW_FRAME_QUEUE_NOMINAL_FRAME_BYTES: usize = 1024;
const UDP_ASSOCIATION_EVENT_QUEUE_CAPACITY: usize = 128;

/// Depth of a flow's inbound frame queue, derived from its per-flow byte limit
/// so the configured byte budget — not a small fixed frame count — governs when
/// an overwhelmed flow is shed. Memory stays bounded by the byte accounting
/// (`BufferedFlowFrame` reserves and releases against the byte limits), so a
/// deeper queue only raises the shed threshold for a momentarily-slow consumer.
fn flow_frame_queue_capacity(max_buffered_bytes_per_flow: usize) -> usize {
    (max_buffered_bytes_per_flow / FLOW_FRAME_QUEUE_NOMINAL_FRAME_BYTES)
        .clamp(FLOW_FRAME_QUEUE_MIN_CAPACITY, FLOW_FRAME_QUEUE_MAX_CAPACITY)
}
const UDP_SEND_ATTEMPTS: usize = 2;
const RELAY_BUFFER_SIZE: usize = 16 * 1024;
const UDP_ASSOCIATION_BUFFER_SIZE: usize = 65_536;
const ACCEPT_RETRY_BASE_MILLIS: u64 = 10;
const ACCEPT_RETRY_MAX_MILLIS: u64 = 1_000;
static NEXT_SOCKS_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_CLIENT_SESSION_ID: AtomicU64 = AtomicU64::new(1);

type AnyError = Box<dyn Error + Send + Sync>;
type CarrierWriter = Arc<Mutex<BoxedCarrierWriter>>;
type FlowTable = Arc<Mutex<HashMap<u64, ClientFlowRoute>>>;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientConnectionState {
    NegotiatingSocks,
    Opening,
    Relaying,
    Closing,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeepalivePong {
    Matched(u64),
    InvalidPayload,
    Unexpected { nonce: u64, expected_nonce: u64 },
}

struct ClientSession {
    correlation_id: u64,
    config_generation: u64,
    writer: CarrierWriter,
    flows: FlowTable,
    limits: FrameLimits,
    data_frame_size: usize,
    max_streams: u64,
    max_udp_flows: u64,
    admission: FlowAdmissionControl,
    supports_udp_stream_fallback: bool,
    supports_udp_datagram: bool,
    datagrams: Option<BoxedDatagramChannel>,
    max_pending_open_bytes: usize,
    max_buffered_bytes_per_session: usize,
    max_buffered_bytes_per_flow: usize,
    session_buffer: ClientSessionBufferControl,
    open_timeout: Option<Duration>,
    task_shutdown_timeout: Option<Duration>,
    tasks: Mutex<ClientSessionTasks>,
    shutdown: ClientSessionShutdown,
    draining: AtomicBool,
    metrics: Arc<ClientMetrics>,
    metric_state: StdMutex<ClientSessionMetricState>,
    next_flow_id: AtomicU64,
    next_ping_nonce: AtomicU64,
    outstanding_ping_nonce: AtomicU64,
    last_pong_nonce: AtomicU64,
    pong_notify: Notify,
}

struct ClientSessionManager {
    config: ClientConfigState,
    metrics: Arc<ClientMetrics>,
    /// Bounded pool of live authenticated carrier sessions of the current
    /// config generation. New flows are placed least-loaded across the pool so
    /// a bulk flow's shedding on one carrier does not stall latency-sensitive
    /// flows on the others (whitepaper §13). Draining sessions are removed here
    /// and kept alive only by their remaining flows.
    pool: Mutex<Vec<Arc<ClientSession>>>,
    connect_lock: Mutex<()>,
    config_publish_lock: Mutex<()>,
    recent_connect_failure: Mutex<Option<CachedConnectFailure>>,
    /// Background teardown of sessions pruned from the pool, kept off the
    /// flow-open path. Drained by [`ClientSessionManager::shutdown`].
    reapers: Mutex<JoinSet<()>>,
    closed: AtomicBool,
}

#[derive(Clone)]
struct SocksConnectionRuntime {
    sessions: Arc<ClientSessionManager>,
    metrics: Arc<ClientMetrics>,
    connection_slots: Arc<Semaphore>,
    handshake_timeout: Option<Duration>,
    max_connections: usize,
}

#[derive(Clone, Debug)]
struct CachedConnectFailure {
    generation: u64,
    message: Arc<str>,
    expires_at: Option<time::Instant>,
}

#[derive(Debug)]
struct CachedConnectFailureError {
    message: Arc<str>,
}

#[derive(Debug)]
struct SessionDrainingError;

/// Owns a freshly connected session until it is published into the pool.
///
/// [`ClientSession::connect`] returns with the carrier-reader, datagram-reader
/// and keepalive tasks already spawned, each holding its own
/// `Arc<ClientSession>` — a reference cycle that only `close()` breaks. The
/// publish path then awaits several locks, so a dropped `connect_and_pool`
/// future (shutdown, `abort_all`) would otherwise strand a fully authenticated
/// session: its reader parked forever on a `shutdown.closed()` that never
/// fires, and invisible to [`ClientSessionManager::shutdown`].
///
/// Dropping this guard without [`PendingClientSession::into_session`] therefore
/// tears the session down. The success path calls `into_session`, so a pooled
/// session is never closed by the guard.
struct PendingClientSession {
    session: Option<Arc<ClientSession>>,
}

struct ClientSessionTasks {
    tasks: JoinSet<ClientSessionTaskKind>,
    kinds: HashMap<Id, ClientSessionTaskKind>,
}

impl fmt::Display for CachedConnectFailureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "recent UK session connect failed; retry cooldown active: {}",
            self.message
        )
    }
}

impl Error for CachedConnectFailureError {}

impl fmt::Display for SessionDrainingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("uk session is draining")
    }
}

impl Error for SessionDrainingError {}

impl PendingClientSession {
    fn new(session: Arc<ClientSession>) -> Self {
        Self {
            session: Some(session),
        }
    }

    /// Publishes the session to the caller, disarming the guard.
    fn into_session(mut self) -> Arc<ClientSession> {
        self.session
            .take()
            .expect("pending client session is taken exactly once")
    }

    /// Tears the session down on a path that can await, avoiding the spawned
    /// fallback in [`Drop`].
    async fn close_and_wait(mut self) {
        if let Some(session) = self.session.take() {
            session.close_and_wait().await;
        }
    }
}

impl Drop for PendingClientSession {
    fn drop(&mut self) {
        let Some(session) = self.session.take() else {
            return;
        };
        warn!(
            event = "client.session.connect_cancelled",
            correlation_id = session.correlation_id
        );
        // A destructor cannot await, so hand the teardown to the runtime. With
        // no runtime left there is nothing to run it on either, so fall back to
        // flipping the shutdown flag: that alone wakes the session's tasks off
        // their `shutdown.closed()` wait so they can exit.
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move { session.close_and_wait().await });
            }
            Err(_) => {
                session.shutdown.close();
            }
        }
    }
}

impl Default for ClientSessionTasks {
    fn default() -> Self {
        Self {
            tasks: JoinSet::new(),
            kinds: HashMap::new(),
        }
    }
}

impl ClientSessionTasks {
    fn spawn<F>(&mut self, kind: ClientSessionTaskKind, task: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let handle = self.tasks.spawn(async move {
            task.await;
            kind
        });
        self.kinds.insert(handle.id(), kind);
    }

    fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    fn len(&self) -> usize {
        self.tasks.len()
    }

    async fn join_next(&mut self) {
        let Some(result) = self.tasks.join_next_with_id().await else {
            return;
        };
        match result {
            Ok((id, kind)) => {
                self.kinds.remove(&id);
                debug!(event = "client.session.task.done", kind = ?kind);
            }
            Err(err) => {
                let kind = self.kinds.remove(&err.id());
                log_client_session_task_error(kind, &err);
            }
        }
    }

    async fn join_all(&mut self) {
        while !self.is_empty() {
            self.join_next().await;
        }
    }

    fn abort_all(&mut self) {
        self.tasks.abort_all();
    }
}

struct ClientFlow {
    id: u64,
    frames: mpsc::Receiver<BufferedFlowFrame>,
    session: Arc<ClientSession>,
    pending_local_data: Vec<Bytes>,
    metric_guard: Option<ActiveFlowGuard>,
    /// Session admission slot held for the flow's whole life; dropping the flow
    /// returns the capacity to its session (see [`FlowAdmissionControl`]).
    _slot: FlowSlot,
}

impl Drop for ClientFlow {
    fn drop(&mut self) {
        let _ = self.metric_guard.take();
    }
}

/// Admission control for one carrier session's flow ceilings.
///
/// Holding a permit *is* the reservation. Selecting a session used to read
/// `flow_count()`, drop the lock, and only reserve the slot much later inside
/// the open path, so a burst of concurrent SOCKS handlers all observed
/// `load < max_streams` on the same session, `max_streams` of them won the late
/// reservation and the rest were rejected — while the pool never grew, because
/// growth was gated on selection returning nothing. Reserving here instead
/// makes admission atomic against the server's `max_streams` and `max_udp_flows`
/// while still letting the pool grow to `max_carrier_sessions`.
///
/// Permits are released when the [`FlowSlot`] is dropped, so no error,
/// rejection or cancellation path can leak a reservation, and no async
/// destructor is needed.
#[derive(Debug)]
struct FlowAdmissionControl {
    streams: Arc<Semaphore>,
    udp_flows: Arc<Semaphore>,
}

/// A reserved flow slot. Dropping it returns the capacity to its session.
#[derive(Debug)]
struct FlowSlot {
    _stream: OwnedSemaphorePermit,
    _udp_flow: Option<OwnedSemaphorePermit>,
}

/// A flow slot already reserved on a specific session, handed from session
/// selection to the open path.
struct FlowAdmission {
    session: Arc<ClientSession>,
    slot: FlowSlot,
}

/// Why one session refused to admit a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdmissionRefusal {
    /// The session is draining or closed.
    Unavailable,
    /// The session is at the negotiated `max_streams`.
    StreamLimit,
    /// The session has stream capacity but is at `max_udp_flows`.
    UdpFlowLimit,
}

/// Why no pooled session could admit a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PoolAdmissionRefusal {
    /// No live session has stream capacity, so growing the pool may help.
    StreamLimit,
    /// A live session has stream capacity but is at `max_udp_flows`. That is a
    /// per-session server limit, so dialling another carrier to work around it
    /// is not the client's call — reject the request instead.
    UdpFlowLimit,
}

impl FlowAdmissionControl {
    fn new(max_streams: u64, max_udp_flows: u64) -> Self {
        Self {
            streams: Arc::new(Semaphore::new(semaphore_permits(max_streams))),
            udp_flows: Arc::new(Semaphore::new(semaphore_permits(max_udp_flows))),
        }
    }

    /// Atomically reserves a flow slot, or reports which ceiling refused it.
    ///
    /// A UDP flow consumes both a stream slot and a UDP-flow slot; when the UDP
    /// ceiling is full the stream permit taken first is dropped here, so a
    /// refused UDP admission costs no stream capacity.
    fn try_admit(&self, protocol: FlowProtocol) -> Result<FlowSlot, AdmissionRefusal> {
        let stream = Arc::clone(&self.streams)
            .try_acquire_owned()
            .map_err(|_| AdmissionRefusal::StreamLimit)?;
        let udp_flow = match protocol {
            FlowProtocol::Tcp => None,
            FlowProtocol::Udp => Some(
                Arc::clone(&self.udp_flows)
                    .try_acquire_owned()
                    .map_err(|_| AdmissionRefusal::UdpFlowLimit)?,
            ),
        };
        Ok(FlowSlot {
            _stream: stream,
            _udp_flow: udp_flow,
        })
    }

    #[cfg(test)]
    fn available_streams(&self) -> usize {
        self.streams.available_permits()
    }

    #[cfg(test)]
    fn available_udp_flows(&self) -> usize {
        self.udp_flows.available_permits()
    }
}

/// Clamps a negotiated flow ceiling to what a [`Semaphore`] can represent.
fn semaphore_permits(limit: u64) -> usize {
    usize::try_from(limit)
        .unwrap_or(Semaphore::MAX_PERMITS)
        .min(Semaphore::MAX_PERMITS)
}

struct UdpAssociation {
    socket: Arc<UdpSocket>,
    idle_timeout: Option<Duration>,
    flow_event_tx: mpsc::Sender<UdpAssociationFlowEvent>,
    client_endpoint: UdpClientEndpoint,
    flows_by_target: HashMap<Target, UdpAssociationFlow>,
    flow_tasks: JoinSet<UdpFlowTaskResult>,
}

#[derive(Debug, Clone)]
struct UdpClientEndpoint {
    requested: socks5::SocksEndpoint,
    /// Source IP of the SOCKS control connection that created this association.
    ///
    /// RFC 1928 lets a client that does not yet know the source address it will
    /// send UDP from advertise all zeros, and virtually every client does. The
    /// association socket is bound to the SOCKS listener's IP rather than
    /// loopback, so without this the first datagram from *any* host that can
    /// reach the bound port would be "learned" as the client and would then
    /// relay UDP under the real client's credentials.
    control_peer_ip: IpAddr,
    learned: Option<SocketAddr>,
}

#[derive(Clone)]
struct UdpAssociationFlow {
    id: u64,
    session: Arc<ClientSession>,
    last_activity: time::Instant,
}

struct UdpFlowTaskResult {
    flow_id: u64,
    target: Target,
    outcome: Result<(), AnyError>,
}

enum UdpAssociationFlowEvent {
    Activity { flow_id: u64, target: Target },
}

enum UdpAssociationFlowLookup {
    Open(UdpAssociationFlow),
    NoFlow,
    Cancelled,
}

enum OpenOutcome {
    Open(ClientFlow),
    Rejected(socks5::Reply),
    Cancelled,
}

enum OpenWaitOutcome {
    Frame(Frame),
    Cancelled,
    TimedOut,
    LocalResourceLimit,
}

enum UdpOpenWaitOutcome {
    Frame(Frame),
    Cancelled,
    TimedOut,
}

enum PendingOpenLocalRead {
    Buffered,
    Closed,
    ResourceLimit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpenResponse {
    Accepted,
    Rejected(socks5::Reply),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlowFrameRoute {
    InvalidFlowId,
    UnknownFlow,
    ProtocolMismatch,
    Enqueued,
    FlowClosed,
    FlowQueueFull,
    SessionQueueFull,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlowProtocol {
    Tcp,
    Udp,
}

impl FlowProtocol {
    const fn metric_protocol(self) -> RelayProtocol {
        match self {
            Self::Tcp => RelayProtocol::Tcp,
            Self::Udp => RelayProtocol::Udp,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientSessionMetricState {
    Active,
    Draining,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientSessionTaskKind {
    CarrierReader,
    DatagramReader,
    Keepalive,
}

#[derive(Debug, Clone)]
struct ClientFlowRoute {
    sender: mpsc::Sender<BufferedFlowFrame>,
    flow_buffer: ClientFlowBufferControl,
    protocol: FlowProtocol,
}

#[derive(Debug, Clone)]
struct ClientSessionBufferControl {
    buffered_bytes: Arc<AtomicUsize>,
}

#[derive(Debug, Clone)]
struct ClientFlowBufferControl {
    buffered_bytes: Arc<AtomicUsize>,
}

#[derive(Debug)]
struct BufferedFlowFrame {
    frame: Option<Frame>,
    payload_len: usize,
    flow_control: ClientFlowBufferControl,
    session_control: ClientSessionBufferControl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BufferReserveError {
    FlowLimit,
    SessionLimit,
}

#[derive(Clone)]
struct ClientSessionShutdown {
    closed: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl Default for ClientSessionShutdown {
    fn default() -> Self {
        Self {
            closed: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
        }
    }
}

impl ClientSessionShutdown {
    fn close(&self) -> bool {
        if self.closed.swap(true, Ordering::SeqCst) {
            false
        } else {
            self.notify.notify_waiters();
            true
        }
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    async fn closed(&self) {
        loop {
            let notified = self.notify.notified();
            if self.is_closed() {
                return;
            }
            notified.await;
        }
    }
}

impl Default for ClientSessionBufferControl {
    fn default() -> Self {
        Self {
            buffered_bytes: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl ClientSessionBufferControl {
    fn reserve_bytes(&self, amount: usize, limit: usize) -> bool {
        reserve_bytes(&self.buffered_bytes, amount, limit)
    }

    fn release_bytes(&self, amount: usize) {
        release_bytes(&self.buffered_bytes, amount);
    }

    #[cfg(test)]
    fn buffered_bytes(&self) -> usize {
        self.buffered_bytes.load(Ordering::SeqCst)
    }
}

impl Default for ClientFlowBufferControl {
    fn default() -> Self {
        Self {
            buffered_bytes: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl ClientFlowBufferControl {
    fn reserve_bytes(&self, amount: usize, limit: usize) -> bool {
        reserve_bytes(&self.buffered_bytes, amount, limit)
    }

    fn release_bytes(&self, amount: usize) {
        release_bytes(&self.buffered_bytes, amount);
    }

    #[cfg(test)]
    fn buffered_bytes(&self) -> usize {
        self.buffered_bytes.load(Ordering::SeqCst)
    }
}

impl ClientFlowRoute {
    fn new(sender: mpsc::Sender<BufferedFlowFrame>, protocol: FlowProtocol) -> Self {
        Self {
            sender,
            flow_buffer: ClientFlowBufferControl::default(),
            protocol,
        }
    }
}

impl BufferedFlowFrame {
    fn new(
        frame: Frame,
        flow_control: ClientFlowBufferControl,
        session_control: ClientSessionBufferControl,
        flow_byte_limit: usize,
        session_byte_limit: usize,
    ) -> Result<Self, BufferReserveError> {
        let payload_len = frame.payload.len();
        if !flow_control.reserve_bytes(payload_len, flow_byte_limit) {
            return Err(BufferReserveError::FlowLimit);
        }
        if !session_control.reserve_bytes(payload_len, session_byte_limit) {
            flow_control.release_bytes(payload_len);
            return Err(BufferReserveError::SessionLimit);
        }
        Ok(Self {
            frame: Some(frame),
            payload_len,
            flow_control,
            session_control,
        })
    }

    fn into_frame(mut self) -> Result<Frame, AnyError> {
        self.release();
        self.frame
            .take()
            .ok_or_else(|| "buffered frame missing".into())
    }

    fn release(&mut self) {
        if self.payload_len > 0 {
            self.flow_control.release_bytes(self.payload_len);
            self.session_control.release_bytes(self.payload_len);
            self.payload_len = 0;
        }
    }
}

impl Drop for BufferedFlowFrame {
    fn drop(&mut self) {
        self.release();
    }
}

pub(crate) async fn run_socks5_listener_until_shutdown<F>(
    config: ClientConfig,
    listen: String,
    shutdown: F,
) -> Result<(), AnyError>
where
    F: Future<Output = ()> + Send,
{
    crate::check_config(&config)?;
    validate_endpoint("socks listen", &listen)?;
    let listener = TcpListener::bind(&listen).await?;
    run_socks5_listener_on_until_shutdown_inner(config, listener, None, shutdown).await
}

pub(crate) async fn run_socks5_listener_until_shutdown_with_reload<F>(
    config: ClientConfig,
    listen: String,
    reload_rx: ClientReloadReceiver,
    shutdown: F,
) -> Result<(), AnyError>
where
    F: Future<Output = ()> + Send,
{
    crate::check_config(&config)?;
    validate_endpoint("socks listen", &listen)?;
    let listener = TcpListener::bind(&listen).await?;
    run_socks5_listener_on_until_shutdown_inner(config, listener, Some(reload_rx), shutdown).await
}

pub(crate) async fn run_socks5_listener_on_until_shutdown<F>(
    config: ClientConfig,
    listener: TcpListener,
    shutdown: F,
) -> Result<(), AnyError>
where
    F: Future<Output = ()> + Send,
{
    run_socks5_listener_on_until_shutdown_inner(config, listener, None, shutdown).await
}

pub(crate) async fn run_socks5_listener_on_until_shutdown_with_reload<F>(
    config: ClientConfig,
    listener: TcpListener,
    reload_rx: ClientReloadReceiver,
    shutdown: F,
) -> Result<(), AnyError>
where
    F: Future<Output = ()> + Send,
{
    run_socks5_listener_on_until_shutdown_inner(config, listener, Some(reload_rx), shutdown).await
}

async fn run_socks5_listener_on_until_shutdown_inner<F>(
    config: ClientConfig,
    listener: TcpListener,
    mut reload_rx: Option<ClientReloadReceiver>,
    shutdown: F,
) -> Result<(), AnyError>
where
    F: Future<Output = ()> + Send,
{
    crate::check_config(&config)?;
    let listen = listener.local_addr()?;
    let socks_handshake_timeout = timeout(config.socks_handshake_timeout_seconds());
    let shutdown_timeout = timeout(config.shutdown_timeout_seconds());
    let max_socks_connections = usize_limit(config.max_socks_connections())?;
    let metrics = Arc::new(ClientMetrics::default());
    let sessions = Arc::new(ClientSessionManager::new(config, Arc::clone(&metrics)));
    let (observability_shutdown_tx, observability_shutdown_rx) = watch::channel(false);
    let initial_config = sessions.config.snapshot();
    let observability_task = start_observability(
        &initial_config.config,
        Arc::clone(&metrics),
        observability_shutdown_rx,
    )
    .await?;
    drop(initial_config);
    let connection_runtime = SocksConnectionRuntime {
        sessions: Arc::clone(&sessions),
        metrics: Arc::clone(&metrics),
        connection_slots: Arc::new(Semaphore::new(max_socks_connections)),
        handshake_timeout: socks_handshake_timeout,
        max_connections: max_socks_connections,
    };
    info!(event = "socks5.listen", listen = %listen);

    let (shutdown_tx, _shutdown_rx) = watch::channel(false);
    metrics.set_ready(true);
    let mut connections = JoinSet::new();
    let mut accept_backoff = ListenerAcceptBackoff::default();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            () = &mut shutdown => {
                info!(event = "socks5.shutdown");
                metrics.set_ready(false);
                let _ = shutdown_tx.send(true);
                break;
            }
            accepted = listener.accept() => {
                let (local, peer) = match accepted {
                    Ok(connection) => {
                        accept_backoff.reset();
                        connection
                    }
                    Err(err) => {
                        let retry_delay = accept_backoff.next_delay();
                        warn!(
                            event = "socks5.accept.error",
                            error = %err,
                            retry_delay_ms = retry_delay.as_millis()
                        );
                        time::sleep(retry_delay).await;
                        continue;
                    }
                };
                connection_runtime
                    .spawn_accepted(
                        &mut connections,
                        local,
                        peer,
                        shutdown_tx.subscribe(),
                    )
                    .await;
            }
            joined = connections.join_next(), if !connections.is_empty() => {
                log_socks_task_result(joined);
            }
            reload = receive_reload(&mut reload_rx) => {
                if let Some(request) = reload {
                    handle_reload_request(&sessions, request).await;
                } else {
                    reload_rx = None;
                    debug!(event = "client.config.reload_channel_closed");
                }
            }
        }
    }

    drain_socks_tasks(&mut connections, shutdown_timeout).await;
    sessions.shutdown().await;
    stop_observability(observability_shutdown_tx, observability_task).await;

    Ok(())
}

async fn start_observability(
    config: &ClientConfig,
    metrics: Arc<ClientMetrics>,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<Option<tokio::task::JoinHandle<()>>, AnyError> {
    let Some(listen) = &config.observability_listen else {
        return Ok(None);
    };
    let listener = TcpListener::bind(listen).await?;
    Ok(Some(tokio::spawn(crate::observability::serve(
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
            warn!(event = "client.observability.task_error", error = %err);
        }
    }
}

async fn receive_reload(
    reload_rx: &mut Option<ClientReloadReceiver>,
) -> Option<ClientReloadRequest> {
    match reload_rx {
        Some(reload_rx) => reload_rx.rx.recv().await,
        None => std::future::pending().await,
    }
}

async fn handle_reload_request(sessions: &ClientSessionManager, request: ClientReloadRequest) {
    let result = sessions.reload(request.config).await;
    match &result {
        Ok(generation) => info!(
            event = "client.config.reload_success",
            config_generation = generation
        ),
        Err(err) => warn!(event = "client.config.reload_failure", error = %err),
    }
    let _ = request.response.send(result.map_err(|err| err.to_string()));
}

async fn drain_socks_tasks(connections: &mut JoinSet<()>, shutdown_timeout: Option<Duration>) {
    if let Some(timeout) = shutdown_timeout {
        if time::timeout(timeout, join_socks_tasks(connections))
            .await
            .is_err()
        {
            warn!(
                event = "socks5.shutdown.timeout",
                remaining_connections = connections.len(),
                timeout_seconds = timeout.as_secs()
            );
            connections.abort_all();
            join_socks_tasks(connections).await;
        }
    } else {
        join_socks_tasks(connections).await;
    }
}

async fn drain_client_session_tasks(
    tasks: &mut ClientSessionTasks,
    shutdown_timeout: Option<Duration>,
) {
    if let Some(timeout) = shutdown_timeout {
        if time::timeout(timeout, tasks.join_all()).await.is_err() {
            warn!(
                event = "client.session.task_shutdown.timeout",
                remaining_tasks = tasks.len(),
                timeout_seconds = timeout.as_secs()
            );
            tasks.abort_all();
            tasks.join_all().await;
        }
    } else {
        tasks.join_all().await;
    }
}

fn log_client_session_task_error(kind: Option<ClientSessionTaskKind>, err: &JoinError) {
    if err.is_cancelled() {
        debug!(event = "client.session.task.cancelled", kind = ?kind, error = %err);
    } else {
        warn!(event = "client.session.task.error", kind = ?kind, error = %err);
    }
}

async fn join_socks_tasks(connections: &mut JoinSet<()>) {
    while let Some(joined) = connections.join_next().await {
        log_socks_task_result(Some(joined));
    }
}

fn log_socks_task_result(result: Option<Result<(), tokio::task::JoinError>>) {
    if let Some(Err(err)) = result {
        warn!(event = "socks5.connection.task_error", error = %err);
    }
}

fn is_clean_socks_disconnect(error: &AnyError) -> bool {
    error
        .as_ref()
        .downcast_ref::<io::Error>()
        .is_some_and(|error| {
            matches!(
                error.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::NotConnected
            )
        })
}

impl SocksConnectionRuntime {
    async fn spawn_accepted(
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
    fn new(config: ClientConfig, metrics: Arc<ClientMetrics>) -> Self {
        let config = ClientConfigState::new(config);
        metrics.set_config_generation(config.generation());
        Self {
            config,
            metrics,
            pool: Mutex::new(Vec::new()),
            connect_lock: Mutex::new(()),
            config_publish_lock: Mutex::new(()),
            recent_connect_failure: Mutex::new(None),
            reapers: Mutex::new(JoinSet::new()),
            closed: AtomicBool::new(false),
        }
    }

    async fn reload(&self, candidate: ClientConfig) -> Result<u64, AnyError> {
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

    async fn open_flow(
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

    async fn open_udp_flow(
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
    async fn current_session(&self) -> Result<Arc<ClientSession>, AnyError> {
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
    async fn admission_for_new_flow(
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
    async fn connect_and_pool(&self) -> Result<Option<Arc<ClientSession>>, AnyError> {
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
            pending.close_and_wait().await;
            return Ok(None);
        }
        self.clear_connect_failure().await;
        if self.is_closed() {
            drop(publish_guard);
            pending.close_and_wait().await;
            return Err("client session manager is shutting down".into());
        }
        let mut pool = self.pool.lock().await;
        if self.is_closed() {
            drop(pool);
            drop(publish_guard);
            pending.close_and_wait().await;
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
    fn max_pool_size(&self) -> usize {
        usize::try_from(self.config.snapshot().config.max_carrier_sessions())
            .unwrap_or(usize::MAX)
            .max(1)
    }

    /// Returns the live (non-closed) pooled sessions, pruning and reaping any
    /// closed ones from the pool.
    async fn live_sessions(&self) -> Vec<Arc<ClientSession>> {
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
    async fn spawn_reaper(&self, session: Arc<ClientSession>) {
        let mut reapers = self.reapers.lock().await;
        while let Some(result) = reapers.try_join_next() {
            if let Err(err) = result {
                debug!(event = "client.session.reaper.join_error", error = %err);
            }
        }
        reapers.spawn(async move { session.close_and_wait().await });
    }

    /// Returns the first live pooled session, if any.
    async fn first_live_session(&self) -> Option<Arc<ClientSession>> {
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
    async fn admit_flow(
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

    async fn recent_connect_failure_if_active(&self) -> Option<CachedConnectFailure> {
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

    async fn remember_connect_failure(
        &self,
        snapshot: &ClientConfigSnapshot,
        error: &AnyError,
    ) -> bool {
        let _publish_guard = self.config_publish_lock.lock().await;
        if self.config.generation() != snapshot.generation {
            return false;
        }
        let Some(delay) = retry_delay(snapshot.config.server_connect_retry_delay_millis()) else {
            return true;
        };
        let mut recent = self.recent_connect_failure.lock().await;
        *recent = Some(CachedConnectFailure {
            generation: snapshot.generation,
            message: Arc::from(error.to_string()),
            expires_at: retry_delay_expires_at(delay),
        });
        true
    }

    async fn clear_connect_failure(&self) {
        *self.recent_connect_failure.lock().await = None;
    }

    async fn invalidate(&self, session: &Arc<ClientSession>) {
        let removed = {
            let mut pool = self.pool.lock().await;
            let before = pool.len();
            pool.retain(|pooled| !Arc::ptr_eq(pooled, session));
            pool.len() != before
        };
        if removed {
            session.close_and_wait().await;
        } else {
            session.close().await;
        }
    }

    async fn shutdown(&self) {
        self.closed.store(true, Ordering::SeqCst);
        let sessions: Vec<Arc<ClientSession>> = { self.pool.lock().await.drain(..).collect() };
        for session in sessions {
            session.close_and_wait().await;
        }
        let mut reapers = self.reapers.lock().await;
        while reapers.join_next().await.is_some() {}
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    async fn supports_udp_relay(&self) -> Result<bool, AnyError> {
        Ok(self.current_session().await?.supports_udp_relay())
    }

    fn udp_flow_idle_timeout(&self) -> Option<Duration> {
        timeout(
            self.config
                .snapshot()
                .config
                .udp_flow_idle_timeout_seconds(),
        )
    }
}

fn ensure_reload_compatible(
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
    async fn connect(
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
            data_frame_size: tcp_data_frame_size(limits),
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

    fn is_closed(&self) -> bool {
        self.shutdown.is_closed()
    }

    fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire)
    }

    async fn begin_drain(&self) {
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

    async fn remove_flow(&self, flow_id: u64) {
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

    async fn close_if_drained(&self) {
        if self.is_draining() && self.flows.lock().await.is_empty() {
            info!(
                event = "client.session.drain_complete",
                correlation_id = self.correlation_id,
                config_generation = self.config_generation
            );
            self.close().await;
        }
    }

    async fn has_open_flows(&self) -> bool {
        !self.flows.lock().await.is_empty()
    }

    /// Current number of open flows on this session (its pool load).
    async fn flow_count(&self) -> usize {
        self.flows.lock().await.len()
    }

    /// Atomically admits one new flow on this session, or reports why it could
    /// not: unavailable (draining or closed), or at one of its ceilings.
    fn try_admit(
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

    async fn close(&self) {
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
    async fn shutdown_carrier(&self) {
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

    async fn close_and_wait(&self) {
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
    async fn open_flow(
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
    async fn open_udp_flow(
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

    async fn wait_for_open_frame(
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

    async fn wait_for_udp_open_frame(
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

    async fn wait_for_udp_open_frame_inner(
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

    async fn wait_for_open_frame_inner(
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

    async fn cancel_pending_open(&self, flow_id: u64) {
        let _ = self.send_tcp_close(flow_id, TCP_CLOSE_ERROR).await;
        self.remove_flow(flow_id).await;
    }

    async fn cancel_pending_udp_open(&self, flow_id: u64) {
        let _ = self.send_udp_close(flow_id, UDP_CLOSE_ERROR).await;
        self.remove_flow(flow_id).await;
    }

    async fn reserve_flow(
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

    async fn send_tcp_open(&self, flow_id: u64, target: Target) -> Result<(), AnyError> {
        let open = TcpOpen::new(target, TCP_OPEN_FLAGS_NONE);
        let mut payload = BytesMut::new();
        open.encode(&mut payload)?;
        let frame = Frame::new(FrameType::TcpOpen, 0, flow_id, payload.freeze())?;
        self.write_frame(&frame).await
    }

    async fn send_udp_open(&self, flow_id: u64, target: Target) -> Result<(), AnyError> {
        let open = UdpOpen::new(target);
        let mut payload = BytesMut::new();
        open.encode(&mut payload)?;
        let frame = Frame::new(FrameType::UdpOpen, 0, flow_id, payload.freeze())?;
        self.write_frame(&frame).await
    }

    async fn send_tcp_data(&self, flow_id: u64, payload: Bytes) -> Result<(), AnyError> {
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
    fn supports_udp_relay(&self) -> bool {
        self.supports_udp_stream_fallback || self.supports_udp_datagram
    }

    /// Largest UDP payload this session can carry to `flow_id`.
    ///
    /// With no stream fallback the datagram channel is the only data path, so
    /// its limit is the real one; otherwise a `UDP_DATA` frame can carry the
    /// rest.
    fn max_udp_payload_len_for(&self, flow_id: u64) -> usize {
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

    async fn send_udp_data(&self, flow_id: u64, payload: Bytes) -> Result<(), AnyError> {
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
    fn try_send_udp_datagram(&self, flow_id: u64, payload: &[u8]) -> bool {
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

    async fn send_tcp_close(&self, flow_id: u64, close_code: u16) -> Result<(), AnyError> {
        let mut payload = BytesMut::new();
        TcpClose::new(close_code).encode(&mut payload)?;
        let frame = Frame::new(FrameType::TcpClose, 0, flow_id, payload.freeze())?;
        self.write_frame(&frame).await
    }

    async fn send_udp_close(&self, flow_id: u64, close_code: u16) -> Result<(), AnyError> {
        let mut payload = BytesMut::new();
        UdpClose::new(close_code).encode(&mut payload)?;
        let frame = Frame::new(FrameType::UdpClose, 0, flow_id, payload.freeze())?;
        self.write_frame(&frame).await
    }

    async fn send_resource_limit(&self, flow_id: u64) -> Result<(), AnyError> {
        self.send_status_frame(FrameType::ResourceLimit, flow_id, ErrorCode::ResourceLimit)
            .await
    }

    async fn send_connection_error(&self, code: ErrorCode) -> Result<(), AnyError> {
        self.send_status_frame(FrameType::Error, 0, code).await
    }

    async fn send_status_frame(
        &self,
        frame_type: FrameType,
        flow_id: u64,
        code: ErrorCode,
    ) -> Result<(), AnyError> {
        let frame = status_frame(frame_type, flow_id, code)?;
        self.write_frame(&frame).await
    }

    async fn write_pong(&self, request_frame: &Frame) -> Result<(), AnyError> {
        let pong_frame = Frame::new(
            FrameType::Pong,
            0,
            request_frame.header.id,
            request_frame.payload.clone(),
        )?;
        self.write_frame(&pong_frame).await
    }

    async fn write_ping(&self) -> Result<u64, AnyError> {
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

    fn observed_pong_nonce(&self) -> u64 {
        self.last_pong_nonce.load(Ordering::SeqCst)
    }

    fn record_pong(&self, payload: &Bytes) {
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

    fn clear_outstanding_ping(&self, nonce: u64) {
        let _ = self.outstanding_ping_nonce.compare_exchange(
            nonce,
            0,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
    }

    async fn wait_for_pong(&self, nonce: u64) -> bool {
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

    async fn write_frame(&self, frame: &Frame) -> Result<(), AnyError> {
        let result = write_frame_locked(&self.writer, frame, &self.shutdown).await;
        if result.is_err() {
            self.close().await;
        }
        result
    }
}

fn reserve_flow_slot(
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

fn udp_route_count(flows: &HashMap<u64, ClientFlowRoute>) -> usize {
    flows
        .values()
        .filter(|route| route.protocol == FlowProtocol::Udp)
        .count()
}

#[derive(Default)]
struct PendingOpenLocalData {
    chunks: Vec<Bytes>,
    queued_bytes: usize,
    scratch: Vec<u8>,
}

impl PendingOpenLocalData {
    fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }

    fn take_chunks(&mut self) -> Vec<Bytes> {
        self.queued_bytes = 0;
        std::mem::take(&mut self.chunks)
    }

    async fn read_from(
        &mut self,
        local: &mut TcpStream,
        data_frame_size: usize,
        byte_limit: usize,
    ) -> PendingOpenLocalRead {
        let remaining = byte_limit.saturating_sub(self.queued_bytes);
        if remaining == 0 {
            return peek_when_pending_buffer_full(local).await;
        }

        let read_len = data_frame_size.max(1).min(remaining);
        if self.scratch.len() < read_len {
            self.scratch.resize(read_len, 0);
        }

        match local.read(&mut self.scratch[..read_len]).await {
            Ok(0) | Err(_) => PendingOpenLocalRead::Closed,
            Ok(read) => {
                self.queued_bytes += read;
                self.chunks
                    .push(Bytes::copy_from_slice(&self.scratch[..read]));
                PendingOpenLocalRead::Buffered
            }
        }
    }
}

async fn peek_when_pending_buffer_full(local: &TcpStream) -> PendingOpenLocalRead {
    let mut byte = [0_u8; 1];
    match local.peek(&mut byte).await {
        Ok(0) | Err(_) => PendingOpenLocalRead::Closed,
        Ok(_) => PendingOpenLocalRead::ResourceLimit,
    }
}

fn allocate_client_flow_id(next_flow_id: &AtomicU64) -> Option<u64> {
    let mut current = next_flow_id.load(Ordering::Relaxed);
    loop {
        if current > MAX_VARINT {
            return None;
        }
        let next = current.saturating_add(FLOW_ID_STEP);
        match next_flow_id.compare_exchange_weak(
            current,
            next,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return Some(current),
            Err(actual) => current = actual,
        }
    }
}

fn next_keepalive_nonce(counter: &AtomicU64) -> Option<u64> {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let next = current.checked_add(1)?;
        match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return Some(next),
            Err(actual) => current = actual,
        }
    }
}

fn keepalive_nonce_payload(nonce: u64) -> Bytes {
    Bytes::copy_from_slice(&nonce.to_be_bytes())
}

fn decode_keepalive_nonce(payload: &Bytes) -> Option<u64> {
    let bytes: [u8; 8] = payload.as_ref().try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

fn record_matching_pong(
    outstanding_ping_nonce: &AtomicU64,
    last_pong_nonce: &AtomicU64,
    payload: &Bytes,
) -> KeepalivePong {
    let Some(nonce) = decode_keepalive_nonce(payload) else {
        return KeepalivePong::InvalidPayload;
    };
    let expected_nonce = outstanding_ping_nonce.load(Ordering::SeqCst);
    if expected_nonce == 0 || nonce != expected_nonce {
        return KeepalivePong::Unexpected {
            nonce,
            expected_nonce,
        };
    }
    last_pong_nonce.store(nonce, Ordering::SeqCst);
    KeepalivePong::Matched(nonce)
}

async fn spawn_carrier_reader(mut carrier_reader: BoxedCarrierReader, session: Arc<ClientSession>) {
    let correlation_id = session.correlation_id;
    let task_session = Arc::clone(&session);
    let task = async move {
        loop {
            let frame = tokio::select! {
                frame = read_frame(&mut carrier_reader, task_session.limits) => frame,
                () = task_session.shutdown.closed() => return,
            };
            match frame {
                Ok(frame) => {
                    if let Err(err) = handle_carrier_frame(&task_session, frame).await {
                        warn!(event = "client.session.frame.error", error = %err);
                        close_session(&task_session).await;
                        return;
                    }
                }
                Err(err) => {
                    if !matches!(err, FrameIoError::Closed) {
                        warn!(event = "client.session.read.error", error = %err);
                        report_frame_io_error(&task_session, &err).await;
                    }
                    close_session(&task_session).await;
                    return;
                }
            }
        }
    };
    session.tasks.lock().await.spawn(
        ClientSessionTaskKind::CarrierReader,
        task.instrument(info_span!("client.session", correlation_id)),
    );
}

/// Receives inbound QUIC datagrams and delivers each to its flow, alongside
/// `UDP_DATA` frames. Does nothing when the session has no datagram channel.
async fn spawn_datagram_reader(session: Arc<ClientSession>) {
    let Some(channel) = session.datagrams.clone() else {
        return;
    };
    let correlation_id = session.correlation_id;
    let task_session = Arc::clone(&session);
    let task = async move {
        loop {
            let datagram = tokio::select! {
                result = channel.recv() => match result {
                    Ok(datagram) => datagram,
                    Err(_) => return,
                },
                () = task_session.shutdown.closed() => return,
            };
            match datagram::decode(datagram) {
                Ok((flow_id, payload)) => {
                    deliver_inbound_udp_datagram(&task_session, flow_id, payload).await;
                }
                Err(err) => {
                    debug!(event = "client.datagram.decode_error", error = %err);
                }
            }
        }
    };
    session.tasks.lock().await.spawn(
        ClientSessionTaskKind::DatagramReader,
        task.instrument(info_span!("client.session", correlation_id)),
    );
}

/// Delivers one inbound UDP datagram to its flow queue.
///
/// Datagrams are unreliable and unordered: a datagram for an unknown, closed,
/// mismatched, or full flow is dropped silently. Unlike the reliable frame
/// path, it never removes the flow or sends a protocol error.
async fn deliver_inbound_udp_datagram(session: &ClientSession, flow_id: u64, payload: Bytes) {
    let mut flows = session.flows.lock().await;
    if !route_inbound_datagram(
        flow_id,
        payload,
        &mut flows,
        session.session_buffer.clone(),
        session.max_buffered_bytes_per_flow,
        session.max_buffered_bytes_per_session,
    ) {
        debug!(event = "client.datagram.dropped", flow_id);
    }
}

/// Routes an inbound UDP datagram to its flow queue without ever mutating the
/// flow table. Returns `true` when the payload was enqueued.
fn route_inbound_datagram(
    flow_id: u64,
    payload: Bytes,
    flows: &mut HashMap<u64, ClientFlowRoute>,
    session_buffer: ClientSessionBufferControl,
    flow_byte_limit: usize,
    session_byte_limit: usize,
) -> bool {
    if !is_client_initiated_flow_id(flow_id) {
        return false;
    }
    let Some(route) = flows.get(&flow_id) else {
        return false;
    };
    if !matches!(route.protocol, FlowProtocol::Udp) {
        return false;
    }
    let Ok(frame) = Frame::new(FrameType::UdpData, 0, flow_id, payload) else {
        return false;
    };
    let Ok(buffered_frame) = BufferedFlowFrame::new(
        frame,
        route.flow_buffer.clone(),
        session_buffer,
        flow_byte_limit,
        session_byte_limit,
    ) else {
        return false;
    };
    route.sender.try_send(buffered_frame).is_ok()
}

async fn spawn_keepalive(session: Arc<ClientSession>, interval: Duration) {
    let correlation_id = session.correlation_id;
    let task_session = Arc::clone(&session);
    let task = async move {
        loop {
            tokio::select! {
                () = time::sleep(interval) => {}
                () = task_session.shutdown.closed() => return,
            }
            if !task_session.has_open_flows().await {
                continue;
            }
            let nonce = match task_session.write_ping().await {
                Ok(nonce) => nonce,
                Err(err) => {
                    debug!(event = "client.session.keepalive.error", error = %err);
                    task_session.close().await;
                    return;
                }
            };
            let pong_result = time::timeout(interval, task_session.wait_for_pong(nonce)).await;
            task_session.clear_outstanding_ping(nonce);
            match pong_result {
                Ok(true) => {}
                Ok(false) => return,
                Err(_) => {
                    if !task_session.is_closed() {
                        warn!(event = "client.session.keepalive.timeout");
                        task_session.close().await;
                    }
                    return;
                }
            }
        }
    };
    session.tasks.lock().await.spawn(
        ClientSessionTaskKind::Keepalive,
        task.instrument(info_span!("client.session", correlation_id)),
    );
}

async fn close_session(session: &ClientSession) {
    session.close().await;
}

async fn handle_carrier_frame(session: &ClientSession, frame: Frame) -> Result<(), AnyError> {
    match frame.header.frame_type {
        FrameType::TcpData
        | FrameType::TcpClose
        | FrameType::UdpData
        | FrameType::UdpClose
        | FrameType::Error
        | FrameType::PolicyDenied
        | FrameType::ResourceLimit => {
            if let Err(err) = validate_server_flow_frame(&frame) {
                report_protocol_error(session).await;
                return Err(err);
            }
            if is_connection_error_frame(&frame) {
                return Err("connection error from server".into());
            }
            let frame_type = frame.header.frame_type;
            let (flow_id, protocol, route) = {
                let mut flows = session.flows.lock().await;
                route_flow_frame(
                    frame,
                    &mut flows,
                    session.session_buffer.clone(),
                    session.max_buffered_bytes_per_flow,
                    session.max_buffered_bytes_per_session,
                )
            };
            let removed_flow = matches!(
                route,
                FlowFrameRoute::ProtocolMismatch
                    | FlowFrameRoute::FlowQueueFull
                    | FlowFrameRoute::SessionQueueFull
                    | FlowFrameRoute::FlowClosed
            );
            match route {
                FlowFrameRoute::InvalidFlowId => {
                    report_protocol_error(session).await;
                    return Err("invalid relay flow id from server".into());
                }
                FlowFrameRoute::ProtocolMismatch => {
                    warn!(
                        event = "client.flow.protocol_mismatch",
                        flow_id,
                        protocol = ?protocol,
                        frame_type = ?frame_type
                    );
                    session
                        .send_status_frame(FrameType::Error, flow_id, ErrorCode::Protocol)
                        .await?;
                    send_flow_error_close(session, flow_id, protocol, frame_type).await?;
                }
                FlowFrameRoute::FlowQueueFull => {
                    warn!(event = "client.flow.queue_full", flow_id);
                    session.send_resource_limit(flow_id).await?;
                    send_flow_error_close(session, flow_id, protocol, frame_type).await?;
                }
                FlowFrameRoute::SessionQueueFull => {
                    warn!(event = "client.session.queue_full", flow_id);
                    session.send_resource_limit(flow_id).await?;
                    send_flow_error_close(session, flow_id, protocol, frame_type).await?;
                }
                FlowFrameRoute::UnknownFlow
                | FlowFrameRoute::Enqueued
                | FlowFrameRoute::FlowClosed => {}
            }
            if removed_flow {
                session.close_if_drained().await;
            }
            Ok(())
        }
        FrameType::Ping => {
            if let Err(err) = validate_session_control_frame(&frame, FrameType::Ping) {
                report_protocol_error(session).await;
                return Err(err);
            }
            session.write_pong(&frame).await
        }
        FrameType::Pong => {
            if let Err(err) = validate_session_control_frame(&frame, FrameType::Pong) {
                report_protocol_error(session).await;
                return Err(err);
            }
            session.record_pong(&frame.payload);
            Ok(())
        }
        _ => {
            report_protocol_error(session).await;
            Err("unexpected frame on client session".into())
        }
    }
}

async fn send_flow_error_close(
    session: &ClientSession,
    flow_id: u64,
    protocol: Option<FlowProtocol>,
    frame_type: FrameType,
) -> Result<(), AnyError> {
    match protocol {
        Some(FlowProtocol::Udp) => session.send_udp_close(flow_id, UDP_CLOSE_ERROR).await,
        Some(FlowProtocol::Tcp) => session.send_tcp_close(flow_id, TCP_CLOSE_ERROR).await,
        None => match frame_type {
            FrameType::UdpData | FrameType::UdpClose => {
                session.send_udp_close(flow_id, UDP_CLOSE_ERROR).await
            }
            _ => session.send_tcp_close(flow_id, TCP_CLOSE_ERROR).await,
        },
    }
}

async fn report_protocol_error(session: &ClientSession) {
    let _ = session.send_connection_error(ErrorCode::Protocol).await;
}

async fn report_frame_io_error(session: &ClientSession, error: &FrameIoError) {
    if let FrameIoError::Protocol(error) = error {
        let _ = session
            .send_connection_error(ErrorCode::from_protocol_error(error))
            .await;
    }
}

fn validate_session_control_frame(frame: &Frame, expected_type: FrameType) -> Result<(), AnyError> {
    validate_connection_frame(frame, expected_type)?;
    Ok(())
}

fn validate_server_flow_frame(frame: &Frame) -> Result<(), AnyError> {
    match frame.header.frame_type {
        FrameType::TcpData | FrameType::UdpData => Ok(()),
        FrameType::TcpClose => {
            let mut payload = frame.payload.clone();
            TcpClose::decode(&mut payload)?;
            Ok(())
        }
        FrameType::UdpClose => {
            let mut payload = frame.payload.clone();
            UdpClose::decode(&mut payload)?;
            Ok(())
        }
        FrameType::Error | FrameType::PolicyDenied | FrameType::ResourceLimit => {
            validate_flow_status(frame.header.frame_type, frame.payload.clone())
        }
        _ => Err("unexpected server flow frame".into()),
    }
}

fn is_connection_error_frame(frame: &Frame) -> bool {
    frame.header.frame_type == FrameType::Error && frame.header.id == 0
}

fn route_flow_frame(
    frame: Frame,
    flows: &mut HashMap<u64, ClientFlowRoute>,
    session_buffer: ClientSessionBufferControl,
    flow_byte_limit: usize,
    session_byte_limit: usize,
) -> (u64, Option<FlowProtocol>, FlowFrameRoute) {
    let flow_id = frame.header.id;
    if !is_client_initiated_flow_id(flow_id) {
        return (flow_id, None, FlowFrameRoute::InvalidFlowId);
    }

    let Some(route) = flows.get(&flow_id) else {
        return (flow_id, None, FlowFrameRoute::UnknownFlow);
    };
    let sender = route.sender.clone();
    let flow_buffer = route.flow_buffer.clone();
    let protocol = route.protocol;
    if !flow_frame_matches_protocol(protocol, frame.header.frame_type) {
        flows.remove(&flow_id);
        return (flow_id, Some(protocol), FlowFrameRoute::ProtocolMismatch);
    }

    let buffered_frame = match BufferedFlowFrame::new(
        frame,
        flow_buffer,
        session_buffer,
        flow_byte_limit,
        session_byte_limit,
    ) {
        Ok(frame) => frame,
        Err(BufferReserveError::FlowLimit) => {
            flows.remove(&flow_id);
            return (flow_id, Some(protocol), FlowFrameRoute::FlowQueueFull);
        }
        Err(BufferReserveError::SessionLimit) => {
            flows.remove(&flow_id);
            return (flow_id, Some(protocol), FlowFrameRoute::SessionQueueFull);
        }
    };

    let route = match sender.try_send(buffered_frame) {
        Ok(()) => FlowFrameRoute::Enqueued,
        Err(mpsc::error::TrySendError::Closed(_)) => FlowFrameRoute::FlowClosed,
        Err(mpsc::error::TrySendError::Full(_)) => FlowFrameRoute::FlowQueueFull,
    };
    if matches!(
        route,
        FlowFrameRoute::FlowClosed | FlowFrameRoute::FlowQueueFull
    ) {
        flows.remove(&flow_id);
    }
    (flow_id, Some(protocol), route)
}

fn flow_frame_matches_protocol(protocol: FlowProtocol, frame_type: FrameType) -> bool {
    match protocol {
        FlowProtocol::Tcp => matches!(
            frame_type,
            FrameType::TcpData
                | FrameType::TcpClose
                | FrameType::Error
                | FrameType::PolicyDenied
                | FrameType::ResourceLimit
        ),
        FlowProtocol::Udp => matches!(
            frame_type,
            FrameType::UdpData
                | FrameType::UdpClose
                | FrameType::Error
                | FrameType::PolicyDenied
                | FrameType::ResourceLimit
        ),
    }
}

async fn handle_socks_connection(
    mut local: TcpStream,
    sessions: Arc<ClientSessionManager>,
    socks_handshake_timeout: Option<Duration>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), AnyError> {
    local.set_nodelay(true)?;
    if *shutdown_rx.borrow() {
        return Ok(());
    }
    let mut state = ClientConnectionState::NegotiatingSocks;
    let request = tokio::select! {
        result = negotiate_socks_request(&mut local, socks_handshake_timeout) => result?,
        changed = shutdown_rx.changed() => {
            let _ = changed;
            transition(&mut state, ClientConnectionState::Closed);
            return Ok(());
        }
    };
    let target = match request {
        socks5::Request::Connect(target) => target,
        socks5::Request::UdpAssociate(endpoint) => {
            debug!(event = "socks5.udp_associate", endpoint = ?endpoint);
            transition(&mut state, ClientConnectionState::Relaying);
            let relay_result = relay_udp_association(local, sessions, endpoint, shutdown_rx).await;
            if relay_result.is_err() {
                transition(&mut state, ClientConnectionState::Closing);
            }
            transition(&mut state, ClientConnectionState::Closed);
            return relay_result;
        }
    };

    transition(&mut state, ClientConnectionState::Opening);
    let open_result = sessions
        .open_flow(target, &mut local, &mut shutdown_rx)
        .await;
    let flow = match open_result {
        Ok(OpenOutcome::Open(flow)) => flow,
        Ok(OpenOutcome::Rejected(reply)) => {
            socks5::send_reply(&mut local, reply).await?;
            transition(&mut state, ClientConnectionState::Closed);
            return Ok(());
        }
        Ok(OpenOutcome::Cancelled) => {
            transition(&mut state, ClientConnectionState::Closed);
            return Ok(());
        }
        Err(err) => {
            let _ = socks5::send_reply(&mut local, socks5::Reply::GeneralFailure).await;
            transition(&mut state, ClientConnectionState::Closing);
            transition(&mut state, ClientConnectionState::Closed);
            return Err(err);
        }
    };
    let flow_id = flow.id;
    let flow_session = Arc::clone(&flow.session);
    if let Err(err) = socks5::send_reply(&mut local, socks5::Reply::Succeeded).await {
        transition(&mut state, ClientConnectionState::Closing);
        let _ = flow_session.send_tcp_close(flow_id, TCP_CLOSE_ERROR).await;
        flow_session.remove_flow(flow_id).await;
        transition(&mut state, ClientConnectionState::Closed);
        return Err(err.into());
    }

    transition(&mut state, ClientConnectionState::Relaying);
    let relay_result = relay_tcp(local, flow, shutdown_rx).await;
    if relay_result.is_err() {
        transition(&mut state, ClientConnectionState::Closing);
        let _ = flow_session.send_tcp_close(flow_id, TCP_CLOSE_ERROR).await;
    }
    flow_session.remove_flow(flow_id).await;
    transition(&mut state, ClientConnectionState::Closed);
    relay_result
}

async fn negotiate_socks_request(
    local: &mut TcpStream,
    socks_handshake_timeout: Option<Duration>,
) -> Result<socks5::Request, AnyError> {
    if let Some(timeout) = socks_handshake_timeout {
        match time::timeout(timeout, socks5::negotiate_request(local)).await {
            Ok(result) => Ok(result?),
            Err(_) => Err("socks handshake timeout".into()),
        }
    } else {
        Ok(socks5::negotiate_request(local).await?)
    }
}

async fn relay_udp_association(
    mut local: TcpStream,
    sessions: Arc<ClientSessionManager>,
    client_endpoint: socks5::SocksEndpoint,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), AnyError> {
    if *shutdown_rx.borrow() {
        return Ok(());
    }

    let supports_udp_relay = tokio::select! {
        result = sessions.supports_udp_relay() => result,
        changed = shutdown_rx.changed() => {
            let _ = changed;
            return Ok(());
        }
    };
    match supports_udp_relay {
        Ok(true) => {}
        Ok(false) => {
            // The server does not offer UDP relay at all, which is exactly what
            // `CommandNotSupported` (0x07) means; 0x01 would invite the client
            // to retry the same unsupported command.
            socks5::send_reply(&mut local, socks5::Reply::CommandNotSupported).await?;
            return Ok(());
        }
        Err(err) => {
            let _ = socks5::send_reply(&mut local, socks5::Reply::GeneralFailure).await;
            return Err(err);
        }
    }

    // The association is only ever usable by the host that opened this control
    // connection, so pin the accepted datagram source to its IP.
    let control_peer_ip = local.peer_addr()?.ip();
    let bind_addr = udp_association_bind_addr(local.local_addr()?);
    let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
    let bound_endpoint = socks5::SocksEndpoint::from(socket.local_addr()?);
    socks5::send_reply_with_endpoint(&mut local, socks5::Reply::Succeeded, &bound_endpoint).await?;

    let (flow_event_tx, mut flow_event_rx) = mpsc::channel(UDP_ASSOCIATION_EVENT_QUEUE_CAPACITY);
    let mut association = UdpAssociation::new(
        socket,
        sessions.udp_flow_idle_timeout(),
        flow_event_tx,
        client_endpoint,
        control_peer_ip,
    );
    let mut idle_interval = udp_idle_interval(association.idle_timeout);
    let mut udp_buf = vec![0_u8; UDP_ASSOCIATION_BUFFER_SIZE].into_boxed_slice();
    let mut tcp_buf = [0_u8; 1];

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                let _ = changed;
                break;
            }
            read = local.read(&mut tcp_buf) => {
                if read? == 0 {
                    break;
                }
                debug!(event = "socks5.udp_associate.control_data_ignored");
            }
            received = association.socket.recv_from(udp_buf.as_mut()) => {
                let (read, peer) = received?;
                if !association
                    .handle_local_udp_datagram(
                        peer,
                        &udp_buf[..read],
                        &mut local,
                        &mut tcp_buf,
                        &sessions,
                        &mut shutdown_rx,
                    )
                    .await?
                {
                    break;
                }
            }
            joined = association.flow_tasks.join_next(), if !association.flow_tasks.is_empty() => {
                association.handle_flow_task_result(joined);
            }
            event = flow_event_rx.recv() => {
                association.handle_flow_event(event);
            }
            () = tick_udp_idle_interval(&mut idle_interval), if idle_interval.is_some() => {
                association.close_idle_flows().await;
            }
        }
    }

    association.close().await;
    Ok(())
}

impl UdpAssociation {
    fn new(
        socket: Arc<UdpSocket>,
        idle_timeout: Option<Duration>,
        flow_event_tx: mpsc::Sender<UdpAssociationFlowEvent>,
        client_endpoint: socks5::SocksEndpoint,
        control_peer_ip: IpAddr,
    ) -> Self {
        Self {
            socket,
            idle_timeout,
            flow_event_tx,
            client_endpoint: UdpClientEndpoint::new(client_endpoint, control_peer_ip),
            flows_by_target: HashMap::new(),
            flow_tasks: JoinSet::new(),
        }
    }

    async fn handle_local_udp_datagram(
        &mut self,
        peer: SocketAddr,
        packet: &[u8],
        local: &mut TcpStream,
        tcp_buf: &mut [u8; 1],
        sessions: &Arc<ClientSessionManager>,
        shutdown_rx: &mut watch::Receiver<bool>,
    ) -> Result<bool, AnyError> {
        if !self.accept_client_endpoint(peer) {
            debug!(event = "socks5.udp_associate.peer_ignored", peer = %peer);
            return Ok(true);
        }

        let datagram = match socks5::decode_udp_datagram(packet) {
            Ok(datagram) => datagram,
            Err(err) => {
                debug!(event = "socks5.udp.datagram.invalid", error = %err);
                return Ok(true);
            }
        };

        // Size the datagram *before* touching a flow: `flow_for_target` opens a
        // UK UDP flow on demand, so checking afterwards would leave an idle
        // flow holding a `max_udp_flows` slot for the whole idle timeout every
        // time a client's first datagram to a target is oversized.
        // Sizing a first datagram may have to wait for a session, so keep the
        // wait cancellable: shutdown must not be held up by a pending dial.
        let max_payload_len = tokio::select! {
            result = self.max_udp_payload_len(&datagram.target, sessions) => result?,
            changed = shutdown_rx.changed() => {
                let _ = changed;
                return Ok(false);
            }
        };
        if udp_payload_exceeds_frame_limit(datagram.payload.len(), max_payload_len) {
            warn_oversized_udp_datagram(&datagram.target, datagram.payload.len(), max_payload_len);
            return Ok(true);
        }

        let mut last_error = None;
        for attempt in 0..UDP_SEND_ATTEMPTS {
            let flow = match self
                .flow_for_target(
                    datagram.target.clone(),
                    local,
                    tcp_buf,
                    sessions,
                    shutdown_rx,
                )
                .await?
            {
                UdpAssociationFlowLookup::Open(flow) => flow,
                UdpAssociationFlowLookup::NoFlow => return Ok(true),
                UdpAssociationFlowLookup::Cancelled => return Ok(false),
            };
            match flow
                .session
                .send_udp_data(flow.id, datagram.payload.clone())
                .await
            {
                Ok(()) => return Ok(true),
                Err(err) => {
                    warn!(
                        event = "client.udp_flow.send.error",
                        flow_id = flow.id,
                        target = %datagram.target.log_safe(),
                        attempt,
                        error = %err
                    );
                    self.remove_flow_if_matches(&datagram.target, flow.id);
                    flow.session.remove_flow(flow.id).await;
                    last_error = Some(err);
                }
            }
        }

        // Drop this datagram rather than failing the association. Returning an
        // error here propagates out of `relay_udp_association` and tears down
        // the SOCKS control connection along with every other target's flow —
        // so one unreachable target would take out an application's entire UDP
        // relay. UDP is best-effort and the failed flow has already been
        // removed, so the next datagram to this target opens a fresh one. This
        // matches the reliable path, where a per-flow failure closes only that
        // flow.
        warn!(
            event = "socks5.udp_associate.datagram_dropped",
            target = %datagram.target.log_safe(),
            attempts = UDP_SEND_ATTEMPTS,
            error = %last_error
                .map_or_else(|| "no send attempt succeeded".to_owned(), |err| err.to_string())
        );
        Ok(true)
    }

    fn accept_client_endpoint(&mut self, peer: SocketAddr) -> bool {
        self.client_endpoint.accepts(peer)
    }

    /// Largest UDP payload this association can relay to `target`: the data
    /// frame size of the target's existing flow, or — for a target with no flow
    /// yet — of a session that could carry one. Queried without opening a flow
    /// so an oversized datagram cannot strand UDP flow capacity.
    async fn max_udp_payload_len(
        &self,
        target: &Target,
        sessions: &ClientSessionManager,
    ) -> Result<usize, AnyError> {
        if let Some(flow) = self.flows_by_target.get(target) {
            return Ok(flow.session.max_udp_payload_len_for(flow.id));
        }
        let session = sessions.current_session().await?;
        // No flow yet, so no flow id: size against the first id this session
        // would allocate, which bounds the varint overhead.
        Ok(session.max_udp_payload_len_for(FIRST_CLIENT_FLOW_ID))
    }

    async fn flow_for_target(
        &mut self,
        target: Target,
        local: &mut TcpStream,
        tcp_buf: &mut [u8; 1],
        sessions: &Arc<ClientSessionManager>,
        shutdown_rx: &mut watch::Receiver<bool>,
    ) -> Result<UdpAssociationFlowLookup, AnyError> {
        if let Some(flow) = self.flows_by_target.get_mut(&target) {
            flow.record_activity();
            return Ok(UdpAssociationFlowLookup::Open(flow.clone()));
        }

        let flow = match sessions
            .open_udp_flow(target.clone(), local, tcp_buf, shutdown_rx)
            .await?
        {
            OpenOutcome::Open(flow) => flow,
            OpenOutcome::Rejected(reply) => {
                debug!(
                    event = "client.udp_flow.open.rejected",
                    target = %target.log_safe(),
                    reply = ?reply
                );
                return Ok(UdpAssociationFlowLookup::NoFlow);
            }
            OpenOutcome::Cancelled => return Ok(UdpAssociationFlowLookup::Cancelled),
        };
        let association_flow = UdpAssociationFlow {
            id: flow.id,
            session: Arc::clone(&flow.session),
            last_activity: time::Instant::now(),
        };
        self.flows_by_target
            .insert(target.clone(), association_flow.clone());
        self.spawn_flow_task(flow, target, shutdown_rx.clone());
        Ok(UdpAssociationFlowLookup::Open(association_flow))
    }

    fn spawn_flow_task(
        &mut self,
        flow: ClientFlow,
        target: Target,
        shutdown_rx: watch::Receiver<bool>,
    ) {
        let socket = Arc::clone(&self.socket);
        let flow_event_tx = self.flow_event_tx.clone();
        let Some(client_endpoint) = self.client_endpoint.learned() else {
            warn!(
                event = "client.udp_flow.missing_client_endpoint",
                flow_id = flow.id,
                target = %target.log_safe()
            );
            self.spawn_udp_flow_cleanup(flow, target);
            return;
        };
        self.flow_tasks.spawn(async move {
            relay_udp_flow_to_client(
                flow,
                target,
                socket,
                client_endpoint,
                shutdown_rx,
                flow_event_tx,
            )
            .await
        });
    }

    fn spawn_udp_flow_cleanup(&mut self, flow: ClientFlow, target: Target) {
        self.flow_tasks.spawn(async move {
            let flow_id = flow.id;
            let session = Arc::clone(&flow.session);
            let outcome = async {
                session.send_udp_close(flow_id, UDP_CLOSE_ERROR).await?;
                session.remove_flow(flow_id).await;
                Ok(())
            }
            .await;
            UdpFlowTaskResult {
                flow_id,
                target,
                outcome,
            }
        });
    }

    fn handle_flow_task_result(
        &mut self,
        joined: Option<Result<UdpFlowTaskResult, tokio::task::JoinError>>,
    ) {
        let Some(joined) = joined else {
            return;
        };
        match joined {
            Ok(result) => {
                self.remove_flow_if_matches(&result.target, result.flow_id);
                if let Err(err) = result.outcome {
                    warn!(
                        event = "client.udp_flow.task_error",
                        flow_id = result.flow_id,
                        target = %result.target.log_safe(),
                        error = %err
                    );
                }
            }
            Err(err) => {
                warn!(event = "client.udp_flow.join_error", error = %err);
            }
        }
    }

    fn remove_flow_if_matches(&mut self, target: &Target, flow_id: u64) -> bool {
        let current_flow_id = self.flows_by_target.get(target).map(|flow| flow.id);
        if udp_flow_id_matches(current_flow_id, flow_id) {
            self.flows_by_target.remove(target);
            true
        } else {
            false
        }
    }

    fn handle_flow_event(&mut self, event: Option<UdpAssociationFlowEvent>) {
        let Some(UdpAssociationFlowEvent::Activity { flow_id, target }) = event else {
            return;
        };
        let Some(flow) = self.flows_by_target.get_mut(&target) else {
            return;
        };
        if flow.id == flow_id {
            flow.record_activity();
        }
    }

    async fn close(&mut self) {
        for flow in self.flows_by_target.values().cloned().collect::<Vec<_>>() {
            let _ = flow.session.send_udp_close(flow.id, UDP_CLOSE_NORMAL).await;
            flow.session.remove_flow(flow.id).await;
        }
        self.flows_by_target.clear();
        self.flow_tasks.abort_all();
        while self.flow_tasks.join_next().await.is_some() {}
    }

    async fn close_idle_flows(&mut self) {
        let Some(idle_timeout) = self.idle_timeout else {
            return;
        };
        let now = time::Instant::now();
        let expired = self
            .flows_by_target
            .iter()
            .filter(|(_, flow)| now.duration_since(flow.last_activity) >= idle_timeout)
            .map(|(target, flow)| (target.clone(), flow.clone()))
            .collect::<Vec<_>>();

        for (target, flow) in expired {
            if self.flows_by_target.remove(&target).is_some() {
                debug!(
                    event = "client.udp_flow.idle_timeout",
                    flow_id = flow.id,
                    target = %target.log_safe()
                );
                let _ = flow.session.send_udp_close(flow.id, UDP_CLOSE_NORMAL).await;
                flow.session.remove_flow(flow.id).await;
            }
        }
    }
}

fn udp_flow_id_matches(current_flow_id: Option<u64>, candidate_flow_id: u64) -> bool {
    current_flow_id == Some(candidate_flow_id)
}

impl UdpClientEndpoint {
    fn new(requested: socks5::SocksEndpoint, control_peer_ip: IpAddr) -> Self {
        Self {
            requested,
            control_peer_ip,
            learned: None,
        }
    }

    fn accepts(&mut self, peer: SocketAddr) -> bool {
        if !self.matches_requested(peer) {
            return false;
        }

        if let Some(learned) = self.learned {
            learned == peer
        } else {
            self.learned = Some(peer);
            true
        }
    }

    fn learned(&self) -> Option<SocketAddr> {
        self.learned
    }

    /// Decides whether `peer` may be the client of this association.
    ///
    /// An explicitly advertised address is honoured as-is. An unspecified
    /// address — and the domain form, which names the client rather than a
    /// source the datagrams can be checked against — falls back to the control
    /// connection's peer IP so only the host that authenticated the association
    /// can use it. The port stays learnable either way, since a client that
    /// advertised `0` genuinely does not know it yet.
    fn matches_requested(&self, peer: SocketAddr) -> bool {
        match &self.requested {
            socks5::SocksEndpoint::Ipv4(addr, port) => {
                self.matches_source_ip(peer, Some(IpAddr::V4(*addr)))
                    && matches_requested_port(peer, *port)
            }
            socks5::SocksEndpoint::Ipv6(addr, port) => {
                self.matches_source_ip(peer, Some(IpAddr::V6(*addr)))
                    && matches_requested_port(peer, *port)
            }
            socks5::SocksEndpoint::Domain(_, port) => {
                self.matches_source_ip(peer, None) && matches_requested_port(peer, *port)
            }
        }
    }

    fn matches_source_ip(&self, peer: SocketAddr, requested_ip: Option<IpAddr>) -> bool {
        match requested_ip {
            Some(requested_ip) if !requested_ip.is_unspecified() => {
                ip_matches(peer.ip(), requested_ip)
            }
            _ => ip_matches(peer.ip(), self.control_peer_ip),
        }
    }
}

fn matches_requested_port(peer: SocketAddr, requested_port: u16) -> bool {
    requested_port == 0 || peer.port() == requested_port
}

/// Compares two IPs, treating an IPv4-mapped IPv6 address as its IPv4 form so a
/// dual-stack SOCKS listener (whose control peer reads as `::ffff:a.b.c.d`)
/// still matches the plain IPv4 source of the same client's datagrams.
fn ip_matches(left: IpAddr, right: IpAddr) -> bool {
    canonical_ip(left) == canonical_ip(right)
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(addr) => addr.to_ipv4_mapped().map_or(IpAddr::V6(addr), IpAddr::V4),
        IpAddr::V4(addr) => IpAddr::V4(addr),
    }
}

fn udp_payload_exceeds_frame_limit(payload_len: usize, max_payload_len: usize) -> bool {
    payload_len > max_payload_len
}

fn warn_oversized_udp_datagram(target: &Target, payload_len: usize, max_payload_len: usize) {
    warn!(
        event = "client.udp.datagram.too_large",
        target = %target.log_safe(),
        payload_len,
        max_payload_len
    );
}

impl UdpAssociationFlow {
    fn record_activity(&mut self) {
        self.last_activity = time::Instant::now();
    }
}

async fn relay_udp_flow_to_client(
    flow: ClientFlow,
    target: Target,
    socket: Arc<UdpSocket>,
    client_endpoint: SocketAddr,
    shutdown_rx: watch::Receiver<bool>,
    flow_event_tx: mpsc::Sender<UdpAssociationFlowEvent>,
) -> UdpFlowTaskResult {
    let flow_id = flow.id;
    let session = Arc::clone(&flow.session);
    let outcome = relay_udp_flow_to_client_inner(
        flow,
        target.clone(),
        socket,
        client_endpoint,
        shutdown_rx,
        flow_event_tx,
    )
    .await;
    session.remove_flow(flow_id).await;
    UdpFlowTaskResult {
        flow_id,
        target,
        outcome,
    }
}

async fn relay_udp_flow_to_client_inner(
    mut flow: ClientFlow,
    target: Target,
    socket: Arc<UdpSocket>,
    client_endpoint: SocketAddr,
    mut shutdown_rx: watch::Receiver<bool>,
    flow_event_tx: mpsc::Sender<UdpAssociationFlowEvent>,
) -> Result<(), AnyError> {
    let flow_id = flow.id;
    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                let _ = changed;
                return Ok(());
            }
            frame = flow.frames.recv() => {
                let Some(frame) = frame else {
                    return Ok(());
                };
                let frame = frame.into_frame()?;
                match frame.header.frame_type {
                    FrameType::UdpData => {
                        let payload_len = frame.payload.len();
                        let packet = socks5::encode_udp_datagram(&target, &frame.payload)?;
                        socket.send_to(&packet, client_endpoint).await?;
                        flow.session.metrics.record_relay_bytes(
                            RelayProtocol::Udp,
                            RelayDirection::ServerToLocal,
                            payload_len,
                        );
                        try_record_udp_association_activity(&flow_event_tx, flow_id, &target);
                    }
                    FrameType::UdpClose => {
                        let mut payload = frame.payload;
                        UdpClose::decode(&mut payload)?;
                        return Ok(());
                    }
                    FrameType::Error | FrameType::PolicyDenied | FrameType::ResourceLimit => {
                        validate_flow_status(frame.header.frame_type, frame.payload)?;
                        return Ok(());
                    }
                    _ => return Err("unexpected frame while relaying udp flow".into()),
                }
            }
        }
    }
}

fn udp_association_bind_addr(tcp_local_addr: SocketAddr) -> SocketAddr {
    match tcp_local_addr.ip() {
        IpAddr::V4(ip) => SocketAddr::new(IpAddr::V4(ip), 0),
        IpAddr::V6(ip) => SocketAddr::new(IpAddr::V6(ip), 0),
    }
}

fn try_record_udp_association_activity(
    flow_event_tx: &mpsc::Sender<UdpAssociationFlowEvent>,
    flow_id: u64,
    target: &Target,
) {
    let _ = flow_event_tx.try_send(UdpAssociationFlowEvent::Activity {
        flow_id,
        target: target.clone(),
    });
}

fn udp_idle_interval(idle_timeout: Option<Duration>) -> Option<time::Interval> {
    let idle_timeout = idle_timeout?;
    Some(time::interval(idle_timeout.min(Duration::from_secs(1))))
}

async fn tick_udp_idle_interval(interval: &mut Option<time::Interval>) {
    if let Some(interval) = interval {
        interval.tick().await;
    } else {
        std::future::pending::<()>().await;
    }
}

async fn relay_tcp(
    mut local: TcpStream,
    mut flow: ClientFlow,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), AnyError> {
    let mut local_to_remote_open = true;
    let mut remote_to_local_open = true;
    let data_frame_size = flow.session.data_frame_size;
    let mut local_buf = vec![0_u8; data_frame_size].into_boxed_slice();

    flush_pending_local_data(&mut flow).await?;

    while local_to_remote_open || remote_to_local_open {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                let _ = changed;
                // Hand over what the server already delivered before the FIN:
                // dropping it would turn up to `max_buffered_bytes_per_flow` of
                // received data into a clean EOF for the local application.
                flush_buffered_frames_before_shutdown(
                    &mut local,
                    &mut flow.frames,
                    &flow.session.metrics,
                )
                .await?;
                local.shutdown().await?;
                local_to_remote_open = false;
                remote_to_local_open = false;
            }
            read = local.read(local_buf.as_mut()), if local_to_remote_open => {
                let read = read?;
                if read == 0 {
                    flow.session.send_tcp_close(flow.id, TCP_CLOSE_NORMAL).await?;
                    local_to_remote_open = false;
                } else {
                    flow.session
                        .send_tcp_data(
                        flow.id,
                        Bytes::copy_from_slice(&local_buf[..read]),
                    )
                    .await?;
                }
            }
            frame = flow.frames.recv(), if local_to_remote_open || remote_to_local_open => {
                let Some(frame) = frame else {
                    local.shutdown().await?;
                    local_to_remote_open = false;
                    remote_to_local_open = false;
                    continue;
                };
                let frame = frame.into_frame()?;
                match frame.header.frame_type {
                    FrameType::TcpData => {
                        if !remote_to_local_open {
                            return Err("tcp data received after remote close".into());
                        }
                        let payload_len = frame.payload.len();
                        let local_write_open = frame.payload.is_empty()
                            || write_all_or_shutdown(&mut local, &frame.payload, &mut shutdown_rx)
                                .await?;
                        if local_write_open {
                            flow.session.metrics.record_relay_bytes(
                                RelayProtocol::Tcp,
                                RelayDirection::ServerToLocal,
                                payload_len,
                            );
                        }
                        if !local_write_open {
                            local_to_remote_open = false;
                            remote_to_local_open = false;
                        }
                    }
                    FrameType::TcpClose => {
                        let mut payload = frame.payload;
                        let close = TcpClose::decode(&mut payload)?;
                        let was_remote_to_local_open = remote_to_local_open;
                        local.shutdown().await?;
                        remote_to_local_open = false;
                        if close.close_code != TCP_CLOSE_NORMAL || !was_remote_to_local_open {
                            local_to_remote_open = false;
                        }
                    }
                    FrameType::Error | FrameType::PolicyDenied | FrameType::ResourceLimit => {
                        validate_flow_status(frame.header.frame_type, frame.payload)?;
                        local.shutdown().await?;
                        local_to_remote_open = false;
                        remote_to_local_open = false;
                    }
                    _ => return Err("unexpected frame while relaying tcp flow".into()),
                }
            }
        }
    }

    Ok(())
}

/// How long a payload already being written to the local socket may keep
/// draining after shutdown is signalled, before the flow is failed instead.
const LOCAL_WRITE_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Writes one relayed payload to the local socket, honouring shutdown.
///
/// `write_all` is not cancellation safe, so racing it against the shutdown
/// signal and dropping the loser would leave an unknown-length prefix on the
/// socket — and the clean FIN below would then tell the local peer that the
/// truncated stream had ended normally. Instead the write future is pinned and
/// resumed, so a shutdown arriving mid-write never discards progress.
///
/// A local peer that has stopped reading cannot be waited on forever, so the
/// post-shutdown completion is bounded. Exceeding the grace period is an error
/// rather than a short write, so the caller tears the flow down instead of
/// finishing it with a clean FIN.
async fn write_all_or_shutdown<W>(
    writer: &mut W,
    payload: &[u8],
    shutdown_rx: &mut watch::Receiver<bool>,
) -> Result<bool, AnyError>
where
    W: AsyncWrite + Unpin,
{
    write_all_or_shutdown_within(writer, payload, shutdown_rx, LOCAL_WRITE_SHUTDOWN_GRACE).await
}

async fn write_all_or_shutdown_within<W>(
    writer: &mut W,
    payload: &[u8],
    shutdown_rx: &mut watch::Receiver<bool>,
    grace: Duration,
) -> Result<bool, AnyError>
where
    W: AsyncWrite + Unpin,
{
    let shutting_down = {
        let mut write = std::pin::pin!(writer.write_all(payload));
        tokio::select! {
            result = &mut write => {
                result?;
                *shutdown_rx.borrow()
            }
            changed = shutdown_rx.changed() => {
                let _ = changed;
                time::timeout(grace, &mut write)
                    .await
                    .map_err(|_| -> AnyError {
                        "timed out flushing local socket during shutdown".into()
                    })??;
                true
            }
        }
    };
    if shutting_down {
        writer.shutdown().await?;
        return Ok(false);
    }
    Ok(true)
}

/// Drains the frames a flow has *already* received into the local socket, so a
/// graceful shutdown never puts a clean FIN behind data it silently dropped.
///
/// Only what is queued right now is drained (`try_recv` never waits on the
/// server), so this is bounded by the per-flow byte budget and cannot delay
/// shutdown on a stalled carrier. Draining stops at the first non-data frame:
/// closes and status frames end the flow anyway, and the caller is about to
/// shut the socket down.
async fn flush_buffered_frames_before_shutdown<W>(
    writer: &mut W,
    frames: &mut mpsc::Receiver<BufferedFlowFrame>,
    metrics: &ClientMetrics,
) -> Result<(), AnyError>
where
    W: AsyncWrite + Unpin,
{
    while let Ok(buffered) = frames.try_recv() {
        let frame = buffered.into_frame()?;
        if frame.header.frame_type != FrameType::TcpData {
            break;
        }
        let payload_len = frame.payload.len();
        writer.write_all(&frame.payload).await?;
        metrics.record_relay_bytes(
            RelayProtocol::Tcp,
            RelayDirection::ServerToLocal,
            payload_len,
        );
    }
    Ok(())
}

async fn flush_pending_local_data(flow: &mut ClientFlow) -> Result<(), AnyError> {
    let data_frame_size = flow.session.data_frame_size.max(1);
    for payload in flow.pending_local_data.drain(..) {
        if payload.len() <= data_frame_size {
            flow.session.send_tcp_data(flow.id, payload).await?;
            continue;
        }

        for chunk in payload.chunks(data_frame_size) {
            flow.session
                .send_tcp_data(flow.id, Bytes::copy_from_slice(chunk))
                .await?;
        }
    }
    Ok(())
}

fn validate_flow_status(frame_type: FrameType, payload: Bytes) -> Result<(), AnyError> {
    match frame_type {
        FrameType::Error => {
            let mut payload = payload;
            let _status = ErrorPayload::decode(&mut payload)?;
            Ok(())
        }
        FrameType::PolicyDenied => expect_error_payload(payload, ErrorCode::PolicyDenied),
        FrameType::ResourceLimit => expect_error_payload(payload, ErrorCode::ResourceLimit),
        _ => Err("unexpected flow status frame".into()),
    }
}

fn status_frame(frame_type: FrameType, flow_id: u64, code: ErrorCode) -> Result<Frame, AnyError> {
    let mut payload = BytesMut::new();
    ErrorPayload::new(code).encode(&mut payload)?;
    Ok(Frame::new(frame_type, 0, flow_id, payload.freeze())?)
}

fn decode_open_response(frame: Frame) -> Result<OpenResponse, AnyError> {
    match frame.header.frame_type {
        // Must be zero-length: `docs/spec-v0.1.md` defines the acknowledgement
        // as an empty TCP_DATA and makes anything else a protocol error, so a
        // coalesced ack is a non-conforming peer, not an optimisation to accept.
        FrameType::TcpData if frame.payload.is_empty() => Ok(OpenResponse::Accepted),
        FrameType::PolicyDenied => {
            expect_error_payload(frame.payload, ErrorCode::PolicyDenied)?;
            Ok(OpenResponse::Rejected(socks5::Reply::NotAllowed))
        }
        FrameType::ResourceLimit => {
            expect_error_payload(frame.payload, ErrorCode::ResourceLimit)?;
            Ok(OpenResponse::Rejected(socks5::Reply::GeneralFailure))
        }
        FrameType::Error => Ok(OpenResponse::Rejected(map_error_payload(frame.payload)?)),
        FrameType::TcpClose => {
            let mut payload = frame.payload;
            let close = TcpClose::decode(&mut payload)?;
            let reply = if close.close_code == TCP_CLOSE_NORMAL {
                socks5::Reply::ConnectionRefused
            } else {
                socks5::Reply::GeneralFailure
            };
            Ok(OpenResponse::Rejected(reply))
        }
        _ => Err("unexpected frame while opening tcp flow".into()),
    }
}

fn decode_udp_open_response(frame: Frame) -> Result<OpenResponse, AnyError> {
    match frame.header.frame_type {
        FrameType::UdpData if frame.payload.is_empty() => Ok(OpenResponse::Accepted),
        FrameType::PolicyDenied => {
            expect_error_payload(frame.payload, ErrorCode::PolicyDenied)?;
            Ok(OpenResponse::Rejected(socks5::Reply::NotAllowed))
        }
        FrameType::ResourceLimit => {
            expect_error_payload(frame.payload, ErrorCode::ResourceLimit)?;
            Ok(OpenResponse::Rejected(socks5::Reply::GeneralFailure))
        }
        FrameType::Error => Ok(OpenResponse::Rejected(map_error_payload(frame.payload)?)),
        FrameType::UdpClose => {
            let mut payload = frame.payload;
            let close = UdpClose::decode(&mut payload)?;
            let reply = if close.close_code == UDP_CLOSE_NORMAL {
                socks5::Reply::ConnectionRefused
            } else {
                socks5::Reply::GeneralFailure
            };
            Ok(OpenResponse::Rejected(reply))
        }
        _ => Err("unexpected frame while opening udp flow".into()),
    }
}

fn expect_error_payload(mut payload: Bytes, code: ErrorCode) -> Result<(), AnyError> {
    let status = ErrorPayload::decode(&mut payload)?;
    if status.code == code {
        Ok(())
    } else {
        Err("unexpected error payload code".into())
    }
}

fn map_error_payload(mut payload: Bytes) -> Result<socks5::Reply, AnyError> {
    let status = ErrorPayload::decode(&mut payload)?;
    let reply = match status.code {
        ErrorCode::InvalidTarget | ErrorCode::TargetUnavailable | ErrorCode::TargetTimeout => {
            socks5::Reply::HostUnreachable
        }
        ErrorCode::PolicyDenied => socks5::Reply::NotAllowed,
        ErrorCode::ResourceLimit
        | ErrorCode::Protocol
        | ErrorCode::UnsupportedVersion
        | ErrorCode::UnsupportedFlag
        | ErrorCode::OversizedFrame
        | ErrorCode::TruncatedFrame
        | ErrorCode::AuthFailed => socks5::Reply::GeneralFailure,
    };
    Ok(reply)
}

async fn write_frame_locked(
    writer: &CarrierWriter,
    frame: &Frame,
    shutdown: &ClientSessionShutdown,
) -> Result<(), AnyError> {
    let mut writer = tokio::select! {
        writer = writer.lock() => writer,
        () = shutdown.closed() => return Err(session_shutdown_error().into()),
    };
    if shutdown.is_closed() {
        return Err(session_shutdown_error().into());
    }
    write_frame_or_shutdown(&mut *writer, frame, shutdown).await?;
    Ok(())
}

async fn write_frame_or_shutdown<W>(
    writer: &mut W,
    frame: &Frame,
    shutdown: &ClientSessionShutdown,
) -> Result<(), AnyError>
where
    W: AsyncWrite + Unpin,
{
    tokio::select! {
        result = write_frame(writer, frame) => result?,
        () = shutdown.closed() => return Err(session_shutdown_error().into()),
    }
    Ok(())
}

fn session_shutdown_error() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "session shutdown")
}

fn keepalive_interval(settings: NegotiatedSettings) -> Option<Duration> {
    let idle_timeout_seconds = settings.idle_timeout_seconds;
    if idle_timeout_seconds == 0 {
        return None;
    }
    let interval_millis = idle_timeout_seconds.saturating_mul(1000).saturating_div(2);
    Some(Duration::from_millis(interval_millis.max(1)))
}

fn tcp_data_frame_size(limits: FrameLimits) -> usize {
    usize::try_from(limits.max_frame_size)
        .map_or(RELAY_BUFFER_SIZE, |limit| limit.min(RELAY_BUFFER_SIZE))
}

fn reserve_bytes(buffered_bytes: &AtomicUsize, amount: usize, limit: usize) -> bool {
    let mut current = buffered_bytes.load(Ordering::SeqCst);
    loop {
        let Some(next) = current.checked_add(amount) else {
            return false;
        };
        if next > limit {
            return false;
        }
        match buffered_bytes.compare_exchange_weak(
            current,
            next,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => return true,
            Err(actual) => current = actual,
        }
    }
}

fn release_bytes(buffered_bytes: &AtomicUsize, amount: usize) {
    let _ = buffered_bytes.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
        Some(current.saturating_sub(amount))
    });
}

fn usize_limit(value: u64) -> Result<usize, AnyError> {
    Ok(usize::try_from(value).map_err(|_| "limit is too large for this platform")?)
}

fn timeout(seconds: u64) -> Option<Duration> {
    (seconds != 0).then(|| Duration::from_secs(seconds))
}

fn retry_delay(milliseconds: u64) -> Option<Duration> {
    (milliseconds != 0).then(|| Duration::from_millis(milliseconds))
}

fn retry_delay_expires_at(delay: Duration) -> Option<time::Instant> {
    time::Instant::now().checked_add(delay)
}

fn cached_connect_failure_error(failure: CachedConnectFailure) -> AnyError {
    Box::new(CachedConnectFailureError {
        message: failure.message,
    })
}

fn is_session_draining_error(error: &AnyError) -> bool {
    error
        .as_ref()
        .downcast_ref::<SessionDrainingError>()
        .is_some()
}

fn transition(state: &mut ClientConnectionState, next: ClientConnectionState) {
    let from = *state;
    debug_assert!(
        is_valid_connection_transition(from, next),
        "invalid client connection state transition"
    );
    debug!(event = "client.connection.state", from = ?from, to = ?next);
    *state = next;
}

const fn is_valid_connection_transition(
    from: ClientConnectionState,
    next: ClientConnectionState,
) -> bool {
    matches!(
        (from, next),
        (
            ClientConnectionState::NegotiatingSocks,
            ClientConnectionState::Opening
                | ClientConnectionState::Relaying
                | ClientConnectionState::Closed
        ) | (
            ClientConnectionState::Opening,
            ClientConnectionState::Relaying
                | ClientConnectionState::Closing
                | ClientConnectionState::Closed
        ) | (
            ClientConnectionState::Relaying,
            ClientConnectionState::Closing | ClientConnectionState::Closed
        ) | (
            ClientConnectionState::Closing,
            ClientConnectionState::Closed
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const FLOW_ID: u64 = 1;
    const CONTROL_PEER_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

    fn negotiated_settings_with_idle_timeout(idle_timeout_seconds: u64) -> NegotiatedSettings {
        NegotiatedSettings {
            max_frame_size: FrameLimits::default().max_frame_size,
            max_streams: 64,
            max_udp_flows: 64,
            supports_udp_datagram: false,
            supports_udp_stream_fallback: true,
            idle_timeout_seconds,
        }
    }

    fn minimal_config() -> ClientConfig {
        ClientConfig {
            server_addr: "127.0.0.1:443".to_owned(),
            server_addrs: None,
            server_name: "localhost".to_owned(),
            observability_listen: None,
            ca_cert_path: "missing-ca.pem".to_owned(),
            key_id: "client".to_owned(),
            secret: "0123456789abcdef0123456789abcdef".to_owned(),
            handshake_timeout_seconds: None,
            server_connect_retry_delay_millis: None,
            socks_handshake_timeout_seconds: None,
            tcp_open_timeout_seconds: None,
            udp_flow_idle_timeout_seconds: None,
            shutdown_timeout_seconds: None,
            max_pending_open_bytes: None,
            max_socks_connections: None,
            max_buffered_bytes_per_session: None,
            max_buffered_bytes_per_flow: None,
            max_carrier_sessions: None,
        }
    }

    fn test_session_manager(config: ClientConfig) -> ClientSessionManager {
        ClientSessionManager::new(config, Arc::new(ClientMetrics::default()))
    }

    /// Builds a session that is structurally complete but carries no live
    /// carrier tasks, for exercising admission and teardown without a server.
    fn test_session(max_streams: u64, max_udp_flows: u64) -> Arc<ClientSession> {
        let limits = FrameLimits::default();
        let (carrier_writer, _carrier_reader) = tokio::io::duplex(64);
        Arc::new(ClientSession {
            correlation_id: 1,
            config_generation: 1,
            writer: Arc::new(Mutex::new(Box::new(carrier_writer))),
            flows: Arc::new(Mutex::new(HashMap::new())),
            limits,
            data_frame_size: tcp_data_frame_size(limits),
            max_streams,
            max_udp_flows,
            admission: FlowAdmissionControl::new(max_streams, max_udp_flows),
            supports_udp_stream_fallback: true,
            supports_udp_datagram: false,
            datagrams: None,
            max_pending_open_bytes: 1024,
            max_buffered_bytes_per_session: 1024,
            max_buffered_bytes_per_flow: 1024,
            session_buffer: ClientSessionBufferControl::default(),
            open_timeout: None,
            task_shutdown_timeout: Some(Duration::from_millis(50)),
            tasks: Mutex::new(ClientSessionTasks::default()),
            shutdown: ClientSessionShutdown::default(),
            draining: AtomicBool::new(false),
            metrics: Arc::new(ClientMetrics::default()),
            metric_state: StdMutex::new(ClientSessionMetricState::Active),
            next_flow_id: AtomicU64::new(FIRST_CLIENT_FLOW_ID),
            next_ping_nonce: AtomicU64::new(0),
            outstanding_ping_nonce: AtomicU64::new(0),
            last_pong_nonce: AtomicU64::new(0),
            pong_notify: Notify::new(),
        })
    }

    /// Stands in for a server that never accepts another byte and never
    /// completes a shutdown — a peer whose socket buffers are full, or a host
    /// blackholing packets. `tokio::io::duplex` cannot model this because its
    /// `poll_shutdown` completes immediately.
    struct StallingWriter;

    impl AsyncWrite for StallingWriter {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            std::task::Poll::Pending
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Pending
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Pending
        }
    }

    /// A session whose carrier never finishes closing.
    fn test_session_with_stalled_carrier(
        task_shutdown_timeout: Option<Duration>,
    ) -> Arc<ClientSession> {
        let session = test_session(4, 4);
        let mut session = Arc::try_unwrap(session).ok().expect("sole owner");
        session.writer = Arc::new(Mutex::new(Box::new(StallingWriter)));
        session.task_shutdown_timeout = task_shutdown_timeout;
        Arc::new(session)
    }

    /// Closing must not hang on a server that cannot accept `close_notify`:
    /// this runs from the listener's accept loop on config reload, and from
    /// relay tasks when a draining session loses its last flow.
    #[tokio::test]
    async fn close_gives_up_on_a_carrier_that_never_finishes_closing() {
        let session = test_session_with_stalled_carrier(Some(Duration::from_millis(100)));

        tokio::time::timeout(Duration::from_secs(5), session.close())
            .await
            .expect("close must not block on an unresponsive carrier");

        assert!(session.is_closed());
    }

    /// Pruning a dead session must not be awaited on the flow-open path — two
    /// of those call sites hold `connect_lock`, so one hung carrier would stall
    /// every new SOCKS connection.
    #[tokio::test]
    async fn pruning_a_dead_session_does_not_block_the_flow_open_path() {
        let manager = test_session_manager(minimal_config());
        // No task-drain deadline and a task that never finishes, so this
        // session's teardown would block forever if it were awaited inline.
        let session = test_session_with_stalled_carrier(None);
        session
            .tasks
            .lock()
            .await
            .spawn(ClientSessionTaskKind::CarrierReader, async {
                std::future::pending::<()>().await;
            });
        // Mark it closed directly rather than via `close()`: with no drain
        // deadline `close()` would itself block on the stalled carrier, which
        // is the situation under test, not part of the setup.
        session.shutdown.close();
        assert!(session.is_closed());
        manager.pool.lock().await.push(session);

        let live = tokio::time::timeout(Duration::from_secs(5), manager.live_sessions())
            .await
            .expect("pruning must not await the stale session's teardown");

        assert!(live.is_empty(), "the closed session should be pruned");
    }

    fn boxed_io_error(kind: io::ErrorKind) -> AnyError {
        io::Error::new(kind, "test error").into()
    }

    fn expect_session_error(result: Result<Arc<ClientSession>, AnyError>) -> AnyError {
        match result {
            Ok(_) => panic!("session connect unexpectedly succeeded"),
            Err(err) => err,
        }
    }

    fn status_payload(code: ErrorCode) -> Bytes {
        let mut payload = BytesMut::new();
        ErrorPayload::new(code).encode(&mut payload).unwrap();
        payload.freeze()
    }

    fn error_frame_for(flow_id: u64, code: ErrorCode) -> Frame {
        Frame::new(FrameType::Error, 0, flow_id, status_payload(code)).unwrap()
    }

    fn error_frame(code: ErrorCode) -> Frame {
        error_frame_for(FLOW_ID, code)
    }

    fn data_frame(flow_id: u64, payload: Bytes) -> Frame {
        Frame::new(FrameType::TcpData, 0, flow_id, payload).unwrap()
    }

    fn close_frame(close_code: u16) -> Frame {
        let mut payload = BytesMut::new();
        TcpClose::new(close_code).encode(&mut payload).unwrap();
        Frame::new(FrameType::TcpClose, 0, FLOW_ID, payload.freeze()).unwrap()
    }

    fn udp_data_frame(flow_id: u64, payload: Bytes) -> Frame {
        Frame::new(FrameType::UdpData, 0, flow_id, payload).unwrap()
    }

    fn udp_close_frame(close_code: u16) -> Frame {
        let mut payload = BytesMut::new();
        UdpClose::new(close_code).encode(&mut payload).unwrap();
        Frame::new(FrameType::UdpClose, 0, FLOW_ID, payload.freeze()).unwrap()
    }

    fn control_frame(frame_type: FrameType, flow_id: u64) -> Frame {
        Frame::new(frame_type, 0, flow_id, Bytes::new()).unwrap()
    }

    fn route_test_flow_frame(
        frame: Frame,
        flows: &mut HashMap<u64, ClientFlowRoute>,
    ) -> (u64, FlowFrameRoute) {
        let (flow_id, _protocol, route) = route_flow_frame(
            frame,
            flows,
            ClientSessionBufferControl::default(),
            usize::MAX,
            usize::MAX,
        );
        (flow_id, route)
    }

    fn buffered_flow_frame(frame: Frame) -> BufferedFlowFrame {
        BufferedFlowFrame::new(
            frame,
            ClientFlowBufferControl::default(),
            ClientSessionBufferControl::default(),
            usize::MAX,
            usize::MAX,
        )
        .unwrap()
    }

    #[test]
    fn reserve_flow_slot_allocates_route_when_capacity_is_available() {
        let mut flows = HashMap::new();
        let next_flow_id = AtomicU64::new(FIRST_CLIENT_FLOW_ID);
        let (sender, _receiver) = mpsc::channel(1);

        assert_eq!(
            reserve_flow_slot(
                &mut flows,
                1,
                &next_flow_id,
                sender,
                FlowProtocol::Tcp,
                u64::MAX,
            )
            .unwrap(),
            Some(FIRST_CLIENT_FLOW_ID)
        );

        assert!(flows.contains_key(&FIRST_CLIENT_FLOW_ID));
        assert_eq!(
            next_flow_id.load(Ordering::Relaxed),
            FIRST_CLIENT_FLOW_ID + FLOW_ID_STEP
        );
    }

    #[test]
    fn reserve_flow_slot_does_not_consume_id_when_stream_limit_is_full() {
        let mut flows = HashMap::new();
        let (existing_sender, _existing_receiver) = mpsc::channel(1);
        flows.insert(
            FLOW_ID,
            ClientFlowRoute::new(existing_sender, FlowProtocol::Tcp),
        );
        let next_flow_id = AtomicU64::new(FIRST_CLIENT_FLOW_ID);
        let (sender, _receiver) = mpsc::channel(1);

        assert_eq!(
            reserve_flow_slot(
                &mut flows,
                1,
                &next_flow_id,
                sender,
                FlowProtocol::Tcp,
                u64::MAX,
            )
            .unwrap(),
            None
        );

        assert_eq!(flows.len(), 1);
        assert_eq!(next_flow_id.load(Ordering::Relaxed), FIRST_CLIENT_FLOW_ID);
    }

    #[test]
    fn reserve_flow_slot_enforces_udp_flow_limit() {
        let mut flows = HashMap::new();
        let (existing_sender, _existing_receiver) = mpsc::channel(1);
        flows.insert(
            FLOW_ID,
            ClientFlowRoute::new(existing_sender, FlowProtocol::Udp),
        );
        let next_flow_id = AtomicU64::new(FIRST_CLIENT_FLOW_ID);
        let (sender, _receiver) = mpsc::channel(1);

        assert_eq!(
            reserve_flow_slot(&mut flows, 8, &next_flow_id, sender, FlowProtocol::Udp, 1,).unwrap(),
            None
        );

        assert_eq!(flows.len(), 1);
        assert_eq!(next_flow_id.load(Ordering::Relaxed), FIRST_CLIENT_FLOW_ID);
    }

    #[test]
    fn reserve_flow_slot_allows_tcp_when_udp_limit_is_full() {
        let mut flows = HashMap::new();
        let (existing_sender, _existing_receiver) = mpsc::channel(1);
        flows.insert(
            FLOW_ID,
            ClientFlowRoute::new(existing_sender, FlowProtocol::Udp),
        );
        let next_flow_id = AtomicU64::new(FIRST_CLIENT_FLOW_ID);
        let (sender, _receiver) = mpsc::channel(1);

        assert_eq!(
            reserve_flow_slot(&mut flows, 8, &next_flow_id, sender, FlowProtocol::Tcp, 1,).unwrap(),
            Some(FIRST_CLIENT_FLOW_ID + FLOW_ID_STEP)
        );
    }

    #[test]
    fn zero_udp_flow_limit_disables_client_udp_reservation() {
        let mut flows = HashMap::new();
        let next_flow_id = AtomicU64::new(FIRST_CLIENT_FLOW_ID);
        let (sender, _receiver) = mpsc::channel(1);

        assert_eq!(
            reserve_flow_slot(&mut flows, 8, &next_flow_id, sender, FlowProtocol::Udp, 0,).unwrap(),
            None
        );

        assert!(flows.is_empty());
        assert_eq!(next_flow_id.load(Ordering::Relaxed), FIRST_CLIENT_FLOW_ID);
    }

    #[test]
    fn routes_carrier_frame_to_existing_flow() {
        let (sender, mut receiver) = mpsc::channel(1);
        let mut flows = HashMap::new();
        flows.insert(FLOW_ID, ClientFlowRoute::new(sender, FlowProtocol::Tcp));

        assert_eq!(
            route_test_flow_frame(
                data_frame(FLOW_ID, Bytes::from_static(b"hello")),
                &mut flows
            ),
            (FLOW_ID, FlowFrameRoute::Enqueued)
        );

        let frame = receiver.try_recv().unwrap().into_frame().unwrap();
        assert_eq!(frame.header.id, FLOW_ID);
        assert_eq!(frame.payload, Bytes::from_static(b"hello"));
        assert!(flows.contains_key(&FLOW_ID));
    }

    #[test]
    fn rejects_udp_frame_for_tcp_flow_before_queueing() {
        let (sender, mut receiver) = mpsc::channel(1);
        let mut flows = HashMap::new();
        flows.insert(FLOW_ID, ClientFlowRoute::new(sender, FlowProtocol::Tcp));

        assert_eq!(
            route_flow_frame(
                udp_data_frame(FLOW_ID, Bytes::from_static(b"wrong protocol")),
                &mut flows,
                ClientSessionBufferControl::default(),
                usize::MAX,
                usize::MAX,
            ),
            (
                FLOW_ID,
                Some(FlowProtocol::Tcp),
                FlowFrameRoute::ProtocolMismatch
            )
        );

        assert!(receiver.try_recv().is_err());
        assert!(!flows.contains_key(&FLOW_ID));
    }

    #[test]
    fn rejects_tcp_frame_for_udp_flow_before_queueing() {
        let (sender, mut receiver) = mpsc::channel(1);
        let mut flows = HashMap::new();
        flows.insert(FLOW_ID, ClientFlowRoute::new(sender, FlowProtocol::Udp));

        assert_eq!(
            route_flow_frame(
                data_frame(FLOW_ID, Bytes::from_static(b"wrong protocol")),
                &mut flows,
                ClientSessionBufferControl::default(),
                usize::MAX,
                usize::MAX,
            ),
            (
                FLOW_ID,
                Some(FlowProtocol::Udp),
                FlowFrameRoute::ProtocolMismatch
            )
        );

        assert!(receiver.try_recv().is_err());
        assert!(!flows.contains_key(&FLOW_ID));
    }

    #[test]
    fn routes_flow_status_to_udp_flow() {
        let (sender, mut receiver) = mpsc::channel(1);
        let mut flows = HashMap::new();
        flows.insert(FLOW_ID, ClientFlowRoute::new(sender, FlowProtocol::Udp));

        assert_eq!(
            route_test_flow_frame(error_frame(ErrorCode::Protocol), &mut flows),
            (FLOW_ID, FlowFrameRoute::Enqueued)
        );

        let frame = receiver.try_recv().unwrap().into_frame().unwrap();
        assert_eq!(frame.header.frame_type, FrameType::Error);
        assert!(flows.contains_key(&FLOW_ID));
    }

    #[test]
    fn ignores_carrier_frame_for_unknown_flow() {
        let mut flows = HashMap::new();

        assert_eq!(
            route_test_flow_frame(data_frame(99, Bytes::from_static(b"late")), &mut flows),
            (99, FlowFrameRoute::UnknownFlow)
        );
        assert!(flows.is_empty());
    }

    #[test]
    fn rejects_zero_id_carrier_flow_frame() {
        let mut flows = HashMap::new();

        assert_eq!(
            route_test_flow_frame(data_frame(0, Bytes::from_static(b"invalid")), &mut flows),
            (0, FlowFrameRoute::InvalidFlowId)
        );
        assert!(flows.is_empty());
    }

    #[test]
    fn rejects_reserved_carrier_flow_frame() {
        let mut flows = HashMap::new();

        assert_eq!(
            route_test_flow_frame(data_frame(2, Bytes::from_static(b"reserved")), &mut flows),
            (2, FlowFrameRoute::InvalidFlowId)
        );
        assert!(flows.is_empty());
    }

    #[test]
    fn removes_closed_flow_sender() {
        let (sender, receiver) = mpsc::channel(1);
        drop(receiver);
        let mut flows = HashMap::new();
        flows.insert(FLOW_ID, ClientFlowRoute::new(sender, FlowProtocol::Tcp));

        assert_eq!(
            route_test_flow_frame(data_frame(FLOW_ID, Bytes::from_static(b"late")), &mut flows),
            (FLOW_ID, FlowFrameRoute::FlowClosed)
        );
        assert!(!flows.contains_key(&FLOW_ID));
    }

    #[test]
    fn removes_full_flow_sender() {
        let (sender, mut receiver) = mpsc::channel(1);
        sender
            .try_send(buffered_flow_frame(data_frame(
                FLOW_ID,
                Bytes::from_static(b"queued"),
            )))
            .unwrap();
        let mut flows = HashMap::new();
        flows.insert(FLOW_ID, ClientFlowRoute::new(sender, FlowProtocol::Tcp));

        assert_eq!(
            route_test_flow_frame(
                data_frame(FLOW_ID, Bytes::from_static(b"overflow")),
                &mut flows
            ),
            (FLOW_ID, FlowFrameRoute::FlowQueueFull)
        );
        assert!(!flows.contains_key(&FLOW_ID));
        assert_eq!(
            receiver.try_recv().unwrap().into_frame().unwrap().payload,
            Bytes::from_static(b"queued")
        );
    }

    #[test]
    fn removes_flow_when_flow_buffer_limit_is_exceeded() {
        let (sender, _receiver) = mpsc::channel(1);
        let mut flows = HashMap::new();
        flows.insert(FLOW_ID, ClientFlowRoute::new(sender, FlowProtocol::Tcp));
        let session_buffer = ClientSessionBufferControl::default();

        assert_eq!(
            route_flow_frame(
                data_frame(FLOW_ID, Bytes::from_static(b"overflow")),
                &mut flows,
                session_buffer.clone(),
                4,
                usize::MAX,
            ),
            (
                FLOW_ID,
                Some(FlowProtocol::Tcp),
                FlowFrameRoute::FlowQueueFull
            )
        );

        assert!(!flows.contains_key(&FLOW_ID));
        assert_eq!(session_buffer.buffered_bytes(), 0);
    }

    #[test]
    fn removes_flow_when_session_buffer_limit_is_exceeded() {
        let (sender, _receiver) = mpsc::channel(1);
        let mut flows = HashMap::new();
        flows.insert(FLOW_ID, ClientFlowRoute::new(sender, FlowProtocol::Tcp));
        let session_buffer = ClientSessionBufferControl::default();

        assert_eq!(
            route_flow_frame(
                data_frame(FLOW_ID, Bytes::from_static(b"overflow")),
                &mut flows,
                session_buffer.clone(),
                usize::MAX,
                4,
            ),
            (
                FLOW_ID,
                Some(FlowProtocol::Tcp),
                FlowFrameRoute::SessionQueueFull
            )
        );

        assert!(!flows.contains_key(&FLOW_ID));
        assert_eq!(session_buffer.buffered_bytes(), 0);
    }

    #[test]
    fn buffered_flow_frame_releases_session_bytes_on_drop() {
        let flow_buffer = ClientFlowBufferControl::default();
        let session_buffer = ClientSessionBufferControl::default();
        let buffered = BufferedFlowFrame::new(
            data_frame(FLOW_ID, Bytes::from_static(b"queued")),
            flow_buffer.clone(),
            session_buffer.clone(),
            16,
            16,
        )
        .unwrap();

        assert_eq!(flow_buffer.buffered_bytes(), 6);
        assert_eq!(session_buffer.buffered_bytes(), 6);
        drop(buffered);
        assert_eq!(flow_buffer.buffered_bytes(), 0);
        assert_eq!(session_buffer.buffered_bytes(), 0);
    }

    #[test]
    fn buffered_flow_frame_releases_session_bytes_on_into_frame() {
        let flow_buffer = ClientFlowBufferControl::default();
        let session_buffer = ClientSessionBufferControl::default();
        let buffered = BufferedFlowFrame::new(
            data_frame(FLOW_ID, Bytes::from_static(b"queued")),
            flow_buffer.clone(),
            session_buffer.clone(),
            16,
            16,
        )
        .unwrap();

        let frame = buffered.into_frame().unwrap();

        assert_eq!(frame.payload, Bytes::from_static(b"queued"));
        assert_eq!(flow_buffer.buffered_bytes(), 0);
        assert_eq!(session_buffer.buffered_bytes(), 0);
    }

    #[test]
    fn buffered_flow_frame_missing_inner_frame_returns_error_after_release() {
        let flow_buffer = ClientFlowBufferControl::default();
        let session_buffer = ClientSessionBufferControl::default();
        let mut buffered = BufferedFlowFrame::new(
            data_frame(FLOW_ID, Bytes::from_static(b"queued")),
            flow_buffer.clone(),
            session_buffer.clone(),
            16,
            16,
        )
        .unwrap();

        let removed = buffered.frame.take();
        assert!(removed.is_some());
        assert_eq!(flow_buffer.buffered_bytes(), 6);
        assert_eq!(session_buffer.buffered_bytes(), 6);

        let error = buffered.into_frame().unwrap_err();

        assert_eq!(error.to_string(), "buffered frame missing");
        assert_eq!(flow_buffer.buffered_bytes(), 0);
        assert_eq!(session_buffer.buffered_bytes(), 0);
    }

    #[test]
    fn decodes_open_ack() {
        let frame = Frame::new(FrameType::TcpData, 0, FLOW_ID, Bytes::new()).unwrap();

        assert_eq!(decode_open_response(frame).unwrap(), OpenResponse::Accepted);
    }

    #[test]
    fn decodes_udp_open_ack() {
        let frame = udp_data_frame(FLOW_ID, Bytes::new());

        assert_eq!(
            decode_udp_open_response(frame).unwrap(),
            OpenResponse::Accepted
        );
    }

    #[test]
    fn decodes_policy_denied_open_response() {
        let frame = Frame::new(
            FrameType::PolicyDenied,
            0,
            FLOW_ID,
            status_payload(ErrorCode::PolicyDenied),
        )
        .unwrap();

        assert_eq!(
            decode_open_response(frame).unwrap(),
            OpenResponse::Rejected(socks5::Reply::NotAllowed)
        );
    }

    #[test]
    fn decodes_resource_limit_open_response() {
        let frame = Frame::new(
            FrameType::ResourceLimit,
            0,
            FLOW_ID,
            status_payload(ErrorCode::ResourceLimit),
        )
        .unwrap();

        assert_eq!(
            decode_open_response(frame).unwrap(),
            OpenResponse::Rejected(socks5::Reply::GeneralFailure)
        );
    }

    #[test]
    fn maps_error_open_response_codes_to_socks_replies() {
        let cases = [
            (ErrorCode::UnsupportedVersion, socks5::Reply::GeneralFailure),
            (ErrorCode::UnsupportedFlag, socks5::Reply::GeneralFailure),
            (ErrorCode::OversizedFrame, socks5::Reply::GeneralFailure),
            (ErrorCode::TruncatedFrame, socks5::Reply::GeneralFailure),
            (ErrorCode::InvalidTarget, socks5::Reply::HostUnreachable),
            (ErrorCode::AuthFailed, socks5::Reply::GeneralFailure),
            (ErrorCode::PolicyDenied, socks5::Reply::NotAllowed),
            (ErrorCode::ResourceLimit, socks5::Reply::GeneralFailure),
            (ErrorCode::Protocol, socks5::Reply::GeneralFailure),
            (ErrorCode::TargetUnavailable, socks5::Reply::HostUnreachable),
            (ErrorCode::TargetTimeout, socks5::Reply::HostUnreachable),
        ];

        for (code, expected_reply) in cases {
            assert_eq!(
                decode_open_response(error_frame(code)).unwrap(),
                OpenResponse::Rejected(expected_reply),
                "error code {code:?}"
            );
        }
    }

    #[test]
    fn accepts_matching_flow_status_payloads() {
        assert!(
            validate_flow_status(FrameType::Error, status_payload(ErrorCode::Protocol)).is_ok()
        );
        assert!(
            validate_flow_status(
                FrameType::PolicyDenied,
                status_payload(ErrorCode::PolicyDenied)
            )
            .is_ok()
        );
        assert!(
            validate_flow_status(
                FrameType::ResourceLimit,
                status_payload(ErrorCode::ResourceLimit)
            )
            .is_ok()
        );
    }

    #[test]
    fn status_frame_encodes_flow_resource_limit() {
        let frame =
            status_frame(FrameType::ResourceLimit, FLOW_ID, ErrorCode::ResourceLimit).unwrap();

        assert_eq!(frame.header.frame_type, FrameType::ResourceLimit);
        assert_eq!(frame.header.id, FLOW_ID);
        let mut payload = frame.payload;
        assert_eq!(
            ErrorPayload::decode(&mut payload).unwrap().code,
            ErrorCode::ResourceLimit
        );
    }

    #[test]
    fn status_frame_encodes_connection_error() {
        let frame = status_frame(FrameType::Error, 0, ErrorCode::Protocol).unwrap();

        assert_eq!(frame.header.frame_type, FrameType::Error);
        assert_eq!(frame.header.id, 0);
        let mut payload = frame.payload;
        assert_eq!(
            ErrorPayload::decode(&mut payload).unwrap().code,
            ErrorCode::Protocol
        );
    }

    #[test]
    fn rejects_mismatched_flow_status_payloads() {
        assert!(
            validate_flow_status(
                FrameType::PolicyDenied,
                status_payload(ErrorCode::ResourceLimit)
            )
            .is_err()
        );
        assert!(
            validate_flow_status(
                FrameType::ResourceLimit,
                status_payload(ErrorCode::PolicyDenied)
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_unexpected_flow_status_frame_type() {
        assert!(validate_flow_status(FrameType::TcpData, Bytes::new()).is_err());
    }

    #[test]
    fn rejects_malformed_flow_status_payload() {
        assert!(validate_flow_status(FrameType::Error, Bytes::new()).is_err());
        assert!(validate_flow_status(FrameType::PolicyDenied, Bytes::new()).is_err());
        assert!(validate_flow_status(FrameType::ResourceLimit, Bytes::new()).is_err());
    }

    #[test]
    fn validates_server_flow_frames_before_routing() {
        assert!(validate_server_flow_frame(&data_frame(FLOW_ID, Bytes::new())).is_ok());
        assert!(validate_server_flow_frame(&close_frame(TCP_CLOSE_NORMAL)).is_ok());
        assert!(validate_server_flow_frame(&udp_data_frame(FLOW_ID, Bytes::new())).is_ok());
        assert!(validate_server_flow_frame(&udp_close_frame(UDP_CLOSE_NORMAL)).is_ok());
        assert!(validate_server_flow_frame(&error_frame(ErrorCode::Protocol)).is_ok());
    }

    #[test]
    fn rejects_malformed_server_flow_frames_before_routing() {
        let malformed_close = Frame::new(FrameType::TcpClose, 0, FLOW_ID, Bytes::new()).unwrap();
        let malformed_udp_close =
            Frame::new(FrameType::UdpClose, 0, FLOW_ID, Bytes::new()).unwrap();
        let malformed_status = Frame::new(FrameType::Error, 0, FLOW_ID, Bytes::new()).unwrap();
        let mismatched_policy_denied = Frame::new(
            FrameType::PolicyDenied,
            0,
            FLOW_ID,
            status_payload(ErrorCode::ResourceLimit),
        )
        .unwrap();

        assert!(validate_server_flow_frame(&malformed_close).is_err());
        assert!(validate_server_flow_frame(&malformed_udp_close).is_err());
        assert!(validate_server_flow_frame(&malformed_status).is_err());
        assert!(validate_server_flow_frame(&mismatched_policy_denied).is_err());
    }

    #[test]
    fn classifies_connection_error_frames() {
        assert!(is_connection_error_frame(&error_frame_for(
            0,
            ErrorCode::Protocol
        )));
        assert!(!is_connection_error_frame(&error_frame(
            ErrorCode::Protocol
        )));
        assert!(!is_connection_error_frame(
            &Frame::new(
                FrameType::PolicyDenied,
                0,
                0,
                status_payload(ErrorCode::PolicyDenied)
            )
            .unwrap()
        ));
    }

    #[test]
    fn decodes_tcp_close_open_response_as_connection_refused() {
        assert_eq!(
            decode_open_response(close_frame(TCP_CLOSE_NORMAL)).unwrap(),
            OpenResponse::Rejected(socks5::Reply::ConnectionRefused)
        );
    }

    #[test]
    fn decodes_udp_close_open_response_as_connection_refused() {
        assert_eq!(
            decode_udp_open_response(udp_close_frame(UDP_CLOSE_NORMAL)).unwrap(),
            OpenResponse::Rejected(socks5::Reply::ConnectionRefused)
        );
    }

    #[test]
    fn maps_tcp_close_error_open_response_to_general_failure() {
        assert_eq!(
            decode_open_response(close_frame(TCP_CLOSE_ERROR)).unwrap(),
            OpenResponse::Rejected(socks5::Reply::GeneralFailure)
        );
    }

    #[test]
    fn rejects_policy_denied_with_wrong_error_code() {
        let frame = Frame::new(
            FrameType::PolicyDenied,
            0,
            FLOW_ID,
            status_payload(ErrorCode::Protocol),
        )
        .unwrap();

        assert!(decode_open_response(frame).is_err());
    }

    #[test]
    fn rejects_resource_limit_with_wrong_error_code() {
        let frame = Frame::new(
            FrameType::ResourceLimit,
            0,
            FLOW_ID,
            status_payload(ErrorCode::PolicyDenied),
        )
        .unwrap();

        assert!(decode_open_response(frame).is_err());
    }

    #[test]
    fn rejects_non_empty_tcp_data_as_open_ack() {
        let frame = Frame::new(
            FrameType::TcpData,
            0,
            FLOW_ID,
            Bytes::from_static(b"early data"),
        )
        .unwrap();

        assert!(decode_open_response(frame).is_err());
    }

    #[test]
    fn rejects_non_empty_udp_data_as_open_ack() {
        let frame = udp_data_frame(FLOW_ID, Bytes::from_static(b"early data"));

        assert!(decode_udp_open_response(frame).is_err());
    }

    #[test]
    fn rejects_unexpected_open_response_frame() {
        let frame = Frame::new(FrameType::Ping, 0, FLOW_ID, Bytes::new()).unwrap();

        assert!(decode_open_response(frame).is_err());
    }

    #[test]
    fn accepts_zero_id_session_control_frame() {
        assert!(
            validate_session_control_frame(&control_frame(FrameType::Ping, 0), FrameType::Ping)
                .is_ok()
        );
        assert!(
            validate_session_control_frame(&control_frame(FrameType::Pong, 0), FrameType::Pong)
                .is_ok()
        );
    }

    #[test]
    fn rejects_nonzero_id_session_control_frame() {
        assert!(
            validate_session_control_frame(
                &control_frame(FrameType::Ping, FLOW_ID),
                FrameType::Ping
            )
            .is_err()
        );
        assert!(
            validate_session_control_frame(
                &control_frame(FrameType::Pong, FLOW_ID),
                FrameType::Pong
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_invalid_socks_listen_endpoint() {
        assert!(validate_endpoint("socks listen", "127.0.0.1").is_err());
        assert!(validate_endpoint("socks listen", "127.0.0.1:0").is_err());
        assert!(validate_endpoint("socks listen", "::1:1080").is_err());
    }

    #[test]
    fn udp_association_bind_addr_uses_tcp_local_ip_with_ephemeral_port() {
        let bind_addr = udp_association_bind_addr(SocketAddr::from(([127, 0, 0, 1], 1080)));

        assert_eq!(bind_addr, SocketAddr::from(([127, 0, 0, 1], 0)));
    }

    #[test]
    fn udp_client_endpoint_learns_unspecified_peer() {
        let first_peer = SocketAddr::from(([127, 0, 0, 1], 41000));
        let second_peer = SocketAddr::from(([127, 0, 0, 1], 41001));
        let mut endpoint = UdpClientEndpoint::new(
            socks5::SocksEndpoint::Ipv4(std::net::Ipv4Addr::UNSPECIFIED, 0),
            CONTROL_PEER_IP,
        );

        assert!(endpoint.accepts(first_peer));
        assert_eq!(endpoint.learned(), Some(first_peer));
        assert!(endpoint.accepts(first_peer));
        assert!(!endpoint.accepts(second_peer));
    }

    #[test]
    fn udp_client_endpoint_ignores_peer_that_misses_declared_port() {
        let expected_peer = SocketAddr::from(([127, 0, 0, 1], 41000));
        let wrong_peer = SocketAddr::from(([127, 0, 0, 1], 41001));
        let mut endpoint = UdpClientEndpoint::new(
            socks5::SocksEndpoint::Ipv4(std::net::Ipv4Addr::LOCALHOST, expected_peer.port()),
            CONTROL_PEER_IP,
        );

        assert!(!endpoint.accepts(wrong_peer));
        assert_eq!(endpoint.learned(), None);
        assert!(endpoint.accepts(expected_peer));
        assert_eq!(endpoint.learned(), Some(expected_peer));
    }

    #[test]
    fn udp_client_endpoint_matches_declared_domain_port() {
        let expected_peer = SocketAddr::from(([127, 0, 0, 1], 41000));
        let wrong_peer = SocketAddr::from(([127, 0, 0, 1], 41001));
        let mut endpoint = UdpClientEndpoint::new(
            socks5::SocksEndpoint::Domain("client.local".to_owned(), 41000),
            CONTROL_PEER_IP,
        );

        assert!(!endpoint.accepts(wrong_peer));
        assert!(endpoint.accepts(expected_peer));
    }

    #[test]
    fn udp_client_endpoint_rejects_foreign_source_for_unspecified_request() {
        // RFC 1928 lets the client advertise all zeros, but the association
        // socket is bound to the SOCKS listener's IP, so only the host that
        // opened the control connection may claim it.
        let foreign_peer = SocketAddr::from(([192, 0, 2, 10], 41000));
        let client_peer = SocketAddr::from(([127, 0, 0, 1], 41000));
        let mut endpoint = UdpClientEndpoint::new(
            socks5::SocksEndpoint::Ipv4(std::net::Ipv4Addr::UNSPECIFIED, 0),
            CONTROL_PEER_IP,
        );

        assert!(!endpoint.accepts(foreign_peer));
        assert_eq!(endpoint.learned(), None);
        assert!(endpoint.accepts(client_peer));
        assert_eq!(endpoint.learned(), Some(client_peer));
    }

    #[test]
    fn udp_client_endpoint_rejects_foreign_source_for_unspecified_ipv6_request() {
        let foreign_peer = SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 41000));
        let client_peer = SocketAddr::from(([127, 0, 0, 1], 41000));
        let mut endpoint = UdpClientEndpoint::new(
            socks5::SocksEndpoint::Ipv6(std::net::Ipv6Addr::UNSPECIFIED, 0),
            CONTROL_PEER_IP,
        );

        assert!(!endpoint.accepts(foreign_peer));
        assert!(endpoint.accepts(client_peer));
    }

    #[test]
    fn udp_client_endpoint_rejects_foreign_source_for_domain_request() {
        // The domain form names the client but says nothing checkable about the
        // datagram source, so it falls back to the control connection's IP.
        let foreign_peer = SocketAddr::from(([192, 0, 2, 10], 41000));
        let client_peer = SocketAddr::from(([127, 0, 0, 1], 41000));
        let mut endpoint = UdpClientEndpoint::new(
            socks5::SocksEndpoint::Domain("client.local".to_owned(), 0),
            CONTROL_PEER_IP,
        );

        assert!(!endpoint.accepts(foreign_peer));
        assert!(endpoint.accepts(client_peer));
    }

    #[test]
    fn udp_client_endpoint_still_honours_an_explicit_client_address() {
        let declared_peer = SocketAddr::from(([203, 0, 113, 5], 41000));
        let control_peer = SocketAddr::from(([127, 0, 0, 1], 41000));
        let mut endpoint = UdpClientEndpoint::new(
            socks5::SocksEndpoint::Ipv4(std::net::Ipv4Addr::new(203, 0, 113, 5), 0),
            CONTROL_PEER_IP,
        );

        assert!(!endpoint.accepts(control_peer));
        assert!(endpoint.accepts(declared_peer));
    }

    #[test]
    fn udp_client_endpoint_matches_an_ipv4_mapped_control_peer() {
        let client_peer = SocketAddr::from(([127, 0, 0, 1], 41000));
        let mapped_control_ip = IpAddr::V6(std::net::Ipv4Addr::LOCALHOST.to_ipv6_mapped());
        let mut endpoint = UdpClientEndpoint::new(
            socks5::SocksEndpoint::Ipv4(std::net::Ipv4Addr::UNSPECIFIED, 0),
            mapped_control_ip,
        );

        assert!(endpoint.accepts(client_peer));
    }

    #[test]
    fn classifies_clean_socks_disconnects() {
        assert!(is_clean_socks_disconnect(&boxed_io_error(
            io::ErrorKind::UnexpectedEof
        )));
        assert!(is_clean_socks_disconnect(&boxed_io_error(
            io::ErrorKind::ConnectionReset
        )));
        assert!(is_clean_socks_disconnect(&boxed_io_error(
            io::ErrorKind::BrokenPipe
        )));
        assert!(is_clean_socks_disconnect(&boxed_io_error(
            io::ErrorKind::NotConnected
        )));
        assert!(!is_clean_socks_disconnect(&boxed_io_error(
            io::ErrorKind::InvalidData
        )));
    }

    #[tokio::test]
    async fn carrier_write_exits_when_session_shutdown_notifies() {
        let (mut writer, _reader) = tokio::io::duplex(1);
        let shutdown = ClientSessionShutdown::default();
        let shutdown_handle = shutdown.clone();
        let frame = Frame::new(
            FrameType::TcpData,
            0,
            FLOW_ID,
            Bytes::from(vec![0x42; 1024]),
        )
        .unwrap();

        let task =
            tokio::spawn(
                async move { write_frame_or_shutdown(&mut writer, &frame, &shutdown).await },
            );
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!task.is_finished());

        shutdown_handle.close();

        let err = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        let io_error = err.downcast_ref::<io::Error>().unwrap();
        assert_eq!(io_error.kind(), io::ErrorKind::Interrupted);
    }

    #[tokio::test]
    async fn client_session_tasks_reap_completed_tasks() {
        let mut tasks = ClientSessionTasks::default();

        tasks.spawn(ClientSessionTaskKind::Keepalive, async {});
        tokio::time::timeout(Duration::from_secs(1), tasks.join_next())
            .await
            .expect("completed client session task should be reaped");

        assert!(tasks.is_empty());
        assert!(tasks.kinds.is_empty());
    }

    #[tokio::test]
    async fn client_session_task_drain_aborts_pending_tasks_after_timeout() {
        let mut tasks = ClientSessionTasks::default();

        tasks.spawn(ClientSessionTaskKind::CarrierReader, async {
            std::future::pending::<()>().await;
        });
        drain_client_session_tasks(&mut tasks, Some(Duration::from_millis(10))).await;

        assert!(tasks.is_empty());
        assert!(tasks.kinds.is_empty());
    }

    #[tokio::test]
    async fn socks_shutdown_timeout_aborts_pending_connection_tasks() {
        let mut connections = JoinSet::new();
        connections.spawn(std::future::pending::<()>());

        tokio::time::timeout(
            Duration::from_secs(1),
            drain_socks_tasks(&mut connections, Some(Duration::from_millis(10))),
        )
        .await
        .unwrap();

        assert!(connections.is_empty());
    }

    #[tokio::test]
    async fn socks_shutdown_drain_waits_for_completed_connection_tasks() {
        let mut connections = JoinSet::new();
        connections.spawn(async {});

        drain_socks_tasks(&mut connections, Some(Duration::from_secs(1))).await;

        assert!(connections.is_empty());
    }

    #[tokio::test]
    async fn udp_association_activity_events_are_lossy_when_queue_is_full() {
        let (event_tx, mut event_rx) = mpsc::channel(1);
        let first_target = Target::Domain("first.example".to_owned(), 53);
        let second_target = Target::Domain("second.example".to_owned(), 53);

        try_record_udp_association_activity(&event_tx, 1, &first_target);
        try_record_udp_association_activity(&event_tx, 3, &second_target);

        match event_rx.recv().await {
            Some(UdpAssociationFlowEvent::Activity { flow_id, target }) => {
                assert_eq!(flow_id, 1);
                assert_eq!(target, first_target);
            }
            None => panic!("activity event should be queued"),
        }
        assert!(event_rx.try_recv().is_err());
    }

    #[test]
    fn allocates_client_flow_ids_up_to_varint_limit() {
        let next_flow_id = AtomicU64::new(MAX_VARINT - FLOW_ID_STEP);

        assert_eq!(
            allocate_client_flow_id(&next_flow_id),
            Some(MAX_VARINT - FLOW_ID_STEP)
        );
        assert_eq!(allocate_client_flow_id(&next_flow_id), Some(MAX_VARINT));
        assert_eq!(allocate_client_flow_id(&next_flow_id), None);
    }

    #[test]
    fn allocates_nonzero_keepalive_nonces() {
        let counter = AtomicU64::new(0);

        assert_eq!(next_keepalive_nonce(&counter), Some(1));
        assert_eq!(next_keepalive_nonce(&counter), Some(2));
    }

    #[test]
    fn keepalive_nonce_exhaustion_does_not_wrap() {
        let counter = AtomicU64::new(u64::MAX - 1);

        assert_eq!(next_keepalive_nonce(&counter), Some(u64::MAX));
        assert_eq!(next_keepalive_nonce(&counter), None);
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    }

    #[test]
    fn decodes_keepalive_nonce_payloads() {
        let payload = keepalive_nonce_payload(42);

        assert_eq!(decode_keepalive_nonce(&payload), Some(42));
        assert_eq!(decode_keepalive_nonce(&Bytes::new()), None);
        assert_eq!(
            decode_keepalive_nonce(&Bytes::from_static(b"too long!")),
            None
        );
    }

    #[test]
    fn records_only_the_outstanding_keepalive_pong() {
        let outstanding = AtomicU64::new(42);
        let last_pong = AtomicU64::new(0);

        assert_eq!(
            record_matching_pong(&outstanding, &last_pong, &keepalive_nonce_payload(42)),
            KeepalivePong::Matched(42)
        );
        assert_eq!(last_pong.load(Ordering::SeqCst), 42);
    }

    #[test]
    fn stale_keepalive_pong_cannot_overwrite_a_match() {
        let outstanding = AtomicU64::new(42);
        let last_pong = AtomicU64::new(42);

        assert_eq!(
            record_matching_pong(&outstanding, &last_pong, &keepalive_nonce_payload(41)),
            KeepalivePong::Unexpected {
                nonce: 41,
                expected_nonce: 42
            }
        );
        assert_eq!(last_pong.load(Ordering::SeqCst), 42);
    }

    #[test]
    fn unsolicited_keepalive_pong_is_ignored() {
        let outstanding = AtomicU64::new(0);
        let last_pong = AtomicU64::new(0);

        assert_eq!(
            record_matching_pong(&outstanding, &last_pong, &keepalive_nonce_payload(1)),
            KeepalivePong::Unexpected {
                nonce: 1,
                expected_nonce: 0
            }
        );
        assert_eq!(last_pong.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn stops_allocating_unrepresentable_client_flow_ids() {
        let next_flow_id = AtomicU64::new(MAX_VARINT + FLOW_ID_STEP);

        assert_eq!(allocate_client_flow_id(&next_flow_id), None);
    }

    #[tokio::test]
    async fn socks_listener_rejects_invalid_backing_config_before_bind() {
        let result = run_socks5_listener_until_shutdown(
            minimal_config(),
            "127.0.0.1:1".to_owned(),
            std::future::pending(),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn session_manager_reuses_recent_connect_failure_during_retry_delay() {
        let mut config = minimal_config();
        config.server_connect_retry_delay_millis = Some(250);
        let manager = test_session_manager(config);

        let first = expect_session_error(manager.current_session().await);
        assert!(!first.to_string().contains("retry cooldown active"));

        let second = expect_session_error(manager.current_session().await);
        let text = second.to_string();

        assert!(text.contains("retry cooldown active"));
        assert!(text.contains("missing-ca.pem"));
    }

    #[tokio::test]
    async fn session_manager_can_disable_connect_failure_retry_delay() {
        let mut config = minimal_config();
        config.server_connect_retry_delay_millis = Some(0);
        let manager = test_session_manager(config);

        let first = expect_session_error(manager.current_session().await);
        let second = expect_session_error(manager.current_session().await);

        assert!(!first.to_string().contains("retry cooldown active"));
        assert!(!second.to_string().contains("retry cooldown active"));
    }

    #[tokio::test]
    async fn expired_session_connect_failure_cache_is_cleared() {
        let manager = test_session_manager(minimal_config());
        *manager.recent_connect_failure.lock().await = Some(CachedConnectFailure {
            generation: 1,
            message: Arc::from("old failure"),
            expires_at: Some(time::Instant::now() - Duration::from_millis(1)),
        });

        assert!(manager.recent_connect_failure_if_active().await.is_none());
        assert!(manager.recent_connect_failure.lock().await.is_none());
    }

    #[tokio::test]
    async fn previous_generation_connect_failure_cache_is_cleared() {
        let manager = test_session_manager(minimal_config());
        *manager.recent_connect_failure.lock().await = Some(CachedConnectFailure {
            generation: 1,
            message: Arc::from("old failure"),
            expires_at: None,
        });
        manager.config.replace(minimal_config());

        assert!(manager.recent_connect_failure_if_active().await.is_none());
        assert!(manager.recent_connect_failure.lock().await.is_none());
    }

    #[test]
    fn client_reload_rejects_static_listener_changes() {
        let current = minimal_config();
        let mut candidate = current.clone();
        candidate.max_socks_connections = Some(current.max_socks_connections() + 1);

        let error = ensure_reload_compatible(&current, &candidate)
            .unwrap_err()
            .to_string();

        assert!(error.contains("max_socks_connections"));
        assert!(error.contains("requires a restart"));
    }

    #[test]
    fn client_reload_rejects_observability_listener_changes() {
        let current = minimal_config();
        let mut candidate = current.clone();
        candidate.observability_listen = Some("127.0.0.1:9091".to_owned());

        let error = ensure_reload_compatible(&current, &candidate)
            .unwrap_err()
            .to_string();

        assert!(error.contains("observability_listen"));
        assert!(error.contains("requires a restart"));
    }

    #[test]
    fn client_reload_accepts_equivalent_effective_listener_settings() {
        let current = minimal_config();
        let mut candidate = current.clone();
        candidate.socks_handshake_timeout_seconds = Some(current.socks_handshake_timeout_seconds());
        candidate.shutdown_timeout_seconds = Some(current.shutdown_timeout_seconds());
        candidate.max_socks_connections = Some(current.max_socks_connections());

        assert!(ensure_reload_compatible(&current, &candidate).is_ok());
    }

    #[test]
    fn unrepresentable_retry_delay_expiry_is_treated_as_non_expiring() {
        assert_eq!(retry_delay_expires_at(Duration::MAX), None);
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
    fn caps_tcp_data_frame_size_to_peer_limit() {
        assert_eq!(
            tcp_data_frame_size(FrameLimits {
                max_frame_size: 1024
            }),
            1024
        );
        assert_eq!(
            tcp_data_frame_size(FrameLimits {
                max_frame_size: 65_536
            }),
            RELAY_BUFFER_SIZE
        );
    }

    #[test]
    fn udp_payload_frame_limit_allows_boundary_only() {
        assert!(!udp_payload_exceeds_frame_limit(512, 512));
        assert!(udp_payload_exceeds_frame_limit(513, 512));
    }

    #[test]
    fn late_udp_flow_completion_does_not_match_replacement() {
        assert!(!udp_flow_id_matches(Some(3), 1));
        assert!(udp_flow_id_matches(Some(3), 3));
        assert!(!udp_flow_id_matches(None, 3));
    }

    #[test]
    fn derives_keepalive_interval_from_idle_timeout() {
        let settings = negotiated_settings_with_idle_timeout(30);

        assert_eq!(keepalive_interval(settings), Some(Duration::from_secs(15)));
    }

    #[test]
    fn keeps_one_second_idle_timeout_before_deadline() {
        let settings = negotiated_settings_with_idle_timeout(1);

        assert_eq!(
            keepalive_interval(settings),
            Some(Duration::from_millis(500))
        );
    }

    #[test]
    fn disables_keepalive_for_zero_idle_timeout() {
        let settings = negotiated_settings_with_idle_timeout(0);

        assert_eq!(keepalive_interval(settings), None);
    }

    #[test]
    fn accepts_client_connection_state_transitions() {
        let valid = [
            (
                ClientConnectionState::NegotiatingSocks,
                ClientConnectionState::Opening,
            ),
            (
                ClientConnectionState::NegotiatingSocks,
                ClientConnectionState::Relaying,
            ),
            (
                ClientConnectionState::NegotiatingSocks,
                ClientConnectionState::Closed,
            ),
            (
                ClientConnectionState::Opening,
                ClientConnectionState::Relaying,
            ),
            (
                ClientConnectionState::Opening,
                ClientConnectionState::Closing,
            ),
            (
                ClientConnectionState::Opening,
                ClientConnectionState::Closed,
            ),
            (
                ClientConnectionState::Relaying,
                ClientConnectionState::Closing,
            ),
            (
                ClientConnectionState::Relaying,
                ClientConnectionState::Closed,
            ),
            (
                ClientConnectionState::Closing,
                ClientConnectionState::Closed,
            ),
        ];

        for (from, next) in valid {
            assert!(is_valid_connection_transition(from, next));
        }
    }

    #[test]
    fn rejects_client_connection_state_regressions() {
        assert!(!is_valid_connection_transition(
            ClientConnectionState::Relaying,
            ClientConnectionState::Opening
        ));
        assert!(!is_valid_connection_transition(
            ClientConnectionState::Closed,
            ClientConnectionState::Relaying
        ));
    }

    #[test]
    fn flow_frame_queue_capacity_tracks_byte_limit() {
        // A tiny byte limit falls back to the floor.
        assert_eq!(
            flow_frame_queue_capacity(1024),
            FLOW_FRAME_QUEUE_MIN_CAPACITY
        );
        // The default 2 MiB per-flow limit derives a queue the byte budget can
        // fill (2 MiB / 1 KiB), far above the old fixed depth of 32.
        assert_eq!(flow_frame_queue_capacity(2 * 1024 * 1024), 2048);
        // A large limit is clamped to the ceiling.
        assert_eq!(
            flow_frame_queue_capacity(64 * 1024 * 1024),
            FLOW_FRAME_QUEUE_MAX_CAPACITY
        );
    }

    #[test]
    fn flow_admission_reserves_up_to_the_stream_ceiling() {
        let admission = FlowAdmissionControl::new(2, 2);

        let first = admission.try_admit(FlowProtocol::Tcp).unwrap();
        let second = admission.try_admit(FlowProtocol::Tcp).unwrap();

        assert_eq!(admission.available_streams(), 0);
        assert_eq!(
            admission.try_admit(FlowProtocol::Tcp).unwrap_err(),
            AdmissionRefusal::StreamLimit
        );

        drop(first);
        assert_eq!(admission.available_streams(), 1);
        assert!(admission.try_admit(FlowProtocol::Tcp).is_ok());
        drop(second);
    }

    #[test]
    fn concurrent_flow_admission_never_oversubscribes_a_session() {
        // The old "read `flow_count()`, reserve later" shape let every waiting
        // opener observe spare capacity; reservation at selection time cannot.
        let admission = FlowAdmissionControl::new(64, 64);
        let slots: Vec<FlowSlot> = (0..200)
            .filter_map(|_| admission.try_admit(FlowProtocol::Tcp).ok())
            .collect();

        assert_eq!(slots.len(), 64);
        assert_eq!(admission.available_streams(), 0);

        drop(slots);
        assert_eq!(admission.available_streams(), 64);
    }

    #[test]
    fn udp_admission_consumes_both_ceilings() {
        let admission = FlowAdmissionControl::new(4, 1);

        let slot = admission.try_admit(FlowProtocol::Udp).unwrap();

        assert_eq!(admission.available_streams(), 3);
        assert_eq!(admission.available_udp_flows(), 0);

        drop(slot);
        assert_eq!(admission.available_streams(), 4);
        assert_eq!(admission.available_udp_flows(), 1);
    }

    #[test]
    fn refused_udp_admission_releases_the_stream_slot() {
        let admission = FlowAdmissionControl::new(4, 1);
        let _held = admission.try_admit(FlowProtocol::Udp).unwrap();

        assert_eq!(
            admission.try_admit(FlowProtocol::Udp).unwrap_err(),
            AdmissionRefusal::UdpFlowLimit
        );
        // The stream permit taken before the UDP ceiling was checked must not
        // be leaked, or repeated UDP refusals would starve TCP flows.
        assert_eq!(admission.available_streams(), 3);
        assert!(admission.try_admit(FlowProtocol::Tcp).is_ok());
    }

    #[test]
    fn tcp_admission_ignores_the_udp_flow_ceiling() {
        let admission = FlowAdmissionControl::new(4, 0);

        assert_eq!(
            admission.try_admit(FlowProtocol::Udp).unwrap_err(),
            AdmissionRefusal::UdpFlowLimit
        );
        assert!(admission.try_admit(FlowProtocol::Tcp).is_ok());
    }

    #[test]
    fn clamps_unrepresentable_flow_ceilings_to_the_semaphore_limit() {
        assert_eq!(semaphore_permits(0), 0);
        assert_eq!(semaphore_permits(64), 64);
        assert_eq!(semaphore_permits(u64::MAX), Semaphore::MAX_PERMITS);
    }

    #[tokio::test]
    async fn session_admission_reserves_a_slot_on_a_live_session() {
        let session = test_session(1, 1);

        let admission = session.try_admit(FlowProtocol::Tcp).unwrap();

        assert!(Arc::ptr_eq(&admission.session, &session));
        assert!(matches!(
            session.try_admit(FlowProtocol::Tcp),
            Err(AdmissionRefusal::StreamLimit)
        ));

        drop(admission);
        assert!(session.try_admit(FlowProtocol::Tcp).is_ok());
    }

    #[tokio::test]
    async fn draining_or_closed_sessions_admit_no_flows() {
        let draining = test_session(4, 4);
        draining.begin_drain().await;
        assert!(matches!(
            draining.try_admit(FlowProtocol::Tcp),
            Err(AdmissionRefusal::Unavailable)
        ));

        let closed = test_session(4, 4);
        closed.close().await;
        assert!(matches!(
            closed.try_admit(FlowProtocol::Tcp),
            Err(AdmissionRefusal::Unavailable)
        ));
    }

    #[tokio::test]
    async fn manager_admits_flows_on_the_least_loaded_pooled_session() {
        let manager = test_session_manager(minimal_config());
        let busy = test_session(4, 4);
        let idle = test_session(4, 4);
        // Give `busy` a flow so the ranking has something to order by.
        assert!(
            busy.reserve_flow(FlowProtocol::Tcp)
                .await
                .unwrap()
                .is_some()
        );
        manager
            .pool
            .lock()
            .await
            .extend([Arc::clone(&busy), Arc::clone(&idle)]);

        let admission = manager.admit_flow(FlowProtocol::Tcp).await.unwrap();

        assert!(Arc::ptr_eq(&admission.session, &idle));
    }

    #[tokio::test]
    async fn manager_falls_through_to_the_next_session_when_one_is_saturated() {
        let manager = test_session_manager(minimal_config());
        let full = test_session(1, 1);
        let spare = test_session(4, 4);
        let _held = full.try_admit(FlowProtocol::Tcp).unwrap();
        manager
            .pool
            .lock()
            .await
            .extend([Arc::clone(&full), Arc::clone(&spare)]);

        let admission = manager.admit_flow(FlowProtocol::Tcp).await.unwrap();

        assert!(Arc::ptr_eq(&admission.session, &spare));
    }

    #[tokio::test]
    async fn manager_rejects_new_flows_when_the_whole_pool_is_saturated() {
        let mut config = minimal_config();
        config.max_carrier_sessions = Some(1);
        let manager = test_session_manager(config);
        let full = test_session(1, 1);
        let _held = full.try_admit(FlowProtocol::Tcp).unwrap();
        manager.pool.lock().await.push(Arc::clone(&full));

        // Genuine exhaustion, not a lost race: no dial past
        // `max_carrier_sessions` and no error, so the caller replies to SOCKS.
        let admission = manager
            .admission_for_new_flow(FlowProtocol::Tcp)
            .await
            .unwrap();

        assert!(admission.is_none());
    }

    #[tokio::test]
    async fn manager_rejects_udp_flows_at_the_per_session_udp_ceiling() {
        // `max_carrier_sessions` still has room, but `max_udp_flows` is a
        // per-session server limit: dialling another carrier to get around it
        // would work around the server's policy, so reject instead. (The pool
        // is deliberately left able to grow, and `minimal_config` cannot dial,
        // so a dial attempt would surface as an error rather than `None`.)
        let manager = test_session_manager(minimal_config());
        let session = test_session(4, 1);
        let _held = session.try_admit(FlowProtocol::Udp).unwrap();
        manager.pool.lock().await.push(Arc::clone(&session));

        let admission = manager
            .admission_for_new_flow(FlowProtocol::Udp)
            .await
            .unwrap();

        assert!(admission.is_none());
        // A TCP flow is still admitted on the same session.
        assert!(
            manager
                .admission_for_new_flow(FlowProtocol::Tcp)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn manager_admits_without_dialling_while_the_pool_has_capacity() {
        // `minimal_config` cannot connect (its CA file is missing), so an
        // admission that succeeds here proves no dial was attempted.
        let manager = test_session_manager(minimal_config());
        manager.pool.lock().await.push(test_session(4, 4));

        assert!(
            manager
                .admission_for_new_flow(FlowProtocol::Udp)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn cancelled_pending_session_is_torn_down() {
        let session = test_session(4, 4);

        drop(PendingClientSession::new(Arc::clone(&session)));

        // `Drop` cannot await, so the teardown is handed to the runtime.
        for _ in 0..100 {
            if session.is_closed() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(session.is_closed());
    }

    #[tokio::test]
    async fn pooled_pending_session_is_not_torn_down() {
        let session = test_session(4, 4);
        let pending = PendingClientSession::new(Arc::clone(&session));

        let published = pending.into_session();

        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        assert!(Arc::ptr_eq(&published, &session));
        assert!(!session.is_closed());
    }

    #[tokio::test]
    async fn explicitly_closed_pending_session_is_torn_down() {
        let session = test_session(4, 4);

        PendingClientSession::new(Arc::clone(&session))
            .close_and_wait()
            .await;

        assert!(session.is_closed());
    }

    #[tokio::test]
    async fn local_write_finishes_the_payload_before_honouring_shutdown() {
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let (mut writer, mut reader) = tokio::io::duplex(4);
        let payload = vec![0x42_u8; 1024];
        let task = tokio::spawn(async move {
            write_all_or_shutdown(&mut writer, &payload, &mut shutdown_rx).await
        });

        shutdown_tx.send(true).unwrap();

        // The whole payload lands even though shutdown was signalled mid-write;
        // a cancelled `write_all` would have left a short, unknown-length prefix
        // behind an otherwise clean FIN.
        let mut received = vec![0_u8; 1024];
        tokio::time::timeout(Duration::from_secs(1), reader.read_exact(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, vec![0x42_u8; 1024]);

        let keep_relaying = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(!keep_relaying);
    }

    /// A local peer that stops reading must not hold shutdown open forever: the
    /// in-flight write gets a bounded grace period and then fails the flow,
    /// rather than blocking or capping a short write with a clean FIN.
    #[tokio::test]
    async fn local_write_gives_up_on_a_local_peer_that_stops_reading() {
        let grace = Duration::from_millis(50);
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let (mut writer, _reader) = tokio::io::duplex(1);
        let payload = vec![0x42_u8; 1024];
        let task = tokio::spawn(async move {
            write_all_or_shutdown_within(&mut writer, &payload, &mut shutdown_rx, grace).await
        });

        shutdown_tx.send(true).unwrap();

        let err = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the write must not outlive the grace period")
            .unwrap()
            .unwrap_err();

        assert!(
            err.to_string().contains("timed out flushing local socket"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn local_write_keeps_relaying_without_shutdown() {
        let (_shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let (mut writer, mut reader) = tokio::io::duplex(64);

        let keep_relaying = write_all_or_shutdown(&mut writer, b"payload", &mut shutdown_rx)
            .await
            .unwrap();

        let mut received = [0_u8; 7];
        reader.read_exact(&mut received).await.unwrap();
        assert!(keep_relaying);
        assert_eq!(&received, b"payload");
    }

    #[tokio::test]
    async fn shutdown_flushes_already_buffered_frames_before_closing_local() {
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        let (sender, mut frames) = mpsc::channel(4);
        let metrics = ClientMetrics::default();
        for payload in [b"first".as_slice(), b"second".as_slice()] {
            sender
                .try_send(buffered_flow_frame(data_frame(
                    FLOW_ID,
                    Bytes::copy_from_slice(payload),
                )))
                .unwrap();
        }
        drop(sender);

        flush_buffered_frames_before_shutdown(&mut writer, &mut frames, &metrics)
            .await
            .unwrap();
        writer.shutdown().await.unwrap();

        let mut received = Vec::new();
        reader.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"firstsecond");
    }

    #[tokio::test]
    async fn shutdown_flush_stops_at_a_non_data_frame() {
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        let (sender, mut frames) = mpsc::channel(4);
        let metrics = ClientMetrics::default();
        sender
            .try_send(buffered_flow_frame(data_frame(
                FLOW_ID,
                Bytes::from_static(b"first"),
            )))
            .unwrap();
        sender
            .try_send(buffered_flow_frame(close_frame(TCP_CLOSE_NORMAL)))
            .unwrap();
        drop(sender);

        flush_buffered_frames_before_shutdown(&mut writer, &mut frames, &metrics)
            .await
            .unwrap();
        writer.shutdown().await.unwrap();

        let mut received = Vec::new();
        reader.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"first");
    }

    #[tokio::test]
    async fn shutdown_flush_is_a_no_op_without_buffered_frames() {
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        let (_sender, mut frames) = mpsc::channel(1);
        let metrics = ClientMetrics::default();

        flush_buffered_frames_before_shutdown(&mut writer, &mut frames, &metrics)
            .await
            .unwrap();
        writer.shutdown().await.unwrap();

        let mut received = Vec::new();
        reader.read_to_end(&mut received).await.unwrap();
        assert!(received.is_empty());
    }
}
