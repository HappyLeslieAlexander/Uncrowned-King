//! SOCKS5-to-UK TCP and UDP relay.

use std::{
    collections::{HashMap, hash_map::Entry},
    error::Error,
    fmt,
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Mutex, Notify, Semaphore, mpsc, watch},
    task::JoinSet,
    time,
};
use tokio_rustls::client::TlsStream;
use tracing::{debug, info, warn};
use uk_proto::{
    ErrorCode, ErrorPayload, FIRST_CLIENT_FLOW_ID, FLOW_ID_STEP, Frame, FrameIoError, FrameLimits,
    FrameType, NegotiatedSettings, TCP_CLOSE_ERROR, TCP_CLOSE_NORMAL, TCP_OPEN_FLAGS_NONE, Target,
    TcpClose, TcpOpen, UDP_CLOSE_ERROR, UDP_CLOSE_NORMAL, UdpClose, UdpOpen,
    is_client_initiated_flow_id, read_frame, validate_connection_frame, varint::MAX_VARINT,
    write_frame,
};

use crate::{
    config::{ClientConfig, validate_endpoint},
    session, socks5,
};

const FLOW_ID_ALLOCATION_ATTEMPTS: usize = 1024;
const FLOW_FRAME_QUEUE_CAPACITY: usize = 32;
const UDP_ASSOCIATION_EVENT_QUEUE_CAPACITY: usize = 128;
const RELAY_BUFFER_SIZE: usize = 16 * 1024;
const UDP_ASSOCIATION_BUFFER_SIZE: usize = 65_536;

type AnyError = Box<dyn Error + Send + Sync>;
type CarrierWriter = Arc<Mutex<WriteHalf<TlsStream<TcpStream>>>>;
type FlowTable = Arc<Mutex<HashMap<u64, ClientFlowRoute>>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientConnectionState {
    NegotiatingSocks,
    Opening,
    Relaying,
    Closing,
    Closed,
}

struct ClientSession {
    writer: CarrierWriter,
    flows: FlowTable,
    limits: FrameLimits,
    data_frame_size: usize,
    max_streams: u64,
    max_udp_flows: u64,
    supports_udp_stream_fallback: bool,
    max_pending_open_bytes: usize,
    max_buffered_bytes_per_session: usize,
    max_buffered_bytes_per_flow: usize,
    session_buffer: ClientSessionBufferControl,
    open_timeout: Option<Duration>,
    shutdown: ClientSessionShutdown,
    next_flow_id: AtomicU64,
    next_ping_nonce: AtomicU64,
    last_pong_nonce: AtomicU64,
    pong_notify: Notify,
}

struct ClientSessionManager {
    config: ClientConfig,
    current: Mutex<Option<Arc<ClientSession>>>,
    connect_lock: Mutex<()>,
    recent_connect_failure: Mutex<Option<CachedConnectFailure>>,
    connect_retry_delay: Option<Duration>,
    closed: AtomicBool,
}

#[derive(Clone, Debug)]
struct CachedConnectFailure {
    message: Arc<str>,
    expires_at: Option<time::Instant>,
}

#[derive(Debug)]
struct CachedConnectFailureError {
    message: Arc<str>,
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

struct ClientFlow {
    id: u64,
    frames: mpsc::Receiver<BufferedFlowFrame>,
    session: Arc<ClientSession>,
    pending_local_data: Vec<Bytes>,
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
    run_socks5_listener_on_until_shutdown(config, listener, shutdown).await
}

pub(crate) async fn run_socks5_listener_on_until_shutdown<F>(
    config: ClientConfig,
    listener: TcpListener,
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
    let sessions = Arc::new(ClientSessionManager::new(config));
    let connection_slots = Arc::new(Semaphore::new(max_socks_connections));
    info!(event = "socks5.listen", listen = %listen);

    let (shutdown_tx, _shutdown_rx) = watch::channel(false);
    let mut connections = JoinSet::new();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            () = &mut shutdown => {
                info!(event = "socks5.shutdown");
                let _ = shutdown_tx.send(true);
                break;
            }
            accepted = listener.accept() => {
                let (mut local, peer) = accepted?;
                let Ok(permit) = Arc::clone(&connection_slots).try_acquire_owned() else {
                    warn!(
                        event = "socks5.connection.limit",
                        peer = %peer,
                        max_connections = max_socks_connections
                    );
                    if let Err(err) = local.shutdown().await {
                        debug!(
                            event = "socks5.connection.limit_shutdown_error",
                            peer = %peer,
                            error = %err
                        );
                    }
                    continue;
                };
                let sessions = Arc::clone(&sessions);
                let shutdown_rx = shutdown_tx.subscribe();
                connections.spawn(async move {
                    let _permit = permit;
                    if let Err(err) =
                        handle_socks_connection(
                            local,
                            sessions,
                            socks_handshake_timeout,
                            shutdown_rx,
                        )
                        .await
                    {
                        if is_clean_socks_disconnect(&err) {
                            debug!(event = "socks5.connection.closed", peer = %peer);
                        } else {
                            warn!(event = "socks5.connection.error", peer = %peer, error = %err);
                        }
                    }
                });
            }
            joined = connections.join_next(), if !connections.is_empty() => {
                log_socks_task_result(joined);
            }
        }
    }

    drain_socks_tasks(&mut connections, shutdown_timeout).await;
    sessions.shutdown().await;

    Ok(())
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

impl ClientSessionManager {
    fn new(config: ClientConfig) -> Self {
        let connect_retry_delay = retry_delay(config.server_connect_retry_delay_millis());
        Self {
            config,
            current: Mutex::new(None),
            connect_lock: Mutex::new(()),
            recent_connect_failure: Mutex::new(None),
            connect_retry_delay,
            closed: AtomicBool::new(false),
        }
    }

    async fn open_flow(
        &self,
        target: Target,
        local: &mut TcpStream,
        shutdown_rx: &mut watch::Receiver<bool>,
    ) -> Result<OpenOutcome, AnyError> {
        if *shutdown_rx.borrow() {
            return Ok(OpenOutcome::Cancelled);
        }
        let mut pending_local_data = PendingOpenLocalData::default();
        let mut last_error = None;
        for attempt in 0..2 {
            let session = tokio::select! {
                result = self.current_session() => result?,
                changed = shutdown_rx.changed() => {
                    let _ = changed;
                    return Ok(OpenOutcome::Cancelled);
                }
            };
            match session
                .open_flow(target.clone(), local, &mut pending_local_data, shutdown_rx)
                .await
            {
                Ok(outcome) => return Ok(outcome),
                Err(err) => {
                    warn!(
                        event = "client.session.open.error",
                        attempt,
                        error = %err
                    );
                    self.invalidate(&session).await;
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
        let mut last_error = None;
        for attempt in 0..2 {
            if *shutdown_rx.borrow() {
                return Ok(OpenOutcome::Cancelled);
            }
            let session = tokio::select! {
                result = self.current_session() => result?,
                changed = shutdown_rx.changed() => {
                    let _ = changed;
                    return Ok(OpenOutcome::Cancelled);
                }
            };
            match session
                .open_udp_flow(target.clone(), local, tcp_buf, shutdown_rx)
                .await
            {
                Ok(outcome) => return Ok(outcome),
                Err(err) => {
                    warn!(
                        event = "client.session.udp_open.error",
                        attempt,
                        error = %err
                    );
                    self.invalidate(&session).await;
                    last_error = Some(err);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| "failed to open uk udp flow".into()))
    }

    async fn current_session(&self) -> Result<Arc<ClientSession>, AnyError> {
        if self.is_closed() {
            return Err("client session manager is shutting down".into());
        }
        if let Some(session) = self.current_session_if_live().await {
            return Ok(session);
        }
        if let Some(failure) = self.recent_connect_failure_if_active().await {
            return Err(cached_connect_failure_error(failure));
        }

        let _connect_guard = self.connect_lock.lock().await;
        if self.is_closed() {
            return Err("client session manager is shutting down".into());
        }
        if let Some(session) = self.current_session_if_live().await {
            return Ok(session);
        }
        if let Some(failure) = self.recent_connect_failure_if_active().await {
            return Err(cached_connect_failure_error(failure));
        }

        info!(event = "client.session.connect");
        let session = match ClientSession::connect(&self.config).await {
            Ok(session) => session,
            Err(err) => {
                self.remember_connect_failure(&err).await;
                return Err(err);
            }
        };
        self.clear_connect_failure().await;
        if self.is_closed() {
            session.close().await;
            return Err("client session manager is shutting down".into());
        }
        let mut current = self.current.lock().await;
        if self.is_closed() {
            drop(current);
            session.close().await;
            return Err("client session manager is shutting down".into());
        }
        *current = Some(Arc::clone(&session));
        Ok(session)
    }

    async fn current_session_if_live(&self) -> Option<Arc<ClientSession>> {
        let mut current = self.current.lock().await;
        if let Some(session) = current.as_ref() {
            if !session.is_closed() {
                return Some(Arc::clone(session));
            }
        }

        *current = None;
        None
    }

    async fn recent_connect_failure_if_active(&self) -> Option<CachedConnectFailure> {
        let mut recent = self.recent_connect_failure.lock().await;
        let failure = recent.as_ref()?;
        if let Some(expires_at) = failure.expires_at {
            if time::Instant::now() >= expires_at {
                *recent = None;
                return None;
            }
        }

        Some(failure.clone())
    }

    async fn remember_connect_failure(&self, error: &AnyError) {
        let Some(delay) = self.connect_retry_delay else {
            return;
        };
        let mut recent = self.recent_connect_failure.lock().await;
        *recent = Some(CachedConnectFailure {
            message: Arc::from(error.to_string()),
            expires_at: retry_delay_expires_at(delay),
        });
    }

    async fn clear_connect_failure(&self) {
        *self.recent_connect_failure.lock().await = None;
    }

    async fn invalidate(&self, session: &Arc<ClientSession>) {
        session.close().await;
        let mut current = self.current.lock().await;
        if current
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, session))
        {
            *current = None;
        }
    }

    async fn shutdown(&self) {
        self.closed.store(true, Ordering::SeqCst);
        let session = { self.current.lock().await.take() };
        if let Some(session) = session {
            session.close().await;
        }
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    async fn supports_udp_stream_fallback(&self) -> Result<bool, AnyError> {
        Ok(self.current_session().await?.supports_udp_stream_fallback)
    }

    fn udp_flow_idle_timeout(&self) -> Option<Duration> {
        timeout(self.config.udp_flow_idle_timeout_seconds())
    }
}

impl ClientSession {
    async fn connect(config: &ClientConfig) -> Result<Arc<Self>, AnyError> {
        let (carrier, settings) = session::connect_authenticated(config).await?;
        let negotiated = settings.negotiated_v0_1()?;
        let limits = negotiated.frame_limits();
        let (carrier_reader, carrier_writer) = tokio::io::split(carrier);
        let session_buffer = ClientSessionBufferControl::default();
        let session = Arc::new(Self {
            writer: Arc::new(Mutex::new(carrier_writer)),
            flows: Arc::new(Mutex::new(HashMap::new())),
            limits,
            data_frame_size: tcp_data_frame_size(limits),
            max_streams: negotiated.max_streams,
            max_udp_flows: negotiated.max_udp_flows,
            supports_udp_stream_fallback: negotiated.udp_stream_fallback_enabled(),
            max_pending_open_bytes: usize_limit(config.max_pending_open_bytes())?,
            max_buffered_bytes_per_session: usize_limit(config.max_buffered_bytes_per_session())?,
            max_buffered_bytes_per_flow: usize_limit(config.max_buffered_bytes_per_flow())?,
            session_buffer,
            open_timeout: timeout(config.tcp_open_timeout_seconds()),
            shutdown: ClientSessionShutdown::default(),
            next_flow_id: AtomicU64::new(FIRST_CLIENT_FLOW_ID),
            next_ping_nonce: AtomicU64::new(0),
            last_pong_nonce: AtomicU64::new(0),
            pong_notify: Notify::new(),
        });
        spawn_carrier_reader(carrier_reader, Arc::clone(&session));
        if let Some(interval) = keepalive_interval(negotiated) {
            spawn_keepalive(Arc::clone(&session), interval);
        }
        Ok(session)
    }

    fn is_closed(&self) -> bool {
        self.shutdown.is_closed()
    }

    async fn has_open_flows(&self) -> bool {
        !self.flows.lock().await.is_empty()
    }

    async fn close(&self) {
        if self.shutdown.close() {
            self.pong_notify.notify_waiters();
            self.flows.lock().await.clear();
            let mut writer = self.writer.lock().await;
            if let Err(err) = writer.shutdown().await {
                debug!(event = "client.session.shutdown.error", error = %err);
            }
        }
    }

    async fn open_flow(
        self: &Arc<Self>,
        target: Target,
        local: &mut TcpStream,
        pending_local_data: &mut PendingOpenLocalData,
        shutdown_rx: &mut watch::Receiver<bool>,
    ) -> Result<OpenOutcome, AnyError> {
        if self.is_closed() {
            return Err("uk session is closed".into());
        }
        let Some((flow_id, frames)) = self.reserve_flow(FlowProtocol::Tcp).await? else {
            return Ok(OpenOutcome::Rejected(socks5::Reply::GeneralFailure));
        };
        if self.is_closed() {
            self.flows.lock().await.remove(&flow_id);
            return Err("uk session is closed".into());
        }

        let send_result = self.send_tcp_open(flow_id, target).await;
        if let Err(err) = send_result {
            self.flows.lock().await.remove(&flow_id);
            return Err(err);
        }

        let mut flow = ClientFlow {
            id: flow_id,
            frames,
            session: Arc::clone(self),
            pending_local_data: Vec::new(),
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
                Ok(OpenOutcome::Open(flow))
            }
            Ok(OpenResponse::Rejected(reply)) => {
                self.flows.lock().await.remove(&flow_id);
                Ok(OpenOutcome::Rejected(reply))
            }
            Err(err) => {
                self.flows.lock().await.remove(&flow_id);
                report_protocol_error(self).await;
                Err(err)
            }
        }
    }

    async fn open_udp_flow(
        self: &Arc<Self>,
        target: Target,
        local: &mut TcpStream,
        tcp_buf: &mut [u8; 1],
        shutdown_rx: &mut watch::Receiver<bool>,
    ) -> Result<OpenOutcome, AnyError> {
        if self.is_closed() {
            return Err("uk session is closed".into());
        }
        if !self.supports_udp_stream_fallback {
            return Ok(OpenOutcome::Rejected(socks5::Reply::GeneralFailure));
        }
        let Some((flow_id, frames)) = self.reserve_flow(FlowProtocol::Udp).await? else {
            return Ok(OpenOutcome::Rejected(socks5::Reply::GeneralFailure));
        };
        if self.is_closed() {
            self.flows.lock().await.remove(&flow_id);
            return Err("uk session is closed".into());
        }

        if let Err(err) = self.send_udp_open(flow_id, target).await {
            self.flows.lock().await.remove(&flow_id);
            return Err(err);
        }

        let mut flow = ClientFlow {
            id: flow_id,
            frames,
            session: Arc::clone(self),
            pending_local_data: Vec::new(),
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
            Ok(OpenResponse::Accepted) => Ok(OpenOutcome::Open(flow)),
            Ok(OpenResponse::Rejected(reply)) => {
                self.flows.lock().await.remove(&flow_id);
                Ok(OpenOutcome::Rejected(reply))
            }
            Err(err) => {
                self.flows.lock().await.remove(&flow_id);
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
        self.flows.lock().await.remove(&flow_id);
        let _ = self.send_tcp_close(flow_id, TCP_CLOSE_ERROR).await;
    }

    async fn cancel_pending_udp_open(&self, flow_id: u64) {
        self.flows.lock().await.remove(&flow_id);
        let _ = self.send_udp_close(flow_id, UDP_CLOSE_ERROR).await;
    }

    async fn reserve_flow(
        &self,
        protocol: FlowProtocol,
    ) -> Result<Option<(u64, mpsc::Receiver<BufferedFlowFrame>)>, AnyError> {
        let (sender, frames) = mpsc::channel(FLOW_FRAME_QUEUE_CAPACITY);
        let mut flows = self.flows.lock().await;
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
        self.write_frame(&frame).await
    }

    async fn send_udp_data(&self, flow_id: u64, payload: Bytes) -> Result<(), AnyError> {
        let frame = Frame::new(FrameType::UdpData, 0, flow_id, payload)?;
        self.write_frame(&frame).await
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
        let frame = Frame::new(FrameType::Ping, 0, 0, keepalive_nonce_payload(nonce))?;
        self.write_frame(&frame).await?;
        Ok(nonce)
    }

    fn observed_pong_nonce(&self) -> u64 {
        self.last_pong_nonce.load(Ordering::SeqCst)
    }

    fn record_pong(&self, payload: &Bytes) {
        let Some(nonce) = decode_keepalive_nonce(payload) else {
            debug!(
                event = "client.session.keepalive.pong_ignored",
                payload_len = payload.len()
            );
            return;
        };
        self.last_pong_nonce.store(nonce, Ordering::SeqCst);
        self.pong_notify.notify_waiters();
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

fn spawn_carrier_reader(
    mut carrier_reader: ReadHalf<TlsStream<TcpStream>>,
    session: Arc<ClientSession>,
) {
    tokio::spawn(async move {
        loop {
            match read_frame(&mut carrier_reader, session.limits).await {
                Ok(frame) => {
                    if let Err(err) = handle_carrier_frame(&session, frame).await {
                        warn!(event = "client.session.frame.error", error = %err);
                        close_session(&session).await;
                        return;
                    }
                }
                Err(err) => {
                    if !matches!(err, FrameIoError::Closed) {
                        warn!(event = "client.session.read.error", error = %err);
                        report_frame_io_error(&session, &err).await;
                    }
                    close_session(&session).await;
                    return;
                }
            }
        }
    });
}

fn spawn_keepalive(session: Arc<ClientSession>, interval: Duration) {
    tokio::spawn(async move {
        loop {
            time::sleep(interval).await;
            if session.is_closed() {
                return;
            }
            if !session.has_open_flows().await {
                continue;
            }
            let nonce = match session.write_ping().await {
                Ok(nonce) => nonce,
                Err(err) => {
                    debug!(event = "client.session.keepalive.error", error = %err);
                    session.close().await;
                    return;
                }
            };
            match time::timeout(interval, session.wait_for_pong(nonce)).await {
                Ok(true) => {}
                Ok(false) => return,
                Err(_) => {
                    if !session.is_closed() {
                        warn!(event = "client.session.keepalive.timeout");
                        session.close().await;
                    }
                    return;
                }
            }
        }
    });
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
        flow_session.flows.lock().await.remove(&flow_id);
        transition(&mut state, ClientConnectionState::Closed);
        return Err(err.into());
    }

    transition(&mut state, ClientConnectionState::Relaying);
    let relay_result = relay_tcp(local, flow, shutdown_rx).await;
    if relay_result.is_err() {
        transition(&mut state, ClientConnectionState::Closing);
        let _ = flow_session.send_tcp_close(flow_id, TCP_CLOSE_ERROR).await;
    }
    flow_session.flows.lock().await.remove(&flow_id);
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

    let supports_udp_stream_fallback = tokio::select! {
        result = sessions.supports_udp_stream_fallback() => result,
        changed = shutdown_rx.changed() => {
            let _ = changed;
            return Ok(());
        }
    };
    match supports_udp_stream_fallback {
        Ok(true) => {}
        Ok(false) => {
            socks5::send_reply(&mut local, socks5::Reply::GeneralFailure).await?;
            return Ok(());
        }
        Err(err) => {
            let _ = socks5::send_reply(&mut local, socks5::Reply::GeneralFailure).await;
            return Err(err);
        }
    }

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
    ) -> Self {
        Self {
            socket,
            idle_timeout,
            flow_event_tx,
            client_endpoint: UdpClientEndpoint::new(client_endpoint),
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
        let max_payload_len = flow.session.data_frame_size;
        if udp_payload_exceeds_frame_limit(datagram.payload.len(), max_payload_len) {
            warn_oversized_udp_datagram(&datagram.target, datagram.payload.len(), max_payload_len);
            return Ok(true);
        }
        flow.session
            .send_udp_data(flow.id, datagram.payload)
            .await?;
        Ok(true)
    }

    fn accept_client_endpoint(&mut self, peer: SocketAddr) -> bool {
        self.client_endpoint.accepts(peer)
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
                session.flows.lock().await.remove(&flow_id);
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
                self.flows_by_target.remove(&result.target);
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
            flow.session.flows.lock().await.remove(&flow.id);
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
                flow.session.flows.lock().await.remove(&flow.id);
            }
        }
    }
}

impl UdpClientEndpoint {
    fn new(requested: socks5::SocksEndpoint) -> Self {
        Self {
            requested,
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

    fn matches_requested(&self, peer: SocketAddr) -> bool {
        match &self.requested {
            socks5::SocksEndpoint::Ipv4(addr, port) => {
                matches_requested_ip_port(peer, IpAddr::V4(*addr), *port)
            }
            socks5::SocksEndpoint::Ipv6(addr, port) => {
                matches_requested_ip_port(peer, IpAddr::V6(*addr), *port)
            }
            socks5::SocksEndpoint::Domain(_, port) => matches_requested_port(peer, *port),
        }
    }
}

fn matches_requested_ip_port(peer: SocketAddr, requested_ip: IpAddr, requested_port: u16) -> bool {
    (requested_ip.is_unspecified() || peer.ip() == requested_ip)
        && matches_requested_port(peer, requested_port)
}

fn matches_requested_port(peer: SocketAddr, requested_port: u16) -> bool {
    requested_port == 0 || peer.port() == requested_port
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
    session.flows.lock().await.remove(&flow_id);
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
                        let packet = socks5::encode_udp_datagram(&target, &frame.payload)?;
                        socket.send_to(&packet, client_endpoint).await?;
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
                        let local_write_open = frame.payload.is_empty()
                            || write_all_or_shutdown(&mut local, &frame.payload, &mut shutdown_rx)
                                .await?;
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

async fn write_all_or_shutdown<W>(
    writer: &mut W,
    payload: &[u8],
    shutdown_rx: &mut watch::Receiver<bool>,
) -> Result<bool, AnyError>
where
    W: AsyncWrite + Unpin,
{
    tokio::select! {
        result = writer.write_all(payload) => {
            result?;
            Ok(true)
        }
        changed = shutdown_rx.changed() => {
            let _ = changed;
            writer.shutdown().await?;
            Ok(false)
        }
    }
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
        }
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
        let mut endpoint = UdpClientEndpoint::new(socks5::SocksEndpoint::Ipv4(
            std::net::Ipv4Addr::UNSPECIFIED,
            0,
        ));

        assert!(endpoint.accepts(first_peer));
        assert_eq!(endpoint.learned(), Some(first_peer));
        assert!(endpoint.accepts(first_peer));
        assert!(!endpoint.accepts(second_peer));
    }

    #[test]
    fn udp_client_endpoint_ignores_peer_that_misses_declared_port() {
        let expected_peer = SocketAddr::from(([127, 0, 0, 1], 41000));
        let wrong_peer = SocketAddr::from(([127, 0, 0, 1], 41001));
        let mut endpoint = UdpClientEndpoint::new(socks5::SocksEndpoint::Ipv4(
            std::net::Ipv4Addr::LOCALHOST,
            expected_peer.port(),
        ));

        assert!(!endpoint.accepts(wrong_peer));
        assert_eq!(endpoint.learned(), None);
        assert!(endpoint.accepts(expected_peer));
        assert_eq!(endpoint.learned(), Some(expected_peer));
    }

    #[test]
    fn udp_client_endpoint_matches_declared_domain_port() {
        let expected_peer = SocketAddr::from(([127, 0, 0, 1], 41000));
        let wrong_peer = SocketAddr::from(([127, 0, 0, 1], 41001));
        let mut endpoint = UdpClientEndpoint::new(socks5::SocksEndpoint::Domain(
            "client.local".to_owned(),
            41000,
        ));

        assert!(!endpoint.accepts(wrong_peer));
        assert!(endpoint.accepts(expected_peer));
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
    async fn local_write_exits_when_shutdown_notifies() {
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let (mut writer, _reader) = tokio::io::duplex(1);
        let payload = vec![0x42; 1024];
        let task = tokio::spawn(async move {
            write_all_or_shutdown(&mut writer, &payload, &mut shutdown_rx).await
        });

        shutdown_tx.send(true).unwrap();
        let wrote_payload = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        assert!(!wrote_payload);
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
        let manager = ClientSessionManager::new(config);

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
        let manager = ClientSessionManager::new(config);

        let first = expect_session_error(manager.current_session().await);
        let second = expect_session_error(manager.current_session().await);

        assert!(!first.to_string().contains("retry cooldown active"));
        assert!(!second.to_string().contains("retry cooldown active"));
    }

    #[tokio::test]
    async fn expired_session_connect_failure_cache_is_cleared() {
        let manager = ClientSessionManager::new(minimal_config());
        *manager.recent_connect_failure.lock().await = Some(CachedConnectFailure {
            message: Arc::from("old failure"),
            expires_at: Some(time::Instant::now() - Duration::from_millis(1)),
        });

        assert!(manager.recent_connect_failure_if_active().await.is_none());
        assert!(manager.recent_connect_failure.lock().await.is_none());
    }

    #[test]
    fn unrepresentable_retry_delay_expiry_is_treated_as_non_expiring() {
        assert_eq!(retry_delay_expires_at(Duration::MAX), None);
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
}
