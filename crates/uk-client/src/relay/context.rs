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
use super::listener::*;
use super::session_manager::*;
use super::tcp::*;
use super::udp::*;
use crate::{
    ClientReloadReceiver, ClientReloadRequest,
    config::{ClientConfig, validate_endpoint},
    config_state::{ClientConfigSnapshot, ClientConfigState},
    observability::{ActiveFlowGuard, ClientMetrics, RelayDirection, RelayProtocol},
    session, socks5,
};
pub(crate) const FLOW_ID_ALLOCATION_ATTEMPTS: usize = 1024;
/// Floor, ceiling, and nominal frame size used to size a flow's inbound frame
/// queue from its byte limit (see [`flow_frame_queue_capacity`]).
pub(crate) const FLOW_FRAME_QUEUE_MIN_CAPACITY: usize = 64;
pub(crate) const FLOW_FRAME_QUEUE_MAX_CAPACITY: usize = 8192;
pub(crate) const FLOW_FRAME_QUEUE_NOMINAL_FRAME_BYTES: usize = 1024;
pub(crate) const UDP_ASSOCIATION_EVENT_QUEUE_CAPACITY: usize = 128;

/// Depth of a flow's inbound frame queue, derived from its per-flow byte limit
/// so the configured byte budget — not a small fixed frame count — governs when
/// an overwhelmed flow is shed. Memory stays bounded by the byte accounting
/// (`BufferedFlowFrame` reserves and releases against the byte limits), so a
/// deeper queue only raises the shed threshold for a momentarily-slow consumer.
pub(crate) fn flow_frame_queue_capacity(max_buffered_bytes_per_flow: usize) -> usize {
    (max_buffered_bytes_per_flow / FLOW_FRAME_QUEUE_NOMINAL_FRAME_BYTES)
        .clamp(FLOW_FRAME_QUEUE_MIN_CAPACITY, FLOW_FRAME_QUEUE_MAX_CAPACITY)
}
pub(crate) const UDP_SEND_ATTEMPTS: usize = 2;
pub(crate) const RELAY_BUFFER_SIZE: usize = 16 * 1024;
pub(crate) const UDP_ASSOCIATION_BUFFER_SIZE: usize = 65_536;
pub(crate) const ACCEPT_RETRY_BASE_MILLIS: u64 = 10;
pub(crate) const ACCEPT_RETRY_MAX_MILLIS: u64 = 1_000;
pub(crate) const SERVER_CONNECT_RETRY_MAX_MILLIS: u64 = 30_000;
pub(crate) static NEXT_SOCKS_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);
pub(crate) static NEXT_CLIENT_SESSION_ID: AtomicU64 = AtomicU64::new(1);

pub(crate) type AnyError = Box<dyn Error + Send + Sync>;
pub(crate) type CarrierWriter = Arc<Mutex<BoxedCarrierWriter>>;
pub(crate) type FlowTable = Arc<Mutex<HashMap<u64, ClientFlowRoute>>>;

#[derive(Default)]
pub(crate) struct ListenerAcceptBackoff {
    pub(crate) consecutive_failures: u32,
}

impl ListenerAcceptBackoff {
    pub(crate) fn next_delay(&mut self) -> Duration {
        let shift = self.consecutive_failures.min(7);
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        Duration::from_millis(
            ACCEPT_RETRY_BASE_MILLIS
                .saturating_mul(1_u64 << shift)
                .min(ACCEPT_RETRY_MAX_MILLIS),
        )
    }

    pub(crate) fn reset(&mut self) {
        self.consecutive_failures = 0;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientConnectionState {
    NegotiatingSocks,
    Opening,
    Relaying,
    Closing,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeepalivePong {
    Matched(u64),
    InvalidPayload,
    Unexpected { nonce: u64, expected_nonce: u64 },
}

#[derive(Clone, Debug)]
pub(crate) struct CachedConnectFailure {
    pub(crate) generation: u64,
    pub(crate) message: Arc<str>,
    pub(crate) expires_at: Option<time::Instant>,
}

#[derive(Debug)]
pub(crate) struct CachedConnectFailureError {
    pub(crate) message: Arc<str>,
}

#[derive(Debug)]
pub(crate) struct SessionDrainingError;

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
pub(crate) struct PendingClientSession {
    pub(crate) session: Option<Arc<ClientSession>>,
}

pub(crate) struct ClientSessionTasks {
    pub(crate) tasks: JoinSet<ClientSessionTaskKind>,
    pub(crate) kinds: HashMap<Id, ClientSessionTaskKind>,
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
    pub(crate) fn new(session: Arc<ClientSession>) -> Self {
        Self {
            session: Some(session),
        }
    }

    /// Publishes the session to the caller, disarming the guard.
    pub(crate) fn into_session(mut self) -> Arc<ClientSession> {
        self.session
            .take()
            .expect("pending client session is taken exactly once")
    }

    /// Tears the session down on a path that can await, avoiding the spawned
    /// fallback in [`Drop`].
    #[allow(dead_code)]
    pub(crate) async fn close_and_wait(mut self) {
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
    pub(crate) fn spawn<F>(&mut self, kind: ClientSessionTaskKind, task: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let handle = self.tasks.spawn(async move {
            task.await;
            kind
        });
        self.kinds.insert(handle.id(), kind);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        self.tasks.len()
    }

    pub(crate) async fn join_next(&mut self) {
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

    pub(crate) async fn join_all(&mut self) {
        while !self.is_empty() {
            self.join_next().await;
        }
    }

    pub(crate) fn abort_all(&mut self) {
        self.tasks.abort_all();
    }
}

pub(crate) struct ClientFlow {
    pub(crate) id: u64,
    pub(crate) frames: mpsc::Receiver<BufferedFlowFrame>,
    pub(crate) session: Arc<ClientSession>,
    pub(crate) pending_local_data: Vec<Bytes>,
    pub(crate) metric_guard: Option<ActiveFlowGuard>,
    /// Session admission slot held for the flow's whole life; dropping the flow
    /// returns the capacity to its session (see [`FlowAdmissionControl`]).
    pub(crate) _slot: FlowSlot,
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
pub(crate) struct FlowAdmissionControl {
    pub(crate) streams: Arc<Semaphore>,
    pub(crate) udp_flows: Arc<Semaphore>,
}

/// A reserved flow slot. Dropping it returns the capacity to its session.
#[derive(Debug)]
pub(crate) struct FlowSlot {
    pub(crate) _stream: OwnedSemaphorePermit,
    pub(crate) _udp_flow: Option<OwnedSemaphorePermit>,
}

/// A flow slot already reserved on a specific session, handed from session
/// selection to the open path.
pub(crate) struct FlowAdmission {
    pub(crate) session: Arc<ClientSession>,
    pub(crate) slot: FlowSlot,
}

/// Why one session refused to admit a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdmissionRefusal {
    /// The session is draining or closed.
    Unavailable,
    /// The session is at the negotiated `max_streams`.
    StreamLimit,
    /// The session has stream capacity but is at `max_udp_flows`.
    UdpFlowLimit,
}

/// Why no pooled session could admit a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PoolAdmissionRefusal {
    /// No live session has stream capacity, so growing the pool may help.
    StreamLimit,
    /// A live session has stream capacity but is at `max_udp_flows`. That is a
    /// per-session server limit, so dialling another carrier to work around it
    /// is not the client's call — reject the request instead.
    UdpFlowLimit,
}

impl FlowAdmissionControl {
    pub(crate) fn new(max_streams: u64, max_udp_flows: u64) -> Self {
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
    pub(crate) fn try_admit(&self, protocol: FlowProtocol) -> Result<FlowSlot, AdmissionRefusal> {
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
    pub(crate) fn available_streams(&self) -> usize {
        self.streams.available_permits()
    }

    #[cfg(test)]
    pub(crate) fn available_udp_flows(&self) -> usize {
        self.udp_flows.available_permits()
    }
}

/// Clamps a negotiated flow ceiling to what a [`Semaphore`] can represent.
pub(crate) fn semaphore_permits(limit: u64) -> usize {
    usize::try_from(limit)
        .unwrap_or(Semaphore::MAX_PERMITS)
        .min(Semaphore::MAX_PERMITS)
}

pub(crate) enum UdpAssociationFlowEvent {
    Activity {
        session_id: u64,
        flow_id: u64,
        target: Target,
    },
}

pub(crate) enum UdpAssociationFlowLookup {
    Open(UdpAssociationFlow),
    NoFlow,
    Cancelled,
}

pub(crate) enum OpenOutcome {
    Open(ClientFlow),
    Rejected(socks5::Reply),
    Cancelled,
}

pub(crate) enum OpenWaitOutcome {
    Frame(Frame),
    Cancelled,
    TimedOut,
    LocalResourceLimit,
}

pub(crate) enum UdpOpenWaitOutcome {
    Frame(Frame),
    Cancelled,
    TimedOut,
}

pub(crate) enum PendingOpenLocalRead {
    Buffered,
    Closed,
    ResourceLimit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpenResponse {
    Accepted,
    Rejected(socks5::Reply),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlowFrameRoute {
    InvalidFlowId,
    UnknownFlow,
    ProtocolMismatch,
    Enqueued,
    FlowClosed,
    FlowQueueFull,
    SessionQueueFull,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlowProtocol {
    Tcp,
    Udp,
}

impl FlowProtocol {
    pub(crate) const fn metric_protocol(self) -> RelayProtocol {
        match self {
            Self::Tcp => RelayProtocol::Tcp,
            Self::Udp => RelayProtocol::Udp,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientSessionMetricState {
    Active,
    Draining,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientSessionTaskKind {
    CarrierReader,
    DatagramReader,
    Keepalive,
}

#[derive(Debug, Clone)]
pub(crate) struct ClientFlowRoute {
    pub(crate) sender: mpsc::Sender<BufferedFlowFrame>,
    pub(crate) flow_buffer: ClientFlowBufferControl,
    pub(crate) protocol: FlowProtocol,
}

#[derive(Debug, Clone)]
pub(crate) struct ClientSessionBufferControl {
    pub(crate) buffered_bytes: Arc<AtomicUsize>,
}

#[derive(Debug, Clone)]
pub(crate) struct ClientFlowBufferControl {
    pub(crate) buffered_bytes: Arc<AtomicUsize>,
}

#[derive(Debug)]
pub(crate) struct BufferedFlowFrame {
    pub(crate) frame: Option<Frame>,
    pub(crate) payload_len: usize,
    pub(crate) flow_control: ClientFlowBufferControl,
    pub(crate) session_control: ClientSessionBufferControl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BufferReserveError {
    FlowLimit,
    SessionLimit,
}

#[derive(Clone)]
pub(crate) struct ClientSessionShutdown {
    pub(crate) closed: Arc<AtomicBool>,
    pub(crate) notify: Arc<Notify>,
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
    pub(crate) fn close(&self) -> bool {
        if self.closed.swap(true, Ordering::SeqCst) {
            false
        } else {
            self.notify.notify_waiters();
            true
        }
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    pub(crate) async fn closed(&self) {
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
    pub(crate) fn reserve_bytes(&self, amount: usize, limit: usize) -> bool {
        reserve_bytes(&self.buffered_bytes, amount, limit)
    }

    pub(crate) fn release_bytes(&self, amount: usize) {
        release_bytes(&self.buffered_bytes, amount);
    }

    #[cfg(test)]
    pub(crate) fn buffered_bytes(&self) -> usize {
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
    pub(crate) fn reserve_bytes(&self, amount: usize, limit: usize) -> bool {
        reserve_bytes(&self.buffered_bytes, amount, limit)
    }

    pub(crate) fn release_bytes(&self, amount: usize) {
        release_bytes(&self.buffered_bytes, amount);
    }

    #[cfg(test)]
    pub(crate) fn buffered_bytes(&self) -> usize {
        self.buffered_bytes.load(Ordering::SeqCst)
    }
}

impl ClientFlowRoute {
    pub(crate) fn new(sender: mpsc::Sender<BufferedFlowFrame>, protocol: FlowProtocol) -> Self {
        Self {
            sender,
            flow_buffer: ClientFlowBufferControl::default(),
            protocol,
        }
    }
}

impl BufferedFlowFrame {
    pub(crate) fn new(
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

    pub(crate) fn into_frame(mut self) -> Result<Frame, AnyError> {
        self.release();
        self.frame
            .take()
            .ok_or_else(|| "buffered frame missing".into())
    }

    pub(crate) fn release(&mut self) {
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

#[derive(Default)]
pub(crate) struct PendingOpenLocalData {
    pub(crate) chunks: Vec<Bytes>,
    pub(crate) queued_bytes: usize,
    pub(crate) scratch: Vec<u8>,
}

impl PendingOpenLocalData {
    pub(crate) fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }

    pub(crate) fn take_chunks(&mut self) -> Vec<Bytes> {
        self.queued_bytes = 0;
        std::mem::take(&mut self.chunks)
    }

    pub(crate) async fn read_from(
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

pub(crate) fn keepalive_interval(settings: NegotiatedSettings) -> Option<Duration> {
    let idle_timeout_seconds = settings.idle_timeout_seconds;
    if idle_timeout_seconds == 0 {
        return None;
    }
    let interval_millis = idle_timeout_seconds.saturating_mul(1000).saturating_div(2);
    Some(Duration::from_millis(interval_millis.max(1)))
}

pub(crate) fn tcp_data_frame_size(limits: FrameLimits, relay_buffer_size: Option<usize>) -> usize {
    let buf_size = relay_buffer_size.unwrap_or(RELAY_BUFFER_SIZE);
    usize::try_from(limits.max_frame_size).map_or(buf_size, |limit| limit.min(buf_size))
}

pub(crate) fn reserve_bytes(buffered_bytes: &AtomicUsize, amount: usize, limit: usize) -> bool {
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

pub(crate) fn release_bytes(buffered_bytes: &AtomicUsize, amount: usize) {
    // Written as an explicit compare-exchange loop rather than
    // `fetch_update`/`try_update`: the former is deprecated on recent
    // toolchains while the latter is not stable on the 1.85 MSRV, so no
    // single method name is warning-free on both.
    let mut current = buffered_bytes.load(Ordering::SeqCst);
    loop {
        let next = current.saturating_sub(amount);
        match buffered_bytes.compare_exchange_weak(
            current,
            next,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => return,
            Err(actual) => current = actual,
        }
    }
}

pub(crate) fn usize_limit(value: u64) -> Result<usize, AnyError> {
    Ok(usize::try_from(value).map_err(|_| "limit is too large for this platform")?)
}

pub(crate) fn timeout(seconds: u64) -> Option<Duration> {
    (seconds != 0).then(|| Duration::from_secs(seconds))
}

pub(crate) fn retry_delay(milliseconds: u64) -> Option<Duration> {
    (milliseconds != 0).then(|| Duration::from_millis(milliseconds))
}

pub(crate) fn retry_delay_expires_at(delay: Duration) -> Option<time::Instant> {
    time::Instant::now().checked_add(delay)
}

pub(crate) fn cached_connect_failure_error(failure: CachedConnectFailure) -> AnyError {
    Box::new(CachedConnectFailureError {
        message: failure.message,
    })
}

pub(crate) fn is_session_draining_error(error: &AnyError) -> bool {
    error
        .as_ref()
        .downcast_ref::<SessionDrainingError>()
        .is_some()
}

pub(crate) fn transition(state: &mut ClientConnectionState, next: ClientConnectionState) {
    let from = *state;
    debug_assert!(
        is_valid_connection_transition(from, next),
        "invalid client connection state transition"
    );
    debug!(event = "client.connection.state", from = ?from, to = ?next);
    *state = next;
}

pub(crate) const fn is_valid_connection_transition(
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
