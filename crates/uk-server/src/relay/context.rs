#![allow(unused_imports, clippy::wildcard_imports)]

use std::{
    collections::HashMap,
    error::Error,
    fmt,
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{
        TcpStream, UdpSocket, lookup_host,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore, mpsc, watch},
    task::{AbortHandle, Id, JoinError, JoinSet},
    time,
};
use tracing::{Instrument, Span, debug, info, warn};
use uk_auth::{AuthenticatedIdentity, unix_now};
use uk_policy::{PolicyContext, PolicyDecision, PolicySet};
use uk_proto::{
    BoxedCarrierReader, BoxedCarrierWriter, BoxedDatagramChannel, DatagramSendOutcome, ErrorCode,
    ErrorPayload, Frame, FrameIoError, FrameLimits, FrameReader, FrameType, TCP_CLOSE_ERROR,
    TCP_CLOSE_NORMAL, TCP_OPEN_FLAGS_NONE, Target, TcpClose, TcpOpen, UDP_CLOSE_ERROR,
    UDP_CLOSE_NORMAL, UdpClose, UdpOpen, datagram, is_client_initiated_flow_id,
    validate_connection_frame, write_frame,
};

use super::dialer::*;
use super::session::*;
use super::tasks::*;
use super::tcp::*;
use super::udp::*;

use crate::observability::{
    ActiveFlowGuard, FlowOpenFailure, RelayDirection, RelayProtocol, ServerMetrics,
};
use crate::security::SecurityState;

pub(crate) const RELAY_BUFFER_SIZE: usize = 16 * 1024;
pub(crate) const TARGET_CONNECT_PARALLELISM: usize = 4;
pub(crate) const TARGET_RESOLUTION_ADDR_LIMIT: usize = 64;
pub(crate) const TARGET_WRITE_QUEUE_MIN_CAPACITY: usize = 64;
pub(crate) const TARGET_WRITE_QUEUE_MAX_CAPACITY: usize = 8192;
pub(crate) const TARGET_WRITE_QUEUE_NOMINAL_FRAME_BYTES: usize = 1024;
pub(crate) const SESSION_EVENT_QUEUE_BASE_CAPACITY: usize = 64;
pub(crate) const SESSION_EVENT_QUEUE_PER_FLOW_CAPACITY: usize = 4;
pub(crate) const SESSION_EVENT_QUEUE_MAX_CAPACITY: usize = 4096;
pub(crate) const UDP_TARGET_BUFFER_SIZE: usize = 65_536;

pub(crate) type AnyError = Box<dyn Error + Send + Sync>;
pub(crate) type FlowTable = HashMap<u64, FlowSlot>;
pub(crate) type FlowEventSender = mpsc::Sender<FlowEvent>;
pub(crate) type FlowEventReceiver = mpsc::Receiver<FlowEvent>;
pub(crate) type BoxedConnectFuture<T> =
    Pin<Box<dyn Future<Output = (SocketAddr, io::Result<T>)> + Send + 'static>>;
pub(crate) type TargetConnector<T> =
    Arc<dyn Fn(SocketAddr) -> BoxedConnectFuture<T> + Send + Sync + 'static>;
pub(crate) struct ServerCarrier {
    pub(crate) carrier_reader: BoxedCarrierReader,
    pub(crate) carrier_writer: BoxedCarrierWriter,
    pub(crate) datagrams: Option<BoxedDatagramChannel>,
}

impl ServerCarrier {
    pub(crate) fn new(
        reader: BoxedCarrierReader,
        writer: BoxedCarrierWriter,
        datagrams: Option<BoxedDatagramChannel>,
    ) -> Self {
        Self {
            carrier_reader: reader,
            carrier_writer: writer,
            datagrams,
        }
    }
}

#[derive(Clone)]
pub(crate) struct CarrierWriter {
    pub(crate) inner: Arc<Mutex<BoxedCarrierWriter>>,
    pub(crate) shutdown: SessionShutdown,
    pub(crate) metrics: Arc<ServerMetrics>,
    pub(crate) write_timeout: Option<Duration>,
}

impl CarrierWriter {
    pub(crate) fn new(
        inner: BoxedCarrierWriter,
        shutdown: SessionShutdown,
        metrics: Arc<ServerMetrics>,
        write_timeout: Option<Duration>,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner)),
            shutdown,
            metrics,
            write_timeout,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RelayLimits {
    pub(crate) frame: FrameLimits,
    pub(crate) max_streams: u64,
    pub(crate) max_udp_flows: u64,
    pub(crate) max_outbound_dials_per_session: usize,
    pub(crate) data_frame_size: usize,
    pub(crate) max_buffered_bytes_per_session: usize,
    pub(crate) max_buffered_bytes_per_flow: usize,
    pub(crate) target_connect_timeout: Option<Duration>,
    pub(crate) tcp_half_close_timeout: Option<Duration>,
    pub(crate) carrier_write_timeout: Option<Duration>,
    pub(crate) udp_flow_idle_timeout: Option<Duration>,
    pub(crate) session_task_shutdown_timeout: Option<Duration>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RelayLimitConfig {
    pub(crate) frame: FrameLimits,
    pub(crate) max_streams: u64,
    pub(crate) max_udp_flows: u64,
    pub(crate) max_outbound_dials_per_session: usize,
    pub(crate) max_buffered_bytes_per_session: usize,
    pub(crate) max_buffered_bytes_per_flow: usize,
    pub(crate) target_connect_timeout: Option<Duration>,
    pub(crate) tcp_half_close_timeout: Option<Duration>,
    pub(crate) carrier_write_timeout: Option<Duration>,
    pub(crate) udp_flow_idle_timeout: Option<Duration>,
    pub(crate) session_task_shutdown_timeout: Option<Duration>,
    pub(crate) relay_buffer_size: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServerSessionState {
    Authenticated,
    Relaying,
    Draining,
    Closing,
    Closed,
}

#[derive(Debug)]
pub(crate) enum OpenFailure {
    PolicyDenied,
    ResourceLimit,
    TargetUnavailable(io::Error),
    TargetTimeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpenSlotRejection {
    DuplicateFlowId,
    ResourceLimit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UdpOpenSlotRejection {
    DuplicateFlowId,
    ResourceLimit,
    UdpFlowLimit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlowIdRejection {
    Zero,
    Reserved,
}

#[derive(Debug)]
pub(crate) enum FlowEvent {
    OpenCompleted {
        flow_id: u64,
        token: FlowToken,
        target: Target,
        result: Result<TcpStream, OpenFailure>,
    },
    UdpOpenCompleted {
        flow_id: u64,
        token: FlowToken,
        target: Target,
        result: Result<UdpSocket, OpenFailure>,
    },
    ReadClosed {
        flow_id: u64,
        token: FlowToken,
    },
    UdpReadClosed {
        flow_id: u64,
        token: FlowToken,
    },
    UdpActivity(u64),
    InboundDatagram {
        flow_id: u64,
        payload: Bytes,
    },
    HalfCloseDrainExpired {
        flow_id: u64,
        token: FlowToken,
        closed_side: HalfCloseSide,
    },
    WriteClosed {
        flow_id: u64,
        token: FlowToken,
    },
    Activity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HalfCloseSide {
    TargetToClient,
    ClientToTarget,
}

pub(crate) enum SessionEvent {
    Flow(Option<FlowEvent>),
    Frame(Frame),
    FrameReadError(FrameIoError),
    SessionTaskCompleted,
    IdleTimeout,
    UdpIdleMaintenance,
    PeerClosed,
    Shutdown,
    DrainTimeout,
    /// The carrier was declared unusable by a writer (see `write_frame_locked`).
    CarrierFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionTaskKind {
    TcpOpen,
    UdpOpen,
    TargetReader,
    UdpReader,
    DatagramReader,
    TargetWriter,
    HalfCloseTimer,
}

#[derive(Debug)]
pub(crate) enum TargetCommand {
    Data(BufferedTargetData),
    Close,
}

#[derive(Debug)]
pub(crate) enum EnqueueError {
    Closed,
    ResourceLimit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TcpDataDisposition {
    UnknownFlow,
    OpeningFlow,
    OtherProtocolFlow,
    EmptyPayload,
    ForwardPayload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UdpDataDisposition {
    UnknownFlow,
    OpeningFlow,
    TcpFlow,
    ForwardPayload,
}

#[derive(Debug, Clone)]
pub(crate) struct SessionBufferControl {
    pub(crate) buffered_bytes: Arc<AtomicUsize>,
}

#[derive(Debug)]
pub(crate) struct BufferedTargetData {
    pub(crate) payload: Bytes,
    pub(crate) payload_len: usize,
    pub(crate) control: TargetFlowControl,
}

#[derive(Debug, Clone)]
pub(crate) struct TargetFlowControl {
    pub(crate) buffered_bytes: Arc<AtomicUsize>,
    pub(crate) session_buffer: SessionBufferControl,
    pub(crate) closed: Arc<AtomicBool>,
    pub(crate) aborted: Arc<AtomicBool>,
    pub(crate) abort_notify: Arc<Notify>,
}

#[derive(Debug, Clone)]
pub(crate) struct OpenDialLimiter {
    pub(crate) semaphore: Arc<Semaphore>,
}

#[derive(Debug, Clone)]
pub(crate) struct FlowTokenAllocator {
    pub(crate) next: Arc<AtomicU64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FlowToken(pub(crate) u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TargetFlowIdentity {
    pub(crate) flow_id: u64,
    pub(crate) token: FlowToken,
}

#[derive(Clone)]
pub(crate) struct OpenDialPermit {
    pub(crate) _permit: Arc<OwnedSemaphorePermit>,
}

#[derive(Debug)]
pub(crate) enum FlowSlot {
    OpeningTcp(OpenFlowCancel),
    OpeningUdp(OpenFlowCancel),
    Tcp(TargetFlow),
    Udp(UdpTargetFlow),
}

#[derive(Clone)]
pub(crate) struct OpenFlowCancel {
    /// Identifies this open attempt. A connect task that finishes after its
    /// flow id was closed and re-opened must not have its result attached to
    /// the new flow, so completion events carry this back for comparison.
    pub(crate) token: FlowToken,
    pub(crate) cancelled: Arc<AtomicBool>,
    pub(crate) notify: Arc<Notify>,
}

#[derive(Debug, Clone)]
pub(crate) struct SessionTaskHandle {
    pub(crate) abort_handle: AbortHandle,
    pub(crate) cancelled: Arc<AtomicBool>,
}

impl SessionTaskHandle {
    pub(crate) fn new(abort_handle: AbortHandle, cancelled: Arc<AtomicBool>) -> Self {
        Self {
            abort_handle,
            cancelled,
        }
    }

    pub(crate) fn abort(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.abort_handle.abort();
    }
}

#[derive(Debug)]
pub(crate) struct TargetFlow {
    pub(crate) token: FlowToken,
    pub(crate) commands: Option<mpsc::Sender<TargetCommand>>,
    pub(crate) control: TargetFlowControl,
    pub(crate) target_to_client_open: bool,
    pub(crate) client_to_target_open: bool,
    pub(crate) target_write_open: bool,
    pub(crate) half_close_timer: Option<SessionTaskHandle>,
    pub(crate) metrics_guard: Option<ActiveFlowGuard>,
}

#[derive(Debug)]
pub(crate) struct UdpTargetFlow {
    /// Identifies this incarnation of the flow id, so a reader task that
    /// finishes after the id has been closed and re-opened cannot act on the
    /// new flow. Mirrors `TargetFlow::token`.
    pub(crate) token: FlowToken,
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) control: TargetFlowControl,
    pub(crate) last_activity: time::Instant,
    pub(crate) metrics_guard: Option<ActiveFlowGuard>,
}

#[derive(Debug, Clone)]
pub(crate) struct SessionShutdown {
    pub(crate) closed: Arc<AtomicBool>,
    pub(crate) notify: Arc<Notify>,
}

pub(crate) struct RelaySessionContext<'a> {
    pub(crate) identity: AuthenticatedIdentity,
    pub(crate) security: SecurityState,
    pub(crate) carrier_writer: &'a CarrierWriter,
    pub(crate) event_tx: &'a FlowEventSender,
    pub(crate) limits: RelayLimits,
    pub(crate) shutdown: SessionShutdown,
    pub(crate) session_buffer: SessionBufferControl,
    pub(crate) open_dial_limiter: OpenDialLimiter,
    pub(crate) flow_tokens: FlowTokenAllocator,
    pub(crate) metrics: Arc<ServerMetrics>,
    /// Datagram channel for the UDP data plane (QUIC only). `None` disables
    /// native datagrams; UDP relay then uses `UDP_DATA` frames.
    pub(crate) datagrams: Option<BoxedDatagramChannel>,
}

impl RelayLimits {
    pub(crate) fn new(config: RelayLimitConfig) -> Self {
        Self {
            frame: config.frame,
            max_streams: config.max_streams,
            max_udp_flows: config.max_udp_flows,
            max_outbound_dials_per_session: config.max_outbound_dials_per_session,
            data_frame_size: tcp_data_frame_size(config.frame, config.relay_buffer_size),
            max_buffered_bytes_per_session: config.max_buffered_bytes_per_session,
            max_buffered_bytes_per_flow: config.max_buffered_bytes_per_flow,
            target_connect_timeout: config.target_connect_timeout,
            tcp_half_close_timeout: config.tcp_half_close_timeout,
            carrier_write_timeout: config.carrier_write_timeout,
            udp_flow_idle_timeout: config.udp_flow_idle_timeout,
            session_task_shutdown_timeout: config.session_task_shutdown_timeout,
        }
    }
}

impl Default for SessionShutdown {
    fn default() -> Self {
        Self {
            closed: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
        }
    }
}

impl SessionShutdown {
    pub(crate) fn close(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            self.notify.notify_waiters();
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

impl Default for FlowTokenAllocator {
    fn default() -> Self {
        Self {
            next: Arc::new(AtomicU64::new(1)),
        }
    }
}

impl FlowTokenAllocator {
    pub(crate) fn next(&self) -> FlowToken {
        FlowToken(self.next.fetch_add(1, Ordering::Relaxed))
    }
}

impl OpenDialLimiter {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(limit)),
        }
    }

    pub(crate) fn try_acquire(&self) -> Option<OpenDialPermit> {
        Arc::clone(&self.semaphore)
            .try_acquire_owned()
            .ok()
            .map(OpenDialPermit::new)
    }

    #[cfg(test)]
    pub(crate) fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }
}

impl OpenDialPermit {
    pub(crate) fn new(permit: OwnedSemaphorePermit) -> Self {
        Self {
            _permit: Arc::new(permit),
        }
    }
}

impl fmt::Debug for OpenDialPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenDialPermit")
            .finish_non_exhaustive()
    }
}

impl OpenFlowCancel {
    pub(crate) fn new(token: FlowToken) -> Self {
        Self {
            token,
            cancelled: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
        }
    }
}

impl fmt::Debug for OpenFlowCancel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenFlowCancel")
            .field("cancelled", &self.is_cancelled())
            .finish_non_exhaustive()
    }
}

impl OpenFlowCancel {
    pub(crate) fn cancel(&self) {
        if !self.cancelled.swap(true, Ordering::SeqCst) {
            self.notify.notify_waiters();
        }
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    pub(crate) async fn cancelled(&self) {
        loop {
            let notified = self.notify.notified();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

impl Default for SessionBufferControl {
    fn default() -> Self {
        Self {
            buffered_bytes: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl SessionBufferControl {
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

impl Default for TargetFlowControl {
    fn default() -> Self {
        Self::new(SessionBufferControl::default())
    }
}

impl TargetFlowControl {
    pub(crate) fn new(session_buffer: SessionBufferControl) -> Self {
        Self {
            buffered_bytes: Arc::new(AtomicUsize::new(0)),
            session_buffer,
            closed: Arc::new(AtomicBool::new(false)),
            aborted: Arc::new(AtomicBool::new(false)),
            abort_notify: Arc::new(Notify::new()),
        }
    }
}

impl TargetFlowControl {
    pub(crate) fn reserve_bytes(
        &self,
        amount: usize,
        flow_limit: usize,
        session_limit: usize,
    ) -> bool {
        if !reserve_bytes(&self.buffered_bytes, amount, flow_limit) {
            return false;
        }
        if !self.session_buffer.reserve_bytes(amount, session_limit) {
            release_bytes(&self.buffered_bytes, amount);
            return false;
        }
        true
    }

    pub(crate) fn release_bytes(&self, amount: usize) {
        release_bytes(&self.buffered_bytes, amount);
        self.session_buffer.release_bytes(amount);
    }

    #[cfg(test)]
    pub(crate) fn buffered_bytes(&self) -> usize {
        self.buffered_bytes.load(Ordering::SeqCst)
    }

    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    pub(crate) fn abort(&self) {
        if !self.aborted.swap(true, Ordering::SeqCst) {
            self.abort_notify.notify_waiters();
        }
        self.close();
    }

    pub(crate) fn is_aborted(&self) -> bool {
        self.aborted.load(Ordering::SeqCst)
    }

    pub(crate) async fn aborted(&self) {
        loop {
            let notified = self.abort_notify.notified();
            if self.is_aborted() {
                return;
            }
            notified.await;
        }
    }
}

impl BufferedTargetData {
    pub(crate) fn new(
        payload: Bytes,
        control: TargetFlowControl,
        flow_byte_limit: usize,
        session_byte_limit: usize,
    ) -> Result<Self, Bytes> {
        let payload_len = payload.len();
        if control.reserve_bytes(payload_len, flow_byte_limit, session_byte_limit) {
            Ok(Self {
                payload,
                payload_len,
                control,
            })
        } else {
            Err(payload)
        }
    }

    pub(crate) fn payload(&self) -> &[u8] {
        &self.payload
    }
}

impl Drop for BufferedTargetData {
    fn drop(&mut self) {
        self.control.release_bytes(self.payload_len);
    }
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
        match buffered_bytes.compare_exchange(current, next, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return true,
            Err(actual) => current = actual,
        }
    }
}

pub(crate) fn release_bytes(buffered_bytes: &AtomicUsize, amount: usize) {
    let mut current = buffered_bytes.load(Ordering::SeqCst);
    loop {
        let next = current.saturating_sub(amount);
        match buffered_bytes.compare_exchange(current, next, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return,
            Err(actual) => current = actual,
        }
    }
}

impl TargetFlow {
    pub(crate) fn new(
        token: FlowToken,
        commands: mpsc::Sender<TargetCommand>,
        control: TargetFlowControl,
    ) -> Self {
        Self {
            token,
            commands: Some(commands),
            control,
            target_to_client_open: true,
            client_to_target_open: true,
            target_write_open: true,
            half_close_timer: None,
            metrics_guard: None,
        }
    }

    pub(crate) fn track_metrics(mut self, guard: ActiveFlowGuard) -> Self {
        self.metrics_guard = Some(guard);
        self
    }

    pub(crate) fn set_half_close_timer(&mut self, handle: SessionTaskHandle) {
        if let Some(old) = self.half_close_timer.replace(handle) {
            old.abort();
        }
    }

    pub(crate) fn cancel_half_close_timer(&mut self) {
        if let Some(handle) = self.half_close_timer.take() {
            handle.abort();
        }
    }

    pub(crate) fn enqueue_data(
        &mut self,
        payload: Bytes,
        flow_byte_limit: usize,
        session_byte_limit: usize,
    ) -> Result<(), EnqueueError> {
        if self.control.is_closed() {
            return Err(EnqueueError::Closed);
        }

        let Ok(buffered_data) = BufferedTargetData::new(
            payload,
            self.control.clone(),
            flow_byte_limit,
            session_byte_limit,
        ) else {
            self.close_client_to_target_queue();
            return Err(EnqueueError::ResourceLimit);
        };

        let Some(commands) = &self.commands else {
            return Err(EnqueueError::Closed);
        };

        match commands.try_send(TargetCommand::Data(buffered_data)) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(EnqueueError::Closed),
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.close_client_to_target_queue();
                Err(EnqueueError::ResourceLimit)
            }
        }
    }

    pub(crate) fn close_client_to_target(&mut self) {
        if self.client_to_target_open {
            self.client_to_target_open = false;
            self.close_client_to_target_queue();
        }
    }

    pub(crate) fn close_client_to_target_queue(&mut self) {
        self.control.close();
        let drop_sender = match self.commands.as_ref() {
            Some(commands) => match commands.try_send(TargetCommand::Close) {
                Ok(()) => false,
                Err(mpsc::error::TrySendError::Closed(_) | mpsc::error::TrySendError::Full(_)) => {
                    true
                }
            },
            None => false,
        };
        if drop_sender {
            self.commands = None;
        }
    }

    pub(crate) fn abort(&mut self) {
        self.cancel_half_close_timer();
        self.target_to_client_open = false;
        self.client_to_target_open = false;
        self.target_write_open = false;
        self.control.abort();
        self.close_client_to_target_queue();
    }

    pub(crate) fn mark_target_to_client_closed(&mut self) {
        self.target_to_client_open = false;
    }

    pub(crate) fn mark_client_to_target_closed(&mut self) {
        self.client_to_target_open = false;
        self.control.close();
    }

    pub(crate) fn mark_target_write_closed(&mut self) {
        self.client_to_target_open = false;
        self.target_write_open = false;
        self.control.close();
    }

    pub(crate) const fn is_removable(&self) -> bool {
        !self.target_to_client_open && !self.client_to_target_open && !self.target_write_open
    }

    #[allow(dead_code)]
    pub(crate) const fn is_fully_closed(&self) -> bool {
        !self.target_to_client_open && !self.client_to_target_open
    }
}

impl Drop for TargetFlow {
    fn drop(&mut self) {
        self.cancel_half_close_timer();
        if !self.is_fully_closed() {
            self.target_to_client_open = false;
            self.client_to_target_open = false;
            self.target_write_open = false;
            self.control.abort();
            self.commands = None;
        }
    }
}

impl UdpTargetFlow {
    pub(crate) fn new(
        token: FlowToken,
        socket: Arc<UdpSocket>,
        control: TargetFlowControl,
    ) -> Self {
        Self {
            token,
            socket,
            control,
            last_activity: time::Instant::now(),
            metrics_guard: None,
        }
    }

    pub(crate) fn track_metrics(mut self, guard: ActiveFlowGuard) -> Self {
        self.metrics_guard = Some(guard);
        self
    }

    pub(crate) fn abort(&self) {
        self.control.abort();
    }

    pub(crate) fn record_activity(&mut self) {
        self.last_activity = time::Instant::now();
    }
}

impl Drop for UdpTargetFlow {
    fn drop(&mut self) {
        self.abort();
    }
}

pub(crate) fn open_target_flow_mut(
    target_writers: &mut FlowTable,
    flow_id: u64,
) -> Option<&mut TargetFlow> {
    match target_writers.get_mut(&flow_id) {
        Some(FlowSlot::Tcp(target)) => Some(target),
        Some(FlowSlot::OpeningTcp(_) | FlowSlot::OpeningUdp(_) | FlowSlot::Udp(_)) | None => None,
    }
}

pub(crate) fn udp_target_flow_mut(
    target_writers: &mut FlowTable,
    flow_id: u64,
) -> Option<&mut UdpTargetFlow> {
    match target_writers.get_mut(&flow_id) {
        Some(FlowSlot::Udp(target)) => Some(target),
        Some(FlowSlot::OpeningTcp(_) | FlowSlot::OpeningUdp(_) | FlowSlot::Tcp(_)) | None => None,
    }
}

pub(crate) fn remove_flow_slot(target_writers: &mut FlowTable, flow_id: u64) -> Option<FlowSlot> {
    let slot = target_writers.remove(&flow_id);
    if let Some(FlowSlot::OpeningTcp(cancel) | FlowSlot::OpeningUdp(cancel)) = &slot {
        cancel.cancel();
    }
    slot
}

pub(crate) fn transition(state: &mut ServerSessionState, next: ServerSessionState) {
    let from = *state;
    debug_assert!(
        is_valid_session_transition(from, next),
        "invalid server session state transition"
    );
    debug!(event = "server.session.state", from = ?from, to = ?next);
    *state = next;
}

pub(crate) const fn is_valid_session_transition(
    from: ServerSessionState,
    next: ServerSessionState,
) -> bool {
    matches!(
        (from, next),
        (
            ServerSessionState::Authenticated,
            ServerSessionState::Relaying
        ) | (
            ServerSessionState::Relaying,
            ServerSessionState::Draining | ServerSessionState::Closing | ServerSessionState::Closed
        ) | (
            ServerSessionState::Draining,
            ServerSessionState::Closing | ServerSessionState::Closed
        ) | (ServerSessionState::Closing, ServerSessionState::Closed)
    )
}

pub(crate) fn tcp_data_frame_size(limits: FrameLimits, relay_buffer_size: Option<usize>) -> usize {
    let buf_size = relay_buffer_size.unwrap_or(RELAY_BUFFER_SIZE);
    usize::try_from(limits.max_frame_size).map_or(buf_size, |limit| limit.min(buf_size))
}
