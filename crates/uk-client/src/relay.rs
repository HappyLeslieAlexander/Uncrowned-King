//! SOCKS5-to-UK TCP relay.

use std::{
    collections::{HashMap, hash_map::Entry},
    error::Error,
    future::Future,
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf},
    net::{TcpListener, TcpStream},
    sync::{Mutex, Notify, Semaphore, mpsc, watch},
    task::JoinSet,
    time,
};
use tokio_rustls::client::TlsStream;
use tracing::{debug, info, warn};
use uk_proto::{
    ErrorCode, ErrorPayload, FIRST_CLIENT_FLOW_ID, FLOW_ID_STEP, Frame, FrameIoError, FrameLimits,
    FrameType, SettingKey, TCP_CLOSE_ERROR, TCP_CLOSE_NORMAL, TCP_OPEN_FLAGS_NONE, Target,
    TcpClose, TcpOpen, frame::DEFAULT_MAX_FRAME_SIZE, is_client_initiated_flow_id, read_frame,
    validate_connection_frame, varint::MAX_VARINT, write_frame,
};

use crate::{
    config::{ClientConfig, validate_endpoint},
    session, socks5,
};

const FLOW_ID_ALLOCATION_ATTEMPTS: usize = 1024;
const FLOW_FRAME_QUEUE_CAPACITY: usize = 32;
const RELAY_BUFFER_SIZE: usize = 16 * 1024;
const DEFAULT_MAX_STREAMS: u64 = 64;

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
    closed: AtomicBool,
}

struct ClientFlow {
    id: u64,
    frames: mpsc::Receiver<BufferedFlowFrame>,
    session: Arc<ClientSession>,
    pending_local_data: Vec<Bytes>,
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
    Enqueued,
    FlowClosed,
    FlowQueueFull,
    SessionQueueFull,
}

#[derive(Debug, Clone)]
struct ClientFlowRoute {
    sender: mpsc::Sender<BufferedFlowFrame>,
    flow_buffer: ClientFlowBufferControl,
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
    fn new(sender: mpsc::Sender<BufferedFlowFrame>) -> Self {
        Self {
            sender,
            flow_buffer: ClientFlowBufferControl::default(),
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

    fn into_frame(mut self) -> Frame {
        self.release();
        self.frame.take().expect("buffered frame missing")
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
    let socks_handshake_timeout = timeout(config.socks_handshake_timeout_seconds());
    let max_socks_connections = usize_limit(config.max_socks_connections())?;
    let sessions = Arc::new(ClientSessionManager::new(config));
    let connection_slots = Arc::new(Semaphore::new(max_socks_connections));
    let listener = TcpListener::bind(&listen).await?;
    info!(event = "socks5.listen", listen = %listen);

    let (shutdown_tx, _shutdown_rx) = watch::channel(false);
    let mut connections = JoinSet::new();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            () = &mut shutdown => {
                info!(event = "socks5.shutdown");
                sessions.shutdown().await;
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

    while let Some(joined) = connections.join_next().await {
        log_socks_task_result(Some(joined));
    }

    Ok(())
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
        Self {
            config,
            current: Mutex::new(None),
            connect_lock: Mutex::new(()),
            closed: AtomicBool::new(false),
        }
    }

    async fn open_flow(
        &self,
        target: Target,
        local: &mut TcpStream,
    ) -> Result<OpenOutcome, AnyError> {
        let mut pending_local_data = PendingOpenLocalData::default();
        let mut last_error = None;
        for attempt in 0..2 {
            let session = self.current_session().await?;
            match session
                .open_flow(target.clone(), local, &mut pending_local_data)
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

    async fn current_session(&self) -> Result<Arc<ClientSession>, AnyError> {
        if self.is_closed() {
            return Err("client session manager is shutting down".into());
        }
        if let Some(session) = self.current_session_if_live().await {
            return Ok(session);
        }

        let _connect_guard = self.connect_lock.lock().await;
        if self.is_closed() {
            return Err("client session manager is shutting down".into());
        }
        if let Some(session) = self.current_session_if_live().await {
            return Ok(session);
        }

        info!(event = "client.session.connect");
        let session = ClientSession::connect(&self.config).await?;
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
}

impl ClientSession {
    async fn connect(config: &ClientConfig) -> Result<Arc<Self>, AnyError> {
        let (carrier, settings) = session::connect_authenticated(config).await?;
        let limits = frame_limits(&settings);
        let (carrier_reader, carrier_writer) = tokio::io::split(carrier);
        let session_buffer = ClientSessionBufferControl::default();
        let session = Arc::new(Self {
            writer: Arc::new(Mutex::new(carrier_writer)),
            flows: Arc::new(Mutex::new(HashMap::new())),
            limits,
            data_frame_size: tcp_data_frame_size(limits),
            max_streams: max_streams(&settings),
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
        if let Some(interval) = keepalive_interval(&settings) {
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
    ) -> Result<OpenOutcome, AnyError> {
        if self.is_closed() {
            return Err("uk session is closed".into());
        }
        let Some((flow_id, frames)) = self.reserve_flow().await? else {
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
            .wait_for_open_frame(flow_id, &mut flow.frames, local, pending_local_data)
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

    async fn wait_for_open_frame(
        &self,
        flow_id: u64,
        frames: &mut mpsc::Receiver<BufferedFlowFrame>,
        local: &mut TcpStream,
        pending_local_data: &mut PendingOpenLocalData,
    ) -> Result<OpenWaitOutcome, AnyError> {
        if let Some(timeout) = self.open_timeout {
            if let Ok(result) = time::timeout(
                timeout,
                self.wait_for_open_frame_inner(flow_id, frames, local, pending_local_data),
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
            self.wait_for_open_frame_inner(flow_id, frames, local, pending_local_data)
                .await
        }
    }

    async fn wait_for_open_frame_inner(
        &self,
        flow_id: u64,
        frames: &mut mpsc::Receiver<BufferedFlowFrame>,
        local: &mut TcpStream,
        pending_local_data: &mut PendingOpenLocalData,
    ) -> Result<OpenWaitOutcome, AnyError> {
        loop {
            tokio::select! {
                frame = frames.recv() => {
                    return frame
                        .map(BufferedFlowFrame::into_frame)
                        .map(OpenWaitOutcome::Frame)
                        .ok_or_else(|| "uk session closed while opening flow".into());
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
            }
        }
    }

    async fn cancel_pending_open(&self, flow_id: u64) {
        self.flows.lock().await.remove(&flow_id);
        let _ = self.send_tcp_close(flow_id, TCP_CLOSE_ERROR).await;
    }

    async fn reserve_flow(
        &self,
    ) -> Result<Option<(u64, mpsc::Receiver<BufferedFlowFrame>)>, AnyError> {
        let (sender, frames) = mpsc::channel(FLOW_FRAME_QUEUE_CAPACITY);
        let mut flows = self.flows.lock().await;
        let Some(flow_id) =
            reserve_flow_slot(&mut flows, self.max_streams, &self.next_flow_id, sender)?
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

    async fn send_tcp_data(&self, flow_id: u64, payload: Bytes) -> Result<(), AnyError> {
        let frame = Frame::new(FrameType::TcpData, 0, flow_id, payload)?;
        self.write_frame(&frame).await
    }

    async fn send_tcp_close(&self, flow_id: u64, close_code: u16) -> Result<(), AnyError> {
        let mut payload = BytesMut::new();
        TcpClose::new(close_code).encode(&mut payload)?;
        let frame = Frame::new(FrameType::TcpClose, 0, flow_id, payload.freeze())?;
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
            if self.is_closed() {
                return false;
            }
            let notified = self.pong_notify.notified();
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
) -> Result<Option<u64>, AnyError> {
    if flows.len() as u64 >= max_streams {
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
            entry.insert(ClientFlowRoute::new(sender));
            return Ok(Some(flow_id));
        }
    }

    Err("no available client flow id".into())
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
            let (flow_id, route) = {
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
                    return Err("invalid tcp relay flow id from server".into());
                }
                FlowFrameRoute::FlowQueueFull => {
                    warn!(event = "client.flow.queue_full", flow_id);
                    session.send_resource_limit(flow_id).await?;
                    session.send_tcp_close(flow_id, TCP_CLOSE_ERROR).await?;
                }
                FlowFrameRoute::SessionQueueFull => {
                    warn!(event = "client.session.queue_full", flow_id);
                    session.send_resource_limit(flow_id).await?;
                    session.send_tcp_close(flow_id, TCP_CLOSE_ERROR).await?;
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
        FrameType::TcpData => Ok(()),
        FrameType::TcpClose => {
            let mut payload = frame.payload.clone();
            TcpClose::decode(&mut payload)?;
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
) -> (u64, FlowFrameRoute) {
    let flow_id = frame.header.id;
    if !is_client_initiated_flow_id(flow_id) {
        return (flow_id, FlowFrameRoute::InvalidFlowId);
    }

    let Some(route) = flows.get(&flow_id) else {
        return (flow_id, FlowFrameRoute::UnknownFlow);
    };
    let sender = route.sender.clone();
    let flow_buffer = route.flow_buffer.clone();

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
            return (flow_id, FlowFrameRoute::FlowQueueFull);
        }
        Err(BufferReserveError::SessionLimit) => {
            flows.remove(&flow_id);
            return (flow_id, FlowFrameRoute::SessionQueueFull);
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
    (flow_id, route)
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
            debug!(event = "socks5.udp_associate.unsupported", endpoint = ?endpoint);
            socks5::send_reply(&mut local, socks5::Reply::CommandNotSupported).await?;
            transition(&mut state, ClientConnectionState::Closed);
            return Ok(());
        }
    };

    transition(&mut state, ClientConnectionState::Opening);
    let open_result = tokio::select! {
        result = sessions.open_flow(target, &mut local) => result,
        changed = shutdown_rx.changed() => {
            let _ = changed;
            transition(&mut state, ClientConnectionState::Closed);
            return Ok(());
        }
    };
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
    socks5::send_reply(&mut local, socks5::Reply::Succeeded).await?;

    transition(&mut state, ClientConnectionState::Relaying);
    let flow_id = flow.id;
    let flow_session = Arc::clone(&flow.session);
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
                let Some(frame) = frame.map(BufferedFlowFrame::into_frame) else {
                    local.shutdown().await?;
                    local_to_remote_open = false;
                    remote_to_local_open = false;
                    continue;
                };
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

fn frame_limits(settings: &uk_proto::Settings) -> FrameLimits {
    FrameLimits {
        max_frame_size: settings
            .get(SettingKey::MaxFrameSize)
            .unwrap_or(DEFAULT_MAX_FRAME_SIZE),
    }
}

fn max_streams(settings: &uk_proto::Settings) -> u64 {
    settings
        .get(SettingKey::MaxStreams)
        .unwrap_or(DEFAULT_MAX_STREAMS)
}

fn keepalive_interval(settings: &uk_proto::Settings) -> Option<Duration> {
    let idle_timeout_seconds = settings.get(SettingKey::IdleTimeoutSeconds)?;
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
            ClientConnectionState::Opening | ClientConnectionState::Closed
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

    fn minimal_config() -> ClientConfig {
        ClientConfig {
            server_addr: "127.0.0.1:443".to_owned(),
            server_addrs: None,
            server_name: "localhost".to_owned(),
            ca_cert_path: "missing-ca.pem".to_owned(),
            key_id: "client".to_owned(),
            secret: "0123456789abcdef0123456789abcdef".to_owned(),
            handshake_timeout_seconds: None,
            socks_handshake_timeout_seconds: None,
            tcp_open_timeout_seconds: None,
            max_pending_open_bytes: None,
            max_socks_connections: None,
            max_buffered_bytes_per_session: None,
            max_buffered_bytes_per_flow: None,
        }
    }

    fn boxed_io_error(kind: io::ErrorKind) -> AnyError {
        io::Error::new(kind, "test error").into()
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

    fn control_frame(frame_type: FrameType, flow_id: u64) -> Frame {
        Frame::new(frame_type, 0, flow_id, Bytes::new()).unwrap()
    }

    fn route_test_flow_frame(
        frame: Frame,
        flows: &mut HashMap<u64, ClientFlowRoute>,
    ) -> (u64, FlowFrameRoute) {
        route_flow_frame(
            frame,
            flows,
            ClientSessionBufferControl::default(),
            usize::MAX,
            usize::MAX,
        )
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
            reserve_flow_slot(&mut flows, 1, &next_flow_id, sender).unwrap(),
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
        flows.insert(FLOW_ID, ClientFlowRoute::new(existing_sender));
        let next_flow_id = AtomicU64::new(FIRST_CLIENT_FLOW_ID);
        let (sender, _receiver) = mpsc::channel(1);

        assert_eq!(
            reserve_flow_slot(&mut flows, 1, &next_flow_id, sender).unwrap(),
            None
        );

        assert_eq!(flows.len(), 1);
        assert_eq!(next_flow_id.load(Ordering::Relaxed), FIRST_CLIENT_FLOW_ID);
    }

    #[test]
    fn routes_carrier_frame_to_existing_flow() {
        let (sender, mut receiver) = mpsc::channel(1);
        let mut flows = HashMap::new();
        flows.insert(FLOW_ID, ClientFlowRoute::new(sender));

        assert_eq!(
            route_test_flow_frame(
                data_frame(FLOW_ID, Bytes::from_static(b"hello")),
                &mut flows
            ),
            (FLOW_ID, FlowFrameRoute::Enqueued)
        );

        let frame = receiver.try_recv().unwrap().into_frame();
        assert_eq!(frame.header.id, FLOW_ID);
        assert_eq!(frame.payload, Bytes::from_static(b"hello"));
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
        flows.insert(FLOW_ID, ClientFlowRoute::new(sender));

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
        flows.insert(FLOW_ID, ClientFlowRoute::new(sender));

        assert_eq!(
            route_test_flow_frame(
                data_frame(FLOW_ID, Bytes::from_static(b"overflow")),
                &mut flows
            ),
            (FLOW_ID, FlowFrameRoute::FlowQueueFull)
        );
        assert!(!flows.contains_key(&FLOW_ID));
        assert_eq!(
            receiver.try_recv().unwrap().into_frame().payload,
            Bytes::from_static(b"queued")
        );
    }

    #[test]
    fn removes_flow_when_flow_buffer_limit_is_exceeded() {
        let (sender, _receiver) = mpsc::channel(1);
        let mut flows = HashMap::new();
        flows.insert(FLOW_ID, ClientFlowRoute::new(sender));
        let session_buffer = ClientSessionBufferControl::default();

        assert_eq!(
            route_flow_frame(
                data_frame(FLOW_ID, Bytes::from_static(b"overflow")),
                &mut flows,
                session_buffer.clone(),
                4,
                usize::MAX,
            ),
            (FLOW_ID, FlowFrameRoute::FlowQueueFull)
        );

        assert!(!flows.contains_key(&FLOW_ID));
        assert_eq!(session_buffer.buffered_bytes(), 0);
    }

    #[test]
    fn removes_flow_when_session_buffer_limit_is_exceeded() {
        let (sender, _receiver) = mpsc::channel(1);
        let mut flows = HashMap::new();
        flows.insert(FLOW_ID, ClientFlowRoute::new(sender));
        let session_buffer = ClientSessionBufferControl::default();

        assert_eq!(
            route_flow_frame(
                data_frame(FLOW_ID, Bytes::from_static(b"overflow")),
                &mut flows,
                session_buffer.clone(),
                usize::MAX,
                4,
            ),
            (FLOW_ID, FlowFrameRoute::SessionQueueFull)
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

        let frame = buffered.into_frame();

        assert_eq!(frame.payload, Bytes::from_static(b"queued"));
        assert_eq!(flow_buffer.buffered_bytes(), 0);
        assert_eq!(session_buffer.buffered_bytes(), 0);
    }

    #[test]
    fn decodes_open_ack() {
        let frame = Frame::new(FrameType::TcpData, 0, FLOW_ID, Bytes::new()).unwrap();

        assert_eq!(decode_open_response(frame).unwrap(), OpenResponse::Accepted);
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
        assert!(validate_server_flow_frame(&error_frame(ErrorCode::Protocol)).is_ok());
    }

    #[test]
    fn rejects_malformed_server_flow_frames_before_routing() {
        let malformed_close = Frame::new(FrameType::TcpClose, 0, FLOW_ID, Bytes::new()).unwrap();
        let malformed_status = Frame::new(FrameType::Error, 0, FLOW_ID, Bytes::new()).unwrap();
        let mismatched_policy_denied = Frame::new(
            FrameType::PolicyDenied,
            0,
            FLOW_ID,
            status_payload(ErrorCode::ResourceLimit),
        )
        .unwrap();

        assert!(validate_server_flow_frame(&malformed_close).is_err());
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
    fn derives_keepalive_interval_from_idle_timeout() {
        let mut settings = uk_proto::Settings::default();
        settings.set(SettingKey::IdleTimeoutSeconds, 30);

        assert_eq!(keepalive_interval(&settings), Some(Duration::from_secs(15)));
    }

    #[test]
    fn keeps_one_second_idle_timeout_before_deadline() {
        let mut settings = uk_proto::Settings::default();
        settings.set(SettingKey::IdleTimeoutSeconds, 1);

        assert_eq!(
            keepalive_interval(&settings),
            Some(Duration::from_millis(500))
        );
    }

    #[test]
    fn disables_keepalive_without_idle_timeout() {
        let settings = uk_proto::Settings::default();

        assert_eq!(keepalive_interval(&settings), None);
    }

    #[test]
    fn disables_keepalive_for_zero_idle_timeout() {
        let mut settings = uk_proto::Settings::default();
        settings.set(SettingKey::IdleTimeoutSeconds, 0);

        assert_eq!(keepalive_interval(&settings), None);
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
