//! Server-side UK TCP relay.

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
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, WriteHalf},
    net::{
        TcpStream, UdpSocket, lookup_host,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore, mpsc, watch},
    task::JoinSet,
};
use tokio_rustls::server::TlsStream;
use tracing::{debug, info, warn};
use uk_auth::Credential;
use uk_policy::{PolicyContext, PolicyDecision, PolicySet};
use uk_proto::{
    ErrorCode, ErrorPayload, Frame, FrameIoError, FrameLimits, FrameType, TCP_CLOSE_ERROR,
    TCP_CLOSE_NORMAL, TCP_OPEN_FLAGS_NONE, Target, TcpClose, TcpOpen, UDP_CLOSE_ERROR,
    UDP_CLOSE_NORMAL, UdpClose, UdpOpen, is_client_initiated_flow_id, read_frame,
    validate_connection_frame, write_frame,
};

const RELAY_BUFFER_SIZE: usize = 16 * 1024;
const TARGET_CONNECT_PARALLELISM: usize = 4;
const TARGET_WRITE_QUEUE_CAPACITY: usize = 32;

type AnyError = Box<dyn Error + Send + Sync>;
type FlowTable = HashMap<u64, FlowSlot>;
type BoxedConnectFuture<T> =
    Pin<Box<dyn Future<Output = (SocketAddr, io::Result<T>)> + Send + 'static>>;
type TargetConnector<T> = Arc<dyn Fn(SocketAddr) -> BoxedConnectFuture<T> + Send + Sync + 'static>;

#[derive(Clone)]
struct CarrierWriter {
    inner: Arc<Mutex<WriteHalf<TlsStream<TcpStream>>>>,
    shutdown: SessionShutdown,
}

impl CarrierWriter {
    fn new(inner: WriteHalf<TlsStream<TcpStream>>, shutdown: SessionShutdown) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner)),
            shutdown,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RelayLimits {
    frame: FrameLimits,
    max_streams: u64,
    max_outbound_dials_per_session: usize,
    data_frame_size: usize,
    max_buffered_bytes_per_session: usize,
    max_buffered_bytes_per_flow: usize,
    target_connect_timeout: Option<Duration>,
    tcp_half_close_timeout: Option<Duration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerSessionState {
    Authenticated,
    Relaying,
    Closing,
    Closed,
}

#[derive(Debug)]
enum OpenFailure {
    PolicyDenied,
    ResourceLimit,
    TargetUnavailable(io::Error),
    TargetTimeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpenSlotRejection {
    DuplicateFlowId,
    ResourceLimit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlowIdRejection {
    Zero,
    Reserved,
}

#[derive(Debug)]
enum FlowEvent {
    OpenCompleted {
        flow_id: u64,
        target: Target,
        result: Result<TcpStream, OpenFailure>,
    },
    UdpOpenCompleted {
        flow_id: u64,
        target: Target,
        result: Result<UdpSocket, OpenFailure>,
    },
    ReadClosed(u64),
    UdpReadClosed(u64),
    HalfCloseDrainExpired {
        flow_id: u64,
        token: FlowToken,
        closed_side: HalfCloseSide,
    },
    WriteClosed(u64),
    Activity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HalfCloseSide {
    TargetToClient,
    ClientToTarget,
}

enum SessionEvent {
    Flow(Option<FlowEvent>),
    Frame(Frame),
    FrameReadError(FrameIoError),
    IdleTimeout,
    PeerClosed,
    Shutdown,
}

#[derive(Debug)]
enum TargetCommand {
    Data(BufferedTargetData),
    Close,
}

#[derive(Debug)]
enum EnqueueError {
    Closed,
    ResourceLimit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpDataDisposition {
    UnknownFlow,
    OpeningFlow,
    OtherProtocolFlow,
    EmptyPayload,
    ForwardPayload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UdpDataDisposition {
    UnknownFlow,
    OpeningFlow,
    TcpFlow,
    ForwardPayload,
}

#[derive(Debug, Clone)]
struct SessionBufferControl {
    buffered_bytes: Arc<AtomicUsize>,
}

#[derive(Debug)]
struct BufferedTargetData {
    payload: Bytes,
    payload_len: usize,
    control: TargetFlowControl,
}

#[derive(Debug, Clone)]
struct TargetFlowControl {
    buffered_bytes: Arc<AtomicUsize>,
    session_buffer: SessionBufferControl,
    closed: Arc<AtomicBool>,
    aborted: Arc<AtomicBool>,
    abort_notify: Arc<Notify>,
}

#[derive(Debug, Clone)]
struct OpenDialLimiter {
    semaphore: Arc<Semaphore>,
}

#[derive(Debug, Clone)]
struct FlowTokenAllocator {
    next: Arc<AtomicU64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FlowToken(u64);

#[derive(Clone)]
struct OpenDialPermit {
    _permit: Arc<OwnedSemaphorePermit>,
}

#[derive(Debug)]
enum FlowSlot {
    OpeningTcp(OpenFlowCancel),
    OpeningUdp(OpenFlowCancel),
    Tcp(TargetFlow),
    Udp(UdpTargetFlow),
}

#[derive(Clone)]
struct OpenFlowCancel {
    cancelled: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

#[derive(Debug)]
struct TargetFlow {
    token: FlowToken,
    commands: Option<mpsc::Sender<TargetCommand>>,
    control: TargetFlowControl,
    target_to_client_open: bool,
    client_to_target_open: bool,
}

#[derive(Debug)]
struct UdpTargetFlow {
    socket: Arc<UdpSocket>,
    control: TargetFlowControl,
}

#[derive(Debug, Clone)]
struct SessionShutdown {
    closed: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

struct RelaySessionContext<'a> {
    credential: Credential,
    policy_set: Arc<PolicySet>,
    carrier_writer: &'a CarrierWriter,
    event_tx: &'a mpsc::UnboundedSender<FlowEvent>,
    limits: RelayLimits,
    shutdown: SessionShutdown,
    session_buffer: SessionBufferControl,
    open_dial_limiter: OpenDialLimiter,
    flow_tokens: FlowTokenAllocator,
}

struct TargetOpenTask {
    flow_id: u64,
    target: Target,
    credential: Credential,
    policy_set: Arc<PolicySet>,
    open_dial_limiter: OpenDialLimiter,
    target_connect_timeout: Option<Duration>,
    event_tx: mpsc::UnboundedSender<FlowEvent>,
    shutdown: SessionShutdown,
    cancel: OpenFlowCancel,
}

struct UdpOpenTask {
    flow_id: u64,
    target: Target,
    credential: Credential,
    policy_set: Arc<PolicySet>,
    open_dial_limiter: OpenDialLimiter,
    target_connect_timeout: Option<Duration>,
    event_tx: mpsc::UnboundedSender<FlowEvent>,
    shutdown: SessionShutdown,
    cancel: OpenFlowCancel,
}

pub(crate) async fn relay_session(
    carrier: TlsStream<TcpStream>,
    credential: Credential,
    policy_set: Arc<PolicySet>,
    limits: RelayLimits,
    idle_timeout: Option<Duration>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), AnyError> {
    let mut state = ServerSessionState::Authenticated;
    transition(&mut state, ServerSessionState::Relaying);

    let (mut carrier_reader, carrier_writer) = tokio::io::split(carrier);
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let mut target_writers = FlowTable::new();
    let shutdown = SessionShutdown::default();
    let session_buffer = SessionBufferControl::default();
    let open_dial_limiter = OpenDialLimiter::new(limits.max_outbound_dials_per_session);
    let flow_tokens = FlowTokenAllocator::default();
    let carrier_writer = CarrierWriter::new(carrier_writer, shutdown.clone());
    let context = RelaySessionContext {
        credential,
        policy_set,
        carrier_writer: &carrier_writer,
        event_tx: &event_tx,
        limits,
        shutdown: shutdown.clone(),
        session_buffer,
        open_dial_limiter,
        flow_tokens,
    };

    let result = loop {
        let event = match next_session_event(
            &mut carrier_reader,
            &mut event_rx,
            limits.frame,
            idle_timeout,
            &mut shutdown_rx,
        )
        .await
        {
            Ok(event) => event,
            Err(err) => break Err(err),
        };

        match event {
            SessionEvent::Flow(event) => {
                handle_flow_event(event, &context, &mut target_writers).await?;
            }
            SessionEvent::Frame(frame) => {
                if let Err(err) = handle_session_frame(frame, &context, &mut target_writers).await {
                    break Err(err);
                }
            }
            SessionEvent::FrameReadError(err) => {
                report_frame_io_error(context.carrier_writer, &err).await;
                break Err(err.into());
            }
            SessionEvent::IdleTimeout => {
                info!(event = "server.session.idle_timeout");
                break Ok(());
            }
            SessionEvent::PeerClosed => {
                info!(event = "server.session.peer_closed");
                break Ok(());
            }
            SessionEvent::Shutdown => {
                info!(event = "server.session.shutdown");
                break Ok(());
            }
        }
    };

    transition(&mut state, ServerSessionState::Closing);
    shutdown.close();
    close_target_flows(&mut target_writers);
    shutdown_carrier_writer(&carrier_writer).await;
    transition(&mut state, ServerSessionState::Closed);
    result
}

async fn handle_flow_event(
    event: Option<FlowEvent>,
    context: &RelaySessionContext<'_>,
    target_writers: &mut FlowTable,
) -> Result<(), AnyError> {
    match event {
        Some(FlowEvent::OpenCompleted {
            flow_id,
            target,
            result,
        }) => handle_tcp_open_completed(flow_id, target, result, context, target_writers).await?,
        Some(FlowEvent::UdpOpenCompleted {
            flow_id,
            target,
            result,
        }) => handle_udp_open_completed(flow_id, target, result, context, target_writers).await?,
        Some(FlowEvent::ReadClosed(flow_id)) => {
            handle_target_read_closed(flow_id, context, target_writers);
        }
        Some(FlowEvent::UdpReadClosed(flow_id)) => {
            if matches!(target_writers.get(&flow_id), Some(FlowSlot::Udp(_))) {
                remove_flow_slot(target_writers, flow_id);
                info!(event = "udp.closed", flow_id);
            }
        }
        Some(FlowEvent::HalfCloseDrainExpired {
            flow_id,
            token,
            closed_side,
        }) => {
            handle_half_close_drain_expired(flow_id, token, closed_side, context, target_writers)
                .await?;
        }
        Some(FlowEvent::WriteClosed(flow_id)) => {
            handle_target_write_closed(flow_id, target_writers);
        }
        Some(FlowEvent::Activity) | None => {}
    }
    Ok(())
}

fn handle_target_read_closed(
    flow_id: u64,
    context: &RelaySessionContext<'_>,
    target_writers: &mut FlowTable,
) {
    if let Some(target) = open_target_flow_mut(target_writers, flow_id) {
        let token = target.token;
        target.mark_target_to_client_closed();
        info!(event = "tcp.target_read_closed", flow_id);
        if target.client_to_target_open {
            if let Some(timeout) = context.limits.tcp_half_close_timeout {
                spawn_half_close_timer(
                    flow_id,
                    token,
                    HalfCloseSide::TargetToClient,
                    timeout,
                    context.event_tx.clone(),
                );
            }
        }
        if target.is_fully_closed() {
            remove_flow_slot(target_writers, flow_id);
            info!(event = "tcp.closed", flow_id);
        }
    }
}

async fn handle_half_close_drain_expired(
    flow_id: u64,
    token: FlowToken,
    closed_side: HalfCloseSide,
    context: &RelaySessionContext<'_>,
    target_writers: &mut FlowTable,
) -> Result<(), AnyError> {
    match expire_half_close_drain(flow_id, token, closed_side, target_writers) {
        HalfCloseDrainDecision::Ignored => {}
        HalfCloseDrainDecision::ClosePeer { remove } => {
            send_tcp_close(context.carrier_writer, flow_id, TCP_CLOSE_NORMAL).await?;
            if remove {
                remove_flow_slot(target_writers, flow_id);
                info!(event = "tcp.half_close_timeout", flow_id, side = ?closed_side);
            }
        }
    }
    Ok(())
}

fn expire_half_close_drain(
    flow_id: u64,
    token: FlowToken,
    closed_side: HalfCloseSide,
    target_writers: &mut FlowTable,
) -> HalfCloseDrainDecision {
    let Some(target) = open_target_flow_mut(target_writers, flow_id) else {
        return HalfCloseDrainDecision::Ignored;
    };
    if target.token != token {
        return HalfCloseDrainDecision::Ignored;
    }

    let should_close_peer = match closed_side {
        HalfCloseSide::TargetToClient
            if !target.target_to_client_open && target.client_to_target_open =>
        {
            target.close_client_to_target();
            true
        }
        HalfCloseSide::ClientToTarget
            if !target.client_to_target_open && target.target_to_client_open =>
        {
            target.abort();
            true
        }
        _ => false,
    };
    if should_close_peer {
        HalfCloseDrainDecision::ClosePeer {
            remove: target.is_fully_closed(),
        }
    } else {
        HalfCloseDrainDecision::Ignored
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HalfCloseDrainDecision {
    Ignored,
    ClosePeer { remove: bool },
}

fn handle_target_write_closed(flow_id: u64, target_writers: &mut FlowTable) {
    if let Some(target) = open_target_flow_mut(target_writers, flow_id) {
        target.mark_client_to_target_closed();
        if target.is_fully_closed() {
            remove_flow_slot(target_writers, flow_id);
            info!(event = "tcp.closed", flow_id);
        }
    }
}

async fn next_session_event(
    carrier_reader: &mut tokio::io::ReadHalf<TlsStream<TcpStream>>,
    event_rx: &mut mpsc::UnboundedReceiver<FlowEvent>,
    limits: FrameLimits,
    idle_timeout: Option<Duration>,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> Result<SessionEvent, AnyError> {
    if *shutdown_rx.borrow() {
        return Ok(SessionEvent::Shutdown);
    }

    if let Some(idle_timeout) = idle_timeout {
        tokio::select! {
            event = event_rx.recv() => Ok(SessionEvent::Flow(event)),
            frame = read_frame(carrier_reader, limits) => Ok(map_frame_event(frame)),
            changed = shutdown_rx.changed() => {
                let _ = changed;
                Ok(SessionEvent::Shutdown)
            }
            () = tokio::time::sleep(idle_timeout) => Ok(SessionEvent::IdleTimeout),
        }
    } else {
        tokio::select! {
            event = event_rx.recv() => Ok(SessionEvent::Flow(event)),
            frame = read_frame(carrier_reader, limits) => Ok(map_frame_event(frame)),
            changed = shutdown_rx.changed() => {
                let _ = changed;
                Ok(SessionEvent::Shutdown)
            }
        }
    }
}

fn map_frame_event(result: Result<Frame, FrameIoError>) -> SessionEvent {
    match result {
        Ok(frame) => SessionEvent::Frame(frame),
        Err(FrameIoError::Closed) => SessionEvent::PeerClosed,
        Err(err) => SessionEvent::FrameReadError(err),
    }
}

async fn handle_session_frame(
    frame: Frame,
    context: &RelaySessionContext<'_>,
    target_writers: &mut FlowTable,
) -> Result<(), AnyError> {
    match frame.header.frame_type {
        FrameType::TcpOpen => handle_tcp_open_frame(context, frame, target_writers).await,
        FrameType::TcpData => handle_tcp_data_frame(frame, context, target_writers).await,
        FrameType::TcpClose => handle_tcp_close_frame(frame, context, target_writers).await,
        FrameType::UdpOpen => handle_udp_open_frame(context, frame, target_writers).await,
        FrameType::UdpData => handle_udp_data_frame(frame, context, target_writers).await,
        FrameType::UdpClose => handle_udp_close_frame(frame, context, target_writers).await,
        FrameType::Error | FrameType::PolicyDenied | FrameType::ResourceLimit => {
            handle_client_flow_status_frame(frame, context, target_writers).await
        }
        FrameType::Ping => {
            validate_or_report_session_control_frame(&frame, context, FrameType::Ping).await?;
            write_pong(context.carrier_writer, &frame).await
        }
        FrameType::Pong => {
            validate_or_report_session_control_frame(&frame, context, FrameType::Pong).await?;
            Ok(())
        }
        _ => reject_unexpected_session_frame(&frame, context).await,
    }
}

async fn reject_unexpected_session_frame(
    frame: &Frame,
    context: &RelaySessionContext<'_>,
) -> Result<(), AnyError> {
    send_error(context.carrier_writer, frame.header.id, ErrorCode::Protocol).await?;
    Err("unexpected frame while relaying session".into())
}

async fn report_frame_io_error(writer: &CarrierWriter, error: &FrameIoError) {
    if let FrameIoError::Protocol(error) = error {
        let _ = send_error(writer, 0, ErrorCode::from_protocol_error(error)).await;
    }
}

async fn validate_or_report_session_control_frame(
    frame: &Frame,
    context: &RelaySessionContext<'_>,
    expected_type: FrameType,
) -> Result<(), AnyError> {
    if let Err(err) = validate_connection_frame(frame, expected_type) {
        send_error(context.carrier_writer, 0, ErrorCode::Protocol).await?;
        return Err(err.into());
    }
    Ok(())
}

#[cfg(test)]
fn validate_session_control_frame(frame: &Frame, expected_type: FrameType) -> Result<(), AnyError> {
    validate_connection_frame(frame, expected_type)?;
    Ok(())
}

async fn handle_tcp_data_frame(
    frame: Frame,
    context: &RelaySessionContext<'_>,
    target_writers: &mut FlowTable,
) -> Result<(), AnyError> {
    let flow_id = frame.header.id;
    if let Err(rejection) = validate_client_relay_flow_id(flow_id) {
        return reject_invalid_client_relay_flow_id(
            context,
            flow_id,
            rejection,
            "tcp data flow id must be non-zero",
        )
        .await;
    }
    match tcp_data_disposition(flow_id, &frame.payload, target_writers) {
        TcpDataDisposition::UnknownFlow | TcpDataDisposition::OtherProtocolFlow => {
            send_error(context.carrier_writer, flow_id, ErrorCode::Protocol).await?;
        }
        TcpDataDisposition::OpeningFlow => {
            send_error(context.carrier_writer, flow_id, ErrorCode::Protocol).await?;
            send_tcp_close(context.carrier_writer, flow_id, TCP_CLOSE_ERROR).await?;
            remove_flow_slot(target_writers, flow_id);
        }
        TcpDataDisposition::EmptyPayload => {}
        TcpDataDisposition::ForwardPayload => {
            forward_tcp_data_frame(flow_id, frame.payload, context, target_writers).await?;
        }
    }
    Ok(())
}

async fn forward_tcp_data_frame(
    flow_id: u64,
    payload: Bytes,
    context: &RelaySessionContext<'_>,
    target_writers: &mut FlowTable,
) -> Result<(), AnyError> {
    let mut should_remove = false;
    let mut should_send_resource_limit = false;
    let Some(target) = open_target_flow_mut(target_writers, flow_id) else {
        send_error(context.carrier_writer, flow_id, ErrorCode::Protocol).await?;
        return Ok(());
    };
    match target.enqueue_data(
        payload,
        context.limits.max_buffered_bytes_per_flow,
        context.limits.max_buffered_bytes_per_session,
    ) {
        Ok(()) => {}
        Err(EnqueueError::Closed) => {
            target.mark_client_to_target_closed();
            should_remove = target.is_fully_closed();
        }
        Err(EnqueueError::ResourceLimit) => {
            target.abort();
            should_remove = true;
            should_send_resource_limit = true;
        }
    }
    if should_send_resource_limit {
        send_resource_limit(context.carrier_writer, flow_id).await?;
        send_tcp_close(context.carrier_writer, flow_id, TCP_CLOSE_ERROR).await?;
    }
    if should_remove {
        remove_flow_slot(target_writers, flow_id);
    }
    Ok(())
}

async fn handle_tcp_close_frame(
    frame: Frame,
    context: &RelaySessionContext<'_>,
    target_writers: &mut FlowTable,
) -> Result<(), AnyError> {
    let flow_id = frame.header.id;
    if let Err(rejection) = validate_client_relay_flow_id(flow_id) {
        return reject_invalid_client_relay_flow_id(
            context,
            flow_id,
            rejection,
            "tcp close flow id must be non-zero",
        )
        .await;
    }
    let mut payload = frame.payload;
    let close = match TcpClose::decode(&mut payload) {
        Ok(close) => close,
        Err(err) => {
            send_error(context.carrier_writer, flow_id, ErrorCode::Protocol).await?;
            return Err(err.into());
        }
    };
    let mut should_report_protocol_error = false;
    let should_remove = match target_writers.get_mut(&flow_id) {
        Some(FlowSlot::OpeningTcp(_)) => true,
        Some(FlowSlot::Tcp(target)) => {
            if close.close_code == TCP_CLOSE_NORMAL {
                let should_start_drain_timer = target.target_to_client_open;
                let token = target.token;
                target.close_client_to_target();
                if should_start_drain_timer {
                    if let Some(timeout) = context.limits.tcp_half_close_timeout {
                        spawn_half_close_timer(
                            flow_id,
                            token,
                            HalfCloseSide::ClientToTarget,
                            timeout,
                            context.event_tx.clone(),
                        );
                    }
                }
            } else {
                target.abort();
            }
            target.is_fully_closed()
        }
        Some(FlowSlot::OpeningUdp(_) | FlowSlot::Udp(_)) => {
            should_report_protocol_error = true;
            false
        }
        None => false,
    };
    if should_report_protocol_error {
        send_error(context.carrier_writer, flow_id, ErrorCode::Protocol).await?;
    }
    if should_remove {
        remove_flow_slot(target_writers, flow_id);
    }
    Ok(())
}

async fn handle_client_flow_status_frame(
    frame: Frame,
    context: &RelaySessionContext<'_>,
    target_writers: &mut FlowTable,
) -> Result<(), AnyError> {
    let flow_id = frame.header.id;
    if flow_id == 0 && frame.header.frame_type == FrameType::Error {
        validate_client_flow_status_payload(frame.header.frame_type, frame.payload)?;
        return Err("connection error from client".into());
    }
    if let Err(rejection) = validate_client_relay_flow_id(flow_id) {
        return reject_invalid_client_relay_flow_id(
            context,
            flow_id,
            rejection,
            "flow status id must be non-zero",
        )
        .await;
    }
    if let Err(err) = validate_client_flow_status_payload(frame.header.frame_type, frame.payload) {
        send_error(context.carrier_writer, flow_id, ErrorCode::Protocol).await?;
        return Err(err);
    }

    abort_client_flow(flow_id, target_writers);
    Ok(())
}

fn abort_client_flow(flow_id: u64, target_writers: &mut FlowTable) {
    let should_remove = match target_writers.get_mut(&flow_id) {
        Some(FlowSlot::OpeningTcp(_) | FlowSlot::OpeningUdp(_)) => true,
        Some(FlowSlot::Tcp(target)) => {
            target.abort();
            true
        }
        Some(FlowSlot::Udp(target)) => {
            target.abort();
            true
        }
        None => false,
    };
    if should_remove {
        remove_flow_slot(target_writers, flow_id);
        info!(event = "tcp.client_flow_aborted", flow_id);
    }
}

fn validate_client_flow_status_payload(
    frame_type: FrameType,
    mut payload: Bytes,
) -> Result<(), AnyError> {
    let status = ErrorPayload::decode(&mut payload)?;
    match frame_type {
        FrameType::Error => Ok(()),
        FrameType::PolicyDenied if status.code == ErrorCode::PolicyDenied => Ok(()),
        FrameType::ResourceLimit if status.code == ErrorCode::ResourceLimit => Ok(()),
        FrameType::PolicyDenied | FrameType::ResourceLimit => {
            Err("unexpected client flow status code".into())
        }
        _ => Err("unexpected client flow status frame".into()),
    }
}

async fn reject_invalid_client_relay_flow_id(
    context: &RelaySessionContext<'_>,
    flow_id: u64,
    rejection: FlowIdRejection,
    zero_id_error: &'static str,
) -> Result<(), AnyError> {
    send_error(context.carrier_writer, flow_id, ErrorCode::Protocol).await?;
    match rejection {
        FlowIdRejection::Zero => Err(zero_id_error.into()),
        FlowIdRejection::Reserved => {
            send_tcp_close(context.carrier_writer, flow_id, TCP_CLOSE_ERROR).await?;
            Ok(())
        }
    }
}

async fn reject_invalid_udp_relay_flow_id(
    context: &RelaySessionContext<'_>,
    flow_id: u64,
    rejection: FlowIdRejection,
    zero_id_error: &'static str,
) -> Result<(), AnyError> {
    send_error(context.carrier_writer, flow_id, ErrorCode::Protocol).await?;
    match rejection {
        FlowIdRejection::Zero => Err(zero_id_error.into()),
        FlowIdRejection::Reserved => {
            send_udp_close(context.carrier_writer, flow_id, UDP_CLOSE_ERROR).await?;
            Ok(())
        }
    }
}

fn check_open_slot(
    flow_id: u64,
    target_writers: &FlowTable,
    max_streams: u64,
) -> Result<(), OpenSlotRejection> {
    if !is_client_initiated_flow_id(flow_id) {
        return Ok(());
    }
    if target_writers.contains_key(&flow_id) {
        return Err(OpenSlotRejection::DuplicateFlowId);
    }
    if target_writers.len() as u64 >= max_streams {
        return Err(OpenSlotRejection::ResourceLimit);
    }
    Ok(())
}

fn validate_client_relay_flow_id(flow_id: u64) -> Result<(), FlowIdRejection> {
    if flow_id == 0 {
        Err(FlowIdRejection::Zero)
    } else if !is_client_initiated_flow_id(flow_id) {
        Err(FlowIdRejection::Reserved)
    } else {
        Ok(())
    }
}

fn tcp_data_disposition(
    flow_id: u64,
    payload: &Bytes,
    target_writers: &FlowTable,
) -> TcpDataDisposition {
    match target_writers.get(&flow_id) {
        None => TcpDataDisposition::UnknownFlow,
        Some(FlowSlot::OpeningTcp(_)) => TcpDataDisposition::OpeningFlow,
        Some(FlowSlot::OpeningUdp(_) | FlowSlot::Udp(_)) => TcpDataDisposition::OtherProtocolFlow,
        Some(FlowSlot::Tcp(_)) if payload.is_empty() => TcpDataDisposition::EmptyPayload,
        Some(FlowSlot::Tcp(_)) => TcpDataDisposition::ForwardPayload,
    }
}

async fn handle_tcp_open_frame(
    context: &RelaySessionContext<'_>,
    frame: Frame,
    target_writers: &mut FlowTable,
) -> Result<(), AnyError> {
    match check_open_slot(frame.header.id, target_writers, context.limits.max_streams) {
        Ok(()) => {}
        Err(OpenSlotRejection::DuplicateFlowId) => {
            send_error(context.carrier_writer, frame.header.id, ErrorCode::Protocol).await?;
            send_tcp_close(context.carrier_writer, frame.header.id, TCP_CLOSE_ERROR).await?;
            return Ok(());
        }
        Err(OpenSlotRejection::ResourceLimit) => {
            send_resource_limit(context.carrier_writer, frame.header.id).await?;
            send_tcp_close(context.carrier_writer, frame.header.id, TCP_CLOSE_ERROR).await?;
            return Ok(());
        }
    }

    if let Some((flow_id, target)) = validate_tcp_open_request(context, frame).await? {
        let cancel = OpenFlowCancel::default();
        target_writers.insert(flow_id, FlowSlot::OpeningTcp(cancel.clone()));
        spawn_target_open(TargetOpenTask {
            flow_id,
            target,
            credential: context.credential.clone(),
            policy_set: Arc::clone(&context.policy_set),
            open_dial_limiter: context.open_dial_limiter.clone(),
            target_connect_timeout: context.limits.target_connect_timeout,
            event_tx: context.event_tx.clone(),
            shutdown: context.shutdown.clone(),
            cancel,
        });
    }
    Ok(())
}

async fn validate_tcp_open_request(
    context: &RelaySessionContext<'_>,
    frame: Frame,
) -> Result<Option<(u64, Target)>, AnyError> {
    let flow_id = frame.header.id;
    if flow_id == 0 {
        send_error(context.carrier_writer, flow_id, ErrorCode::Protocol).await?;
        return Err("tcp flow id must be non-zero".into());
    }
    if !is_client_initiated_flow_id(flow_id) {
        send_error(context.carrier_writer, flow_id, ErrorCode::Protocol).await?;
        send_tcp_close(context.carrier_writer, flow_id, TCP_CLOSE_ERROR).await?;
        warn!(event = "tcp.open.reserved_flow_id", flow_id);
        return Ok(None);
    }

    let mut payload = frame.payload;
    let open = match TcpOpen::decode(&mut payload) {
        Ok(open) => open,
        Err(err) => {
            send_error(context.carrier_writer, flow_id, ErrorCode::InvalidTarget).await?;
            send_tcp_close(context.carrier_writer, flow_id, TCP_CLOSE_ERROR).await?;
            warn!(event = "tcp.open.invalid", flow_id, error = %err);
            return Ok(None);
        }
    };
    if open.open_flags != TCP_OPEN_FLAGS_NONE {
        send_error(context.carrier_writer, flow_id, ErrorCode::Protocol).await?;
        send_tcp_close(context.carrier_writer, flow_id, TCP_CLOSE_ERROR).await?;
        return Ok(None);
    }

    Ok(Some((flow_id, open.target)))
}

async fn handle_udp_open_frame(
    context: &RelaySessionContext<'_>,
    frame: Frame,
    target_writers: &mut FlowTable,
) -> Result<(), AnyError> {
    match check_open_slot(frame.header.id, target_writers, context.limits.max_streams) {
        Ok(()) => {}
        Err(OpenSlotRejection::DuplicateFlowId) => {
            send_error(context.carrier_writer, frame.header.id, ErrorCode::Protocol).await?;
            send_udp_close(context.carrier_writer, frame.header.id, UDP_CLOSE_ERROR).await?;
            return Ok(());
        }
        Err(OpenSlotRejection::ResourceLimit) => {
            send_resource_limit(context.carrier_writer, frame.header.id).await?;
            send_udp_close(context.carrier_writer, frame.header.id, UDP_CLOSE_ERROR).await?;
            return Ok(());
        }
    }

    if let Some((flow_id, target)) = validate_udp_open_request(context, frame).await? {
        let cancel = OpenFlowCancel::default();
        target_writers.insert(flow_id, FlowSlot::OpeningUdp(cancel.clone()));
        spawn_udp_open(UdpOpenTask {
            flow_id,
            target,
            credential: context.credential.clone(),
            policy_set: Arc::clone(&context.policy_set),
            open_dial_limiter: context.open_dial_limiter.clone(),
            target_connect_timeout: context.limits.target_connect_timeout,
            event_tx: context.event_tx.clone(),
            shutdown: context.shutdown.clone(),
            cancel,
        });
    }
    Ok(())
}

async fn validate_udp_open_request(
    context: &RelaySessionContext<'_>,
    frame: Frame,
) -> Result<Option<(u64, Target)>, AnyError> {
    let flow_id = frame.header.id;
    if flow_id == 0 {
        send_error(context.carrier_writer, flow_id, ErrorCode::Protocol).await?;
        return Err("udp flow id must be non-zero".into());
    }
    if !is_client_initiated_flow_id(flow_id) {
        send_error(context.carrier_writer, flow_id, ErrorCode::Protocol).await?;
        send_udp_close(context.carrier_writer, flow_id, UDP_CLOSE_ERROR).await?;
        warn!(event = "udp.open.reserved_flow_id", flow_id);
        return Ok(None);
    }

    let mut payload = frame.payload;
    let open = match UdpOpen::decode(&mut payload) {
        Ok(open) => open,
        Err(err) => {
            send_error(
                context.carrier_writer,
                flow_id,
                ErrorCode::from_protocol_error(&err),
            )
            .await?;
            send_udp_close(context.carrier_writer, flow_id, UDP_CLOSE_ERROR).await?;
            warn!(event = "udp.open.invalid", flow_id, error = %err);
            return Ok(None);
        }
    };

    Ok(Some((flow_id, open.target)))
}

async fn handle_udp_data_frame(
    frame: Frame,
    context: &RelaySessionContext<'_>,
    target_writers: &mut FlowTable,
) -> Result<(), AnyError> {
    let flow_id = frame.header.id;
    if let Err(rejection) = validate_client_relay_flow_id(flow_id) {
        return reject_invalid_udp_relay_flow_id(
            context,
            flow_id,
            rejection,
            "udp data flow id must be non-zero",
        )
        .await;
    }
    match udp_data_disposition(flow_id, target_writers) {
        UdpDataDisposition::UnknownFlow | UdpDataDisposition::TcpFlow => {
            send_error(context.carrier_writer, flow_id, ErrorCode::Protocol).await?;
        }
        UdpDataDisposition::OpeningFlow => {
            send_error(context.carrier_writer, flow_id, ErrorCode::Protocol).await?;
            send_udp_close(context.carrier_writer, flow_id, UDP_CLOSE_ERROR).await?;
            remove_flow_slot(target_writers, flow_id);
        }
        UdpDataDisposition::ForwardPayload => {
            forward_udp_data_frame(flow_id, frame.payload, context, target_writers).await?;
        }
    }
    Ok(())
}

async fn forward_udp_data_frame(
    flow_id: u64,
    payload: Bytes,
    context: &RelaySessionContext<'_>,
    target_writers: &mut FlowTable,
) -> Result<(), AnyError> {
    let Some(target) = udp_target_flow_mut(target_writers, flow_id) else {
        send_error(context.carrier_writer, flow_id, ErrorCode::Protocol).await?;
        return Ok(());
    };
    if let Err(err) = target.socket.send(&payload).await {
        warn!(event = "udp.target.write.error", flow_id, error = %err);
        send_error(
            context.carrier_writer,
            flow_id,
            ErrorCode::TargetUnavailable,
        )
        .await?;
        send_udp_close(context.carrier_writer, flow_id, UDP_CLOSE_ERROR).await?;
        remove_flow_slot(target_writers, flow_id);
    }
    Ok(())
}

async fn handle_udp_close_frame(
    frame: Frame,
    context: &RelaySessionContext<'_>,
    target_writers: &mut FlowTable,
) -> Result<(), AnyError> {
    let flow_id = frame.header.id;
    if let Err(rejection) = validate_client_relay_flow_id(flow_id) {
        return reject_invalid_udp_relay_flow_id(
            context,
            flow_id,
            rejection,
            "udp close flow id must be non-zero",
        )
        .await;
    }
    let mut payload = frame.payload;
    let close = match UdpClose::decode(&mut payload) {
        Ok(close) => close,
        Err(err) => {
            send_error(context.carrier_writer, flow_id, ErrorCode::Protocol).await?;
            return Err(err.into());
        }
    };
    let should_remove = match target_writers.get_mut(&flow_id) {
        Some(FlowSlot::OpeningUdp(_)) => true,
        Some(FlowSlot::Udp(target)) => {
            if close.close_code != UDP_CLOSE_NORMAL {
                target.abort();
            }
            true
        }
        Some(FlowSlot::OpeningTcp(_) | FlowSlot::Tcp(_)) => {
            send_error(context.carrier_writer, flow_id, ErrorCode::Protocol).await?;
            false
        }
        None => false,
    };
    if should_remove {
        remove_flow_slot(target_writers, flow_id);
    }
    Ok(())
}

fn udp_data_disposition(flow_id: u64, target_writers: &FlowTable) -> UdpDataDisposition {
    match target_writers.get(&flow_id) {
        None => UdpDataDisposition::UnknownFlow,
        Some(FlowSlot::OpeningUdp(_)) => UdpDataDisposition::OpeningFlow,
        Some(FlowSlot::OpeningTcp(_) | FlowSlot::Tcp(_)) => UdpDataDisposition::TcpFlow,
        Some(FlowSlot::Udp(_)) => UdpDataDisposition::ForwardPayload,
    }
}

fn spawn_target_open(task: TargetOpenTask) {
    tokio::spawn(async move {
        tokio::select! {
            result = connect_allowed_target(
                &task.target,
                &task.credential,
                &task.policy_set,
                &task.open_dial_limiter,
                task.target_connect_timeout,
            ) => {
                if !task.shutdown.is_closed() && !task.cancel.is_cancelled() {
                    let _ = task.event_tx.send(FlowEvent::OpenCompleted {
                        flow_id: task.flow_id,
                        target: task.target,
                        result,
                    });
                }
            }
            () = task.cancel.cancelled() => {}
        }
    });
}

fn spawn_udp_open(task: UdpOpenTask) {
    tokio::spawn(async move {
        tokio::select! {
            result = connect_allowed_udp_target(
                &task.target,
                &task.credential,
                &task.policy_set,
                &task.open_dial_limiter,
                task.target_connect_timeout,
            ) => {
                if !task.shutdown.is_closed() && !task.cancel.is_cancelled() {
                    let _ = task.event_tx.send(FlowEvent::UdpOpenCompleted {
                        flow_id: task.flow_id,
                        target: task.target,
                        result,
                    });
                }
            }
            () = task.cancel.cancelled() => {}
        }
    });
}

async fn handle_tcp_open_completed(
    flow_id: u64,
    target: Target,
    result: Result<TcpStream, OpenFailure>,
    context: &RelaySessionContext<'_>,
    target_writers: &mut FlowTable,
) -> Result<(), AnyError> {
    if !matches!(target_writers.get(&flow_id), Some(FlowSlot::OpeningTcp(_))) {
        return Ok(());
    }

    match result {
        Ok(target_stream) => {
            let target_flow = accept_open_target(flow_id, target, target_stream, context).await?;
            target_writers.insert(flow_id, FlowSlot::Tcp(target_flow));
        }
        Err(err) => {
            reject_open_failure(flow_id, &target, err, context).await?;
            remove_flow_slot(target_writers, flow_id);
        }
    }
    Ok(())
}

async fn handle_udp_open_completed(
    flow_id: u64,
    target: Target,
    result: Result<UdpSocket, OpenFailure>,
    context: &RelaySessionContext<'_>,
    target_writers: &mut FlowTable,
) -> Result<(), AnyError> {
    if !matches!(target_writers.get(&flow_id), Some(FlowSlot::OpeningUdp(_))) {
        return Ok(());
    }

    match result {
        Ok(target_socket) => {
            let target_flow =
                accept_open_udp_target(flow_id, target, target_socket, context).await?;
            target_writers.insert(flow_id, FlowSlot::Udp(target_flow));
        }
        Err(err) => {
            reject_udp_open_failure(flow_id, &target, err, context).await?;
            remove_flow_slot(target_writers, flow_id);
        }
    }
    Ok(())
}

async fn accept_open_target(
    flow_id: u64,
    target: Target,
    target_stream: TcpStream,
    context: &RelaySessionContext<'_>,
) -> Result<TargetFlow, AnyError> {
    let (target_reader, target_writer) = target_stream.into_split();
    let (target_writer_tx, target_writer_rx) = mpsc::channel(TARGET_WRITE_QUEUE_CAPACITY);
    let flow_control = TargetFlowControl::new(context.session_buffer.clone());
    let token = context.flow_tokens.next();
    let target_flow = TargetFlow::new(token, target_writer_tx, flow_control.clone());
    send_tcp_data(context.carrier_writer, flow_id, Bytes::new()).await?;
    spawn_target_reader(
        flow_id,
        target_reader,
        flow_control.clone(),
        context.carrier_writer.clone(),
        context.event_tx.clone(),
        context.shutdown.clone(),
        context.limits.data_frame_size,
    );
    spawn_target_writer(
        flow_id,
        target_writer,
        target_writer_rx,
        flow_control,
        context.carrier_writer.clone(),
        context.event_tx.clone(),
        context.shutdown.clone(),
    );
    info!(event = "tcp.open", flow_id, target = ?target);
    Ok(target_flow)
}

async fn accept_open_udp_target(
    flow_id: u64,
    target: Target,
    target_socket: UdpSocket,
    context: &RelaySessionContext<'_>,
) -> Result<UdpTargetFlow, AnyError> {
    let target_socket = Arc::new(target_socket);
    let flow_control = TargetFlowControl::new(context.session_buffer.clone());
    let target_flow = UdpTargetFlow::new(Arc::clone(&target_socket), flow_control.clone());
    send_udp_data(context.carrier_writer, flow_id, Bytes::new()).await?;
    spawn_udp_reader(
        flow_id,
        target_socket,
        flow_control,
        context.carrier_writer.clone(),
        context.event_tx.clone(),
        context.shutdown.clone(),
        context.limits.data_frame_size,
    );
    info!(event = "udp.open", flow_id, target = ?target);
    Ok(target_flow)
}

async fn reject_open_failure(
    flow_id: u64,
    target: &Target,
    failure: OpenFailure,
    context: &RelaySessionContext<'_>,
) -> Result<(), AnyError> {
    match failure {
        OpenFailure::PolicyDenied => {
            warn!(event = "policy.denied", flow_id, target = ?target);
            send_policy_denied(context.carrier_writer, flow_id).await?;
            send_tcp_close(context.carrier_writer, flow_id, TCP_CLOSE_NORMAL).await?;
        }
        OpenFailure::ResourceLimit => {
            warn!(event = "tcp.open.dial_limit", flow_id, target = ?target);
            send_resource_limit(context.carrier_writer, flow_id).await?;
            send_tcp_close(context.carrier_writer, flow_id, TCP_CLOSE_ERROR).await?;
        }
        OpenFailure::TargetUnavailable(err) => {
            warn!(event = "target.unavailable", flow_id, target = ?target, error = %err);
            send_error(
                context.carrier_writer,
                flow_id,
                ErrorCode::TargetUnavailable,
            )
            .await?;
            send_tcp_close(context.carrier_writer, flow_id, TCP_CLOSE_ERROR).await?;
        }
        OpenFailure::TargetTimeout => {
            warn!(event = "target.timeout", flow_id, target = ?target);
            send_error(context.carrier_writer, flow_id, ErrorCode::TargetTimeout).await?;
            send_tcp_close(context.carrier_writer, flow_id, TCP_CLOSE_ERROR).await?;
        }
    }
    Ok(())
}

async fn reject_udp_open_failure(
    flow_id: u64,
    target: &Target,
    failure: OpenFailure,
    context: &RelaySessionContext<'_>,
) -> Result<(), AnyError> {
    match failure {
        OpenFailure::PolicyDenied => {
            warn!(event = "udp.policy.denied", flow_id, target = ?target);
            send_policy_denied(context.carrier_writer, flow_id).await?;
            send_udp_close(context.carrier_writer, flow_id, UDP_CLOSE_NORMAL).await?;
        }
        OpenFailure::ResourceLimit => {
            warn!(event = "udp.open.dial_limit", flow_id, target = ?target);
            send_resource_limit(context.carrier_writer, flow_id).await?;
            send_udp_close(context.carrier_writer, flow_id, UDP_CLOSE_ERROR).await?;
        }
        OpenFailure::TargetUnavailable(err) => {
            warn!(event = "udp.target.unavailable", flow_id, target = ?target, error = %err);
            send_error(
                context.carrier_writer,
                flow_id,
                ErrorCode::TargetUnavailable,
            )
            .await?;
            send_udp_close(context.carrier_writer, flow_id, UDP_CLOSE_ERROR).await?;
        }
        OpenFailure::TargetTimeout => {
            warn!(event = "udp.target.timeout", flow_id, target = ?target);
            send_error(context.carrier_writer, flow_id, ErrorCode::TargetTimeout).await?;
            send_udp_close(context.carrier_writer, flow_id, UDP_CLOSE_ERROR).await?;
        }
    }
    Ok(())
}

fn spawn_target_reader(
    flow_id: u64,
    target_reader: OwnedReadHalf,
    flow_control: TargetFlowControl,
    carrier_writer: CarrierWriter,
    event_tx: mpsc::UnboundedSender<FlowEvent>,
    shutdown: SessionShutdown,
    data_frame_size: usize,
) {
    tokio::spawn(async move {
        match relay_target_to_client(
            flow_id,
            target_reader,
            flow_control,
            &carrier_writer,
            &event_tx,
            &shutdown,
            data_frame_size,
        )
        .await
        {
            Err(err) if !shutdown.is_closed() => {
                warn!(event = "tcp.target.read.error", flow_id, error = %err);
                let _ = send_error(&carrier_writer, flow_id, ErrorCode::TargetUnavailable).await;
                let _ = send_tcp_close(&carrier_writer, flow_id, TCP_CLOSE_ERROR).await;
            }
            _ => {}
        }
        let _ = event_tx.send(FlowEvent::ReadClosed(flow_id));
    });
}

fn spawn_udp_reader(
    flow_id: u64,
    target_socket: Arc<UdpSocket>,
    flow_control: TargetFlowControl,
    carrier_writer: CarrierWriter,
    event_tx: mpsc::UnboundedSender<FlowEvent>,
    shutdown: SessionShutdown,
    data_frame_size: usize,
) {
    tokio::spawn(async move {
        match relay_udp_target_to_client(
            flow_id,
            target_socket,
            flow_control,
            &carrier_writer,
            &event_tx,
            &shutdown,
            data_frame_size,
        )
        .await
        {
            Err(err) if !shutdown.is_closed() => {
                warn!(event = "udp.target.read.error", flow_id, error = %err);
                let _ = send_error(&carrier_writer, flow_id, ErrorCode::TargetUnavailable).await;
                let _ = send_udp_close(&carrier_writer, flow_id, UDP_CLOSE_ERROR).await;
            }
            _ => {}
        }
        let _ = event_tx.send(FlowEvent::UdpReadClosed(flow_id));
    });
}

fn spawn_target_writer(
    flow_id: u64,
    target_writer: OwnedWriteHalf,
    commands: mpsc::Receiver<TargetCommand>,
    flow_control: TargetFlowControl,
    carrier_writer: CarrierWriter,
    event_tx: mpsc::UnboundedSender<FlowEvent>,
    shutdown: SessionShutdown,
) {
    tokio::spawn(async move {
        match relay_client_to_target(target_writer, commands, flow_control, &event_tx, &shutdown)
            .await
        {
            Err(err) if !shutdown.is_closed() => {
                warn!(event = "tcp.target.write.error", flow_id, error = %err);
                let _ = send_error(&carrier_writer, flow_id, ErrorCode::TargetUnavailable).await;
                let _ = send_tcp_close(&carrier_writer, flow_id, TCP_CLOSE_ERROR).await;
            }
            _ => {}
        }
        let _ = event_tx.send(FlowEvent::WriteClosed(flow_id));
    });
}

fn spawn_half_close_timer(
    flow_id: u64,
    token: FlowToken,
    closed_side: HalfCloseSide,
    timeout: Duration,
    event_tx: mpsc::UnboundedSender<FlowEvent>,
) {
    tokio::spawn(async move {
        tokio::time::sleep(timeout).await;
        let _ = event_tx.send(FlowEvent::HalfCloseDrainExpired {
            flow_id,
            token,
            closed_side,
        });
    });
}

async fn relay_client_to_target(
    mut target_writer: OwnedWriteHalf,
    mut commands: mpsc::Receiver<TargetCommand>,
    flow_control: TargetFlowControl,
    event_tx: &mpsc::UnboundedSender<FlowEvent>,
    shutdown: &SessionShutdown,
) -> Result<(), AnyError> {
    loop {
        let command = tokio::select! {
            command = commands.recv() => command,
            () = shutdown.closed() => return Ok(()),
            () = flow_control.aborted() => return Ok(()),
        };
        let Some(command) = command else {
            break;
        };
        match command {
            TargetCommand::Data(buffered_data) => {
                if flow_control.is_aborted() || shutdown.is_closed() {
                    return Ok(());
                }

                let write_result = tokio::select! {
                    result = target_writer.write_all(buffered_data.payload()) => result,
                    () = shutdown.closed() => return Ok(()),
                    () = flow_control.aborted() => return Ok(()),
                };
                write_result?;
                let _ = event_tx.send(FlowEvent::Activity);
            }
            TargetCommand::Close => {
                flow_control.close();
                target_writer.shutdown().await?;
                return Ok(());
            }
        }
    }
    if flow_control.is_closed() && !flow_control.is_aborted() && !shutdown.is_closed() {
        target_writer.shutdown().await?;
    }
    Ok(())
}

impl RelayLimits {
    pub(crate) fn new(
        frame: FrameLimits,
        max_streams: u64,
        max_outbound_dials_per_session: usize,
        max_buffered_bytes_per_session: usize,
        max_buffered_bytes_per_flow: usize,
        target_connect_timeout: Option<Duration>,
        tcp_half_close_timeout: Option<Duration>,
    ) -> Self {
        Self {
            frame,
            max_streams,
            max_outbound_dials_per_session,
            data_frame_size: tcp_data_frame_size(frame),
            max_buffered_bytes_per_session,
            max_buffered_bytes_per_flow,
            target_connect_timeout,
            tcp_half_close_timeout,
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
    fn close(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            self.notify.notify_waiters();
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

impl Default for FlowTokenAllocator {
    fn default() -> Self {
        Self {
            next: Arc::new(AtomicU64::new(1)),
        }
    }
}

impl FlowTokenAllocator {
    fn next(&self) -> FlowToken {
        FlowToken(self.next.fetch_add(1, Ordering::Relaxed))
    }
}

impl OpenDialLimiter {
    fn new(limit: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(limit)),
        }
    }

    fn try_acquire(&self) -> Option<OpenDialPermit> {
        Arc::clone(&self.semaphore)
            .try_acquire_owned()
            .ok()
            .map(OpenDialPermit::new)
    }

    #[cfg(test)]
    fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }
}

impl OpenDialPermit {
    fn new(permit: OwnedSemaphorePermit) -> Self {
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

impl Default for OpenFlowCancel {
    fn default() -> Self {
        Self {
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
    fn cancel(&self) {
        if !self.cancelled.swap(true, Ordering::SeqCst) {
            self.notify.notify_waiters();
        }
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    async fn cancelled(&self) {
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

impl Default for TargetFlowControl {
    fn default() -> Self {
        Self::new(SessionBufferControl::default())
    }
}

impl TargetFlowControl {
    fn new(session_buffer: SessionBufferControl) -> Self {
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
    fn reserve_bytes(&self, amount: usize, flow_limit: usize, session_limit: usize) -> bool {
        if !reserve_bytes(&self.buffered_bytes, amount, flow_limit) {
            return false;
        }
        if !self.session_buffer.reserve_bytes(amount, session_limit) {
            release_bytes(&self.buffered_bytes, amount);
            return false;
        }
        true
    }

    fn release_bytes(&self, amount: usize) {
        release_bytes(&self.buffered_bytes, amount);
        self.session_buffer.release_bytes(amount);
    }

    #[cfg(test)]
    fn buffered_bytes(&self) -> usize {
        self.buffered_bytes.load(Ordering::SeqCst)
    }

    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    fn abort(&self) {
        if !self.aborted.swap(true, Ordering::SeqCst) {
            self.abort_notify.notify_waiters();
        }
        self.close();
    }

    fn is_aborted(&self) -> bool {
        self.aborted.load(Ordering::SeqCst)
    }

    async fn aborted(&self) {
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
    fn new(
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

    fn payload(&self) -> &[u8] {
        &self.payload
    }
}

impl Drop for BufferedTargetData {
    fn drop(&mut self) {
        self.control.release_bytes(self.payload_len);
    }
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
        match buffered_bytes.compare_exchange(current, next, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return true,
            Err(actual) => current = actual,
        }
    }
}

fn release_bytes(buffered_bytes: &AtomicUsize, amount: usize) {
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
    fn new(
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
        }
    }

    fn enqueue_data(
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

    fn close_client_to_target(&mut self) {
        if self.client_to_target_open {
            self.client_to_target_open = false;
            self.close_client_to_target_queue();
        }
    }

    fn close_client_to_target_queue(&mut self) {
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

    fn abort(&mut self) {
        self.target_to_client_open = false;
        self.client_to_target_open = false;
        self.control.abort();
        self.close_client_to_target_queue();
    }

    fn mark_target_to_client_closed(&mut self) {
        self.target_to_client_open = false;
    }

    fn mark_client_to_target_closed(&mut self) {
        self.client_to_target_open = false;
        self.control.close();
    }

    const fn is_fully_closed(&self) -> bool {
        !self.target_to_client_open && !self.client_to_target_open
    }
}

impl Drop for TargetFlow {
    fn drop(&mut self) {
        if !self.is_fully_closed() {
            self.target_to_client_open = false;
            self.client_to_target_open = false;
            self.control.abort();
            self.commands = None;
        }
    }
}

impl UdpTargetFlow {
    fn new(socket: Arc<UdpSocket>, control: TargetFlowControl) -> Self {
        Self { socket, control }
    }

    fn abort(&self) {
        self.control.abort();
    }
}

impl Drop for UdpTargetFlow {
    fn drop(&mut self) {
        self.abort();
    }
}

fn open_target_flow_mut(target_writers: &mut FlowTable, flow_id: u64) -> Option<&mut TargetFlow> {
    match target_writers.get_mut(&flow_id) {
        Some(FlowSlot::Tcp(target)) => Some(target),
        Some(FlowSlot::OpeningTcp(_) | FlowSlot::OpeningUdp(_) | FlowSlot::Udp(_)) | None => None,
    }
}

fn udp_target_flow_mut(target_writers: &mut FlowTable, flow_id: u64) -> Option<&mut UdpTargetFlow> {
    match target_writers.get_mut(&flow_id) {
        Some(FlowSlot::Udp(target)) => Some(target),
        Some(FlowSlot::OpeningTcp(_) | FlowSlot::OpeningUdp(_) | FlowSlot::Tcp(_)) | None => None,
    }
}

fn remove_flow_slot(target_writers: &mut FlowTable, flow_id: u64) -> Option<FlowSlot> {
    let slot = target_writers.remove(&flow_id);
    if let Some(FlowSlot::OpeningTcp(cancel) | FlowSlot::OpeningUdp(cancel)) = &slot {
        cancel.cancel();
    }
    slot
}

async fn relay_target_to_client(
    flow_id: u64,
    mut target_reader: OwnedReadHalf,
    flow_control: TargetFlowControl,
    carrier_writer: &CarrierWriter,
    event_tx: &mpsc::UnboundedSender<FlowEvent>,
    shutdown: &SessionShutdown,
    data_frame_size: usize,
) -> Result<(), AnyError> {
    let mut target_buf = vec![0_u8; data_frame_size].into_boxed_slice();
    loop {
        if shutdown.is_closed() || flow_control.is_aborted() {
            return Ok(());
        }
        let read = tokio::select! {
            read = target_reader.read(target_buf.as_mut()) => read?,
            () = shutdown.closed() => return Ok(()),
            () = flow_control.aborted() => return Ok(()),
        };
        if shutdown.is_closed() || flow_control.is_aborted() {
            return Ok(());
        }
        if read == 0 {
            send_tcp_close(carrier_writer, flow_id, TCP_CLOSE_NORMAL).await?;
            return Ok(());
        }
        send_tcp_data(
            carrier_writer,
            flow_id,
            Bytes::copy_from_slice(&target_buf[..read]),
        )
        .await?;
        let _ = event_tx.send(FlowEvent::Activity);
    }
}

async fn relay_udp_target_to_client(
    flow_id: u64,
    target_socket: Arc<UdpSocket>,
    flow_control: TargetFlowControl,
    carrier_writer: &CarrierWriter,
    event_tx: &mpsc::UnboundedSender<FlowEvent>,
    shutdown: &SessionShutdown,
    data_frame_size: usize,
) -> Result<(), AnyError> {
    let mut target_buf = vec![0_u8; data_frame_size].into_boxed_slice();
    loop {
        if shutdown.is_closed() || flow_control.is_aborted() {
            return Ok(());
        }
        let read = tokio::select! {
            read = target_socket.recv(target_buf.as_mut()) => read?,
            () = shutdown.closed() => return Ok(()),
            () = flow_control.aborted() => return Ok(()),
        };
        if shutdown.is_closed() || flow_control.is_aborted() {
            return Ok(());
        }
        send_udp_data(
            carrier_writer,
            flow_id,
            Bytes::copy_from_slice(&target_buf[..read]),
        )
        .await?;
        let _ = event_tx.send(FlowEvent::Activity);
    }
}

fn close_target_flows(target_writers: &mut FlowTable) {
    for slot in target_writers.drain().map(|(_, target)| target) {
        match slot {
            FlowSlot::OpeningTcp(cancel) | FlowSlot::OpeningUdp(cancel) => cancel.cancel(),
            FlowSlot::Tcp(mut target) => target.close_client_to_target(),
            FlowSlot::Udp(target) => target.abort(),
        }
    }
}

async fn shutdown_carrier_writer(carrier_writer: &CarrierWriter) {
    let mut writer = carrier_writer.inner.lock().await;
    if let Err(err) = writer.shutdown().await {
        debug!(event = "server.session.shutdown.error", error = %err);
    }
}

async fn connect_allowed_target(
    target: &Target,
    credential: &Credential,
    policy_set: &PolicySet,
    open_dial_limiter: &OpenDialLimiter,
    target_connect_timeout: Option<Duration>,
) -> Result<TcpStream, OpenFailure> {
    with_optional_timeout(
        target_connect_timeout,
        connect_allowed_target_inner(target, credential, policy_set, open_dial_limiter),
    )
    .await
}

async fn connect_allowed_target_inner(
    target: &Target,
    credential: &Credential,
    policy_set: &PolicySet,
    open_dial_limiter: &OpenDialLimiter,
) -> Result<TcpStream, OpenFailure> {
    let addrs = resolve_target(target).await?;
    let resolved_ips = resolved_ips(target, &addrs);
    let context = PolicyContext {
        key_id: &credential.key_id,
        policy_group: credential.policy_group.as_deref(),
        target,
        resolved_ips: &resolved_ips,
    };
    if policy_set.evaluate(&context) != PolicyDecision::Allow {
        return Err(OpenFailure::PolicyDenied);
    }
    connect_socket_addrs(&addrs, open_dial_limiter).await
}

async fn connect_allowed_udp_target(
    target: &Target,
    credential: &Credential,
    policy_set: &PolicySet,
    open_dial_limiter: &OpenDialLimiter,
    target_connect_timeout: Option<Duration>,
) -> Result<UdpSocket, OpenFailure> {
    with_optional_timeout(
        target_connect_timeout,
        connect_allowed_udp_target_inner(target, credential, policy_set, open_dial_limiter),
    )
    .await
}

async fn connect_allowed_udp_target_inner(
    target: &Target,
    credential: &Credential,
    policy_set: &PolicySet,
    open_dial_limiter: &OpenDialLimiter,
) -> Result<UdpSocket, OpenFailure> {
    let addrs = resolve_target(target).await?;
    let resolved_ips = resolved_ips(target, &addrs);
    let context = PolicyContext {
        key_id: &credential.key_id,
        policy_group: credential.policy_group.as_deref(),
        target,
        resolved_ips: &resolved_ips,
    };
    if policy_set.evaluate(&context) != PolicyDecision::Allow {
        return Err(OpenFailure::PolicyDenied);
    }
    connect_udp_socket_addrs(&addrs, open_dial_limiter).await
}

async fn resolve_target(target: &Target) -> Result<Vec<SocketAddr>, OpenFailure> {
    let addrs = match target {
        Target::Domain(domain, port) => lookup_host((domain.as_str(), *port))
            .await
            .map_err(OpenFailure::TargetUnavailable)?
            .collect(),
        Target::Ipv4(ip, port) => vec![SocketAddr::new(IpAddr::V4(*ip), *port)],
        Target::Ipv6(ip, port) => vec![SocketAddr::new(IpAddr::V6(*ip), *port)],
    };
    if addrs.is_empty() {
        Err(OpenFailure::TargetUnavailable(io::Error::new(
            io::ErrorKind::NotFound,
            "target resolved to no addresses",
        )))
    } else {
        Ok(addrs)
    }
}

fn resolved_ips(target: &Target, addrs: &[SocketAddr]) -> Vec<IpAddr> {
    match target {
        Target::Domain(_, _) => addrs.iter().map(SocketAddr::ip).collect(),
        Target::Ipv4(_, _) | Target::Ipv6(_, _) => Vec::new(),
    }
}

async fn connect_socket_addrs(
    addrs: &[SocketAddr],
    open_dial_limiter: &OpenDialLimiter,
) -> Result<TcpStream, OpenFailure> {
    let connector = target_connector();
    connect_first_successful(addrs, &connector, open_dial_limiter).await
}

async fn connect_udp_socket_addrs(
    addrs: &[SocketAddr],
    open_dial_limiter: &OpenDialLimiter,
) -> Result<UdpSocket, OpenFailure> {
    let connector = udp_target_connector();
    connect_first_successful(addrs, &connector, open_dial_limiter).await
}

fn target_connector() -> TargetConnector<TcpStream> {
    Arc::new(|addr| -> BoxedConnectFuture<TcpStream> { Box::pin(connect_socket_addr(addr)) })
}

fn udp_target_connector() -> TargetConnector<UdpSocket> {
    Arc::new(|addr| -> BoxedConnectFuture<UdpSocket> { Box::pin(connect_udp_socket_addr(addr)) })
}

async fn connect_socket_addr(addr: SocketAddr) -> (SocketAddr, io::Result<TcpStream>) {
    let result = match TcpStream::connect(addr).await {
        Ok(stream) => stream.set_nodelay(true).map(|()| stream),
        Err(err) => Err(err),
    };
    (addr, result)
}

async fn connect_udp_socket_addr(addr: SocketAddr) -> (SocketAddr, io::Result<UdpSocket>) {
    let bind_addr = match addr {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let result = async {
        let socket = UdpSocket::bind(bind_addr).await?;
        socket.connect(addr).await?;
        Ok(socket)
    }
    .await;
    (addr, result)
}

async fn connect_first_successful<T>(
    addrs: &[SocketAddr],
    connector: &TargetConnector<T>,
    open_dial_limiter: &OpenDialLimiter,
) -> Result<T, OpenFailure>
where
    T: Send + 'static,
{
    let mut tasks = JoinSet::new();
    let mut next_index = 0;

    let mut last_error = None;
    loop {
        spawn_target_connects(
            addrs,
            &mut next_index,
            &mut tasks,
            connector,
            open_dial_limiter,
        );
        if tasks.is_empty() {
            if next_index < addrs.len() {
                return Err(OpenFailure::ResourceLimit);
            }
            break;
        }

        let Some(result) = tasks.join_next().await else {
            break;
        };
        match result {
            Ok((addr, Ok(stream))) => {
                debug!(event = "target.connect.candidate_success", %addr);
                tasks.abort_all();
                return Ok(stream);
            }
            Ok((addr, Err(err))) => {
                debug!(event = "target.connect.candidate_failed", %addr, error = %err);
                last_error = Some(err);
            }
            Err(err) => {
                last_error = Some(io::Error::other(err));
            }
        }
    }

    Err(OpenFailure::TargetUnavailable(last_error.unwrap_or_else(
        || io::Error::new(io::ErrorKind::NotFound, "target has no socket addresses"),
    )))
}

fn spawn_target_connects<T>(
    addrs: &[SocketAddr],
    next_index: &mut usize,
    tasks: &mut JoinSet<(SocketAddr, io::Result<T>)>,
    connector: &TargetConnector<T>,
    open_dial_limiter: &OpenDialLimiter,
) where
    T: Send + 'static,
{
    while *next_index < addrs.len() && tasks.len() < TARGET_CONNECT_PARALLELISM {
        let Some(permit) = open_dial_limiter.try_acquire() else {
            break;
        };
        let addr = addrs[*next_index];
        *next_index += 1;
        let connector = Arc::clone(connector);
        tasks.spawn(async move {
            let permit_guard = permit;
            let result = connector(addr).await;
            drop(permit_guard);
            result
        });
    }
}

async fn with_optional_timeout<T, F>(
    duration: Option<Duration>,
    future: F,
) -> Result<T, OpenFailure>
where
    F: Future<Output = Result<T, OpenFailure>>,
{
    if let Some(duration) = duration {
        tokio::time::timeout(duration, future)
            .await
            .map_err(|_| OpenFailure::TargetTimeout)?
    } else {
        future.await
    }
}

async fn send_tcp_data(
    writer: &CarrierWriter,
    flow_id: u64,
    payload: Bytes,
) -> Result<(), AnyError> {
    let frame = Frame::new(FrameType::TcpData, 0, flow_id, payload)?;
    write_frame_locked(writer, &frame).await
}

async fn send_tcp_close(
    writer: &CarrierWriter,
    flow_id: u64,
    close_code: u16,
) -> Result<(), AnyError> {
    let mut payload = BytesMut::new();
    TcpClose::new(close_code).encode(&mut payload)?;
    let frame = Frame::new(FrameType::TcpClose, 0, flow_id, payload.freeze())?;
    write_frame_locked(writer, &frame).await
}

async fn send_udp_data(
    writer: &CarrierWriter,
    flow_id: u64,
    payload: Bytes,
) -> Result<(), AnyError> {
    let frame = Frame::new(FrameType::UdpData, 0, flow_id, payload)?;
    write_frame_locked(writer, &frame).await
}

async fn send_udp_close(
    writer: &CarrierWriter,
    flow_id: u64,
    close_code: u16,
) -> Result<(), AnyError> {
    let mut payload = BytesMut::new();
    UdpClose::new(close_code).encode(&mut payload)?;
    let frame = Frame::new(FrameType::UdpClose, 0, flow_id, payload.freeze())?;
    write_frame_locked(writer, &frame).await
}

async fn send_policy_denied(writer: &CarrierWriter, flow_id: u64) -> Result<(), AnyError> {
    send_status_frame(
        writer,
        FrameType::PolicyDenied,
        flow_id,
        ErrorCode::PolicyDenied,
    )
    .await
}

async fn send_resource_limit(writer: &CarrierWriter, flow_id: u64) -> Result<(), AnyError> {
    send_status_frame(
        writer,
        FrameType::ResourceLimit,
        flow_id,
        ErrorCode::ResourceLimit,
    )
    .await
}

async fn send_error(writer: &CarrierWriter, flow_id: u64, code: ErrorCode) -> Result<(), AnyError> {
    send_status_frame(writer, FrameType::Error, flow_id, code).await
}

async fn send_status_frame(
    writer: &CarrierWriter,
    frame_type: FrameType,
    flow_id: u64,
    code: ErrorCode,
) -> Result<(), AnyError> {
    let mut payload = BytesMut::new();
    ErrorPayload::new(code).encode(&mut payload)?;
    let frame = Frame::new(frame_type, 0, flow_id, payload.freeze())?;
    write_frame_locked(writer, &frame).await
}

async fn write_pong(writer: &CarrierWriter, request_frame: &Frame) -> Result<(), AnyError> {
    let pong_frame = Frame::new(
        FrameType::Pong,
        0,
        request_frame.header.id,
        request_frame.payload.clone(),
    )?;
    write_frame_locked(writer, &pong_frame).await
}

async fn write_frame_locked(writer: &CarrierWriter, frame: &Frame) -> Result<(), AnyError> {
    let mut guard = tokio::select! {
        writer = writer.inner.lock() => writer,
        () = writer.shutdown.closed() => return Err(session_shutdown_error().into()),
    };
    if writer.shutdown.is_closed() {
        return Err(session_shutdown_error().into());
    }
    write_frame_or_shutdown(&mut *guard, frame, &writer.shutdown).await?;
    Ok(())
}

async fn write_frame_or_shutdown<W>(
    writer: &mut W,
    frame: &Frame,
    shutdown: &SessionShutdown,
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

fn transition(state: &mut ServerSessionState, next: ServerSessionState) {
    let from = *state;
    debug_assert!(
        is_valid_session_transition(from, next),
        "invalid server session state transition"
    );
    debug!(event = "server.session.state", from = ?from, to = ?next);
    *state = next;
}

const fn is_valid_session_transition(from: ServerSessionState, next: ServerSessionState) -> bool {
    matches!(
        (from, next),
        (
            ServerSessionState::Authenticated,
            ServerSessionState::Relaying
        ) | (
            ServerSessionState::Relaying,
            ServerSessionState::Closing | ServerSessionState::Closed
        ) | (ServerSessionState::Closing, ServerSessionState::Closed)
    )
}

fn tcp_data_frame_size(limits: FrameLimits) -> usize {
    usize::try_from(limits.max_frame_size)
        .map_or(RELAY_BUFFER_SIZE, |limit| limit.min(RELAY_BUFFER_SIZE))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_FLOW_TOKEN: FlowToken = FlowToken(1);
    const STALE_FLOW_TOKEN: FlowToken = FlowToken(2);

    fn test_target_flow() -> TargetFlow {
        test_target_flow_with_token(TEST_FLOW_TOKEN)
    }

    fn test_target_flow_with_token(token: FlowToken) -> TargetFlow {
        let (commands, _commands_rx) = mpsc::channel(1);
        TargetFlow::new(token, commands, TargetFlowControl::default())
    }

    fn test_open_flow_slot() -> FlowSlot {
        FlowSlot::Tcp(test_target_flow())
    }

    fn test_opening_flow_slot() -> FlowSlot {
        FlowSlot::OpeningTcp(OpenFlowCancel::default())
    }

    async fn test_udp_flow() -> UdpTargetFlow {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        UdpTargetFlow::new(Arc::new(socket), TargetFlowControl::default())
    }

    fn control_frame(frame_type: FrameType, flow_id: u64) -> Frame {
        Frame::new(frame_type, 0, flow_id, Bytes::new()).unwrap()
    }

    fn status_payload(code: ErrorCode) -> Bytes {
        let mut payload = BytesMut::new();
        ErrorPayload::new(code).encode(&mut payload).unwrap();
        payload.freeze()
    }

    #[test]
    fn client_half_close_keeps_flow_reserved_until_target_read_closes() {
        let mut flow = test_target_flow();

        flow.close_client_to_target();

        assert!(!flow.client_to_target_open);
        assert!(flow.target_to_client_open);
        assert!(!flow.is_fully_closed());
        assert!(!flow.control.is_aborted());

        flow.mark_target_to_client_closed();

        assert!(flow.is_fully_closed());
    }

    #[test]
    fn target_read_close_keeps_flow_reserved_until_client_write_closes() {
        let mut flow = test_target_flow();

        flow.mark_target_to_client_closed();

        assert!(flow.client_to_target_open);
        assert!(!flow.target_to_client_open);
        assert!(!flow.is_fully_closed());

        flow.close_client_to_target();

        assert!(flow.is_fully_closed());
    }

    #[test]
    fn abort_marks_both_directions_closed() {
        let mut flow = test_target_flow();

        flow.abort();

        assert!(!flow.client_to_target_open);
        assert!(!flow.target_to_client_open);
        assert!(flow.is_fully_closed());
        assert!(flow.control.is_aborted());
    }

    #[test]
    fn dropping_open_target_flow_aborts_control() {
        let flow = test_target_flow();
        let control = flow.control.clone();

        drop(flow);

        assert!(control.is_aborted());
    }

    #[test]
    fn dropping_fully_closed_target_flow_does_not_abort_control() {
        let mut flow = test_target_flow();
        let control = flow.control.clone();
        flow.mark_target_to_client_closed();
        flow.mark_client_to_target_closed();

        drop(flow);

        assert!(!control.is_aborted());
    }

    #[test]
    fn stale_half_close_timer_does_not_affect_reused_flow_id() {
        let mut target_writers = FlowTable::new();
        let mut flow = test_target_flow_with_token(TEST_FLOW_TOKEN);
        flow.mark_target_to_client_closed();
        target_writers.insert(1, FlowSlot::Tcp(flow));

        assert_eq!(
            expire_half_close_drain(
                1,
                STALE_FLOW_TOKEN,
                HalfCloseSide::TargetToClient,
                &mut target_writers
            ),
            HalfCloseDrainDecision::Ignored
        );

        let target = open_target_flow_mut(&mut target_writers, 1).expect("flow should remain open");
        assert!(target.client_to_target_open);
        assert!(!target.control.is_closed());
    }

    #[test]
    fn matching_half_close_timer_closes_original_flow() {
        let mut target_writers = FlowTable::new();
        let mut flow = test_target_flow_with_token(TEST_FLOW_TOKEN);
        flow.mark_target_to_client_closed();
        target_writers.insert(1, FlowSlot::Tcp(flow));

        assert_eq!(
            expire_half_close_drain(
                1,
                TEST_FLOW_TOKEN,
                HalfCloseSide::TargetToClient,
                &mut target_writers
            ),
            HalfCloseDrainDecision::ClosePeer { remove: true }
        );

        let target = open_target_flow_mut(&mut target_writers, 1).expect("removal is caller-owned");
        assert!(!target.client_to_target_open);
        assert!(target.control.is_closed());
    }

    #[test]
    fn target_flow_control_tracks_buffered_bytes() {
        let session = SessionBufferControl::default();
        let control = TargetFlowControl::new(session.clone());

        assert!(control.reserve_bytes(8, 10, 16));
        assert_eq!(control.buffered_bytes(), 8);
        assert_eq!(session.buffered_bytes(), 8);
        assert!(!control.reserve_bytes(3, 10, 16));
        assert_eq!(control.buffered_bytes(), 8);
        assert_eq!(session.buffered_bytes(), 8);

        control.release_bytes(4);
        assert_eq!(control.buffered_bytes(), 4);
        assert_eq!(session.buffered_bytes(), 4);
        assert!(control.reserve_bytes(6, 10, 16));
        assert_eq!(control.buffered_bytes(), 10);
        assert_eq!(session.buffered_bytes(), 10);
    }

    #[test]
    fn target_flow_control_rejects_session_buffer_limit() {
        let session = SessionBufferControl::default();
        let first = TargetFlowControl::new(session.clone());
        let second = TargetFlowControl::new(session.clone());

        assert!(first.reserve_bytes(8, 10, 10));
        assert!(!second.reserve_bytes(3, 10, 10));

        assert_eq!(first.buffered_bytes(), 8);
        assert_eq!(second.buffered_bytes(), 0);
        assert_eq!(session.buffered_bytes(), 8);
    }

    #[test]
    fn target_flow_control_release_saturates_at_zero() {
        let session = SessionBufferControl::default();
        let control = TargetFlowControl::new(session.clone());

        control.release_bytes(1);
        assert_eq!(control.buffered_bytes(), 0);
        assert_eq!(session.buffered_bytes(), 0);

        assert!(control.reserve_bytes(5, 10, 10));
        control.release_bytes(8);
        assert_eq!(control.buffered_bytes(), 0);
        assert_eq!(session.buffered_bytes(), 0);
    }

    #[tokio::test]
    async fn session_shutdown_notifies_waiters() {
        let shutdown = SessionShutdown::default();
        let waiter = shutdown.clone();
        let task = tokio::spawn(async move {
            waiter.closed().await;
        });

        shutdown.close();

        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn carrier_write_exits_when_session_shutdown_notifies() {
        let (mut writer, _reader) = tokio::io::duplex(1);
        let shutdown = SessionShutdown::default();
        let shutdown_handle = shutdown.clone();
        let frame = Frame::new(FrameType::TcpData, 0, 1, Bytes::from(vec![0xaa; 1024])).unwrap();

        let write_task =
            tokio::spawn(
                async move { write_frame_or_shutdown(&mut writer, &frame, &shutdown).await },
            );
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!write_task.is_finished());

        shutdown_handle.close();

        let err = tokio::time::timeout(Duration::from_secs(1), write_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        let io_error = err.downcast_ref::<io::Error>().unwrap();
        assert_eq!(io_error.kind(), io::ErrorKind::Interrupted);
    }

    #[tokio::test]
    async fn target_flow_abort_notifies_waiters() {
        let control = TargetFlowControl::default();
        let waiter = control.clone();
        let task = tokio::spawn(async move {
            waiter.aborted().await;
        });

        control.abort();

        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn half_close_drops_full_target_queue_sender() {
        let (commands, mut commands_rx) = mpsc::channel(1);
        let mut flow = TargetFlow::new(TEST_FLOW_TOKEN, commands, TargetFlowControl::default());

        flow.enqueue_data(Bytes::from_static(b"queued"), 1024, 1024)
            .unwrap();
        flow.close_client_to_target();

        assert!(flow.commands.is_none());
        assert!(flow.control.is_closed());
        match commands_rx.recv().await {
            Some(TargetCommand::Data(payload)) => {
                assert_eq!(payload.payload(), b"queued");
            }
            other => panic!("unexpected target command: {other:?}"),
        }
        assert!(commands_rx.recv().await.is_none());
    }

    #[test]
    fn dropped_queued_target_data_releases_session_buffer() {
        let session = SessionBufferControl::default();
        let control = TargetFlowControl::new(session.clone());
        let (commands, commands_rx) = mpsc::channel(1);
        let mut flow = TargetFlow::new(TEST_FLOW_TOKEN, commands, control.clone());

        flow.enqueue_data(Bytes::from_static(b"queued"), 1024, 1024)
            .unwrap();
        assert_eq!(control.buffered_bytes(), 6);
        assert_eq!(session.buffered_bytes(), 6);

        drop(commands_rx);

        assert_eq!(control.buffered_bytes(), 0);
        assert_eq!(session.buffered_bytes(), 0);
    }

    #[tokio::test]
    async fn half_close_enqueues_close_when_target_queue_has_capacity() {
        let (commands, mut commands_rx) = mpsc::channel(1);
        let mut flow = TargetFlow::new(TEST_FLOW_TOKEN, commands, TargetFlowControl::default());

        flow.close_client_to_target();

        assert!(flow.commands.is_some());
        assert!(flow.control.is_closed());
        assert!(matches!(
            commands_rx.recv().await,
            Some(TargetCommand::Close)
        ));
    }

    #[tokio::test]
    async fn target_writer_exits_when_session_shutdown_notifies() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let target_stream = TcpStream::connect(addr).await.unwrap();
        let (_target_peer, _) = listener.accept().await.unwrap();
        let (_target_reader, target_writer) = target_stream.into_split();
        let (_commands_tx, commands_rx) = mpsc::channel(1);
        let (event_tx, _event_rx) = mpsc::unbounded_channel();
        let flow_control = TargetFlowControl::default();
        let shutdown = SessionShutdown::default();
        let shutdown_handle = shutdown.clone();

        let writer = tokio::spawn(async move {
            relay_client_to_target(
                target_writer,
                commands_rx,
                flow_control,
                &event_tx,
                &shutdown,
            )
            .await
        });
        shutdown_handle.close();

        tokio::time::timeout(Duration::from_secs(1), writer)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn target_writer_reports_activity_after_payload_write() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let target_stream = TcpStream::connect(addr).await.unwrap();
        let (mut target_peer, _) = listener.accept().await.unwrap();
        let (_target_reader, target_writer) = target_stream.into_split();
        let (commands_tx, commands_rx) = mpsc::channel(1);
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let flow_control = TargetFlowControl::default();
        let shutdown = SessionShutdown::default();
        let payload = Bytes::from_static(b"writer activity");
        let buffered_payload =
            BufferedTargetData::new(payload.clone(), flow_control.clone(), 1024, 1024).unwrap();

        commands_tx
            .send(TargetCommand::Data(buffered_payload))
            .await
            .unwrap();
        drop(commands_tx);

        let writer = relay_client_to_target(
            target_writer,
            commands_rx,
            flow_control,
            &event_tx,
            &shutdown,
        );
        let reader = async {
            let mut received = vec![0_u8; payload.len()];
            target_peer.read_exact(&mut received).await?;
            Ok::<_, io::Error>(received)
        };
        let (writer_result, reader_result) = tokio::join!(writer, reader);

        writer_result.unwrap();
        assert_eq!(reader_result.unwrap(), payload);
        assert!(matches!(event_rx.recv().await, Some(FlowEvent::Activity)));
    }

    #[test]
    fn duplicate_open_slot_is_protocol_error_before_stream_limit() {
        let mut target_writers = FlowTable::new();
        target_writers.insert(1, test_open_flow_slot());

        assert_eq!(
            check_open_slot(1, &target_writers, 1),
            Err(OpenSlotRejection::DuplicateFlowId)
        );
    }

    #[test]
    fn new_open_slot_rejects_resource_limit() {
        let mut target_writers = FlowTable::new();
        target_writers.insert(1, test_open_flow_slot());

        assert_eq!(
            check_open_slot(3, &target_writers, 1),
            Err(OpenSlotRejection::ResourceLimit)
        );
    }

    #[test]
    fn reserved_open_slot_is_left_for_protocol_validation() {
        let mut target_writers = FlowTable::new();
        target_writers.insert(1, test_open_flow_slot());

        assert_eq!(check_open_slot(2, &target_writers, 1), Ok(()));
    }

    #[test]
    fn validates_client_relay_flow_ids() {
        assert_eq!(validate_client_relay_flow_id(0), Err(FlowIdRejection::Zero));
        assert_eq!(
            validate_client_relay_flow_id(2),
            Err(FlowIdRejection::Reserved)
        );
        assert_eq!(validate_client_relay_flow_id(1), Ok(()));
    }

    #[test]
    fn validates_client_flow_status_payloads() {
        assert!(
            validate_client_flow_status_payload(
                FrameType::Error,
                status_payload(ErrorCode::Protocol)
            )
            .is_ok()
        );
        assert!(
            validate_client_flow_status_payload(
                FrameType::ResourceLimit,
                status_payload(ErrorCode::ResourceLimit)
            )
            .is_ok()
        );
        assert!(
            validate_client_flow_status_payload(
                FrameType::PolicyDenied,
                status_payload(ErrorCode::PolicyDenied)
            )
            .is_ok()
        );
        assert!(
            validate_client_flow_status_payload(
                FrameType::ResourceLimit,
                status_payload(ErrorCode::Protocol)
            )
            .is_err()
        );
        assert!(validate_client_flow_status_payload(FrameType::TcpData, Bytes::new()).is_err());
    }

    #[test]
    fn client_flow_status_aborts_open_flow() {
        let flow = test_target_flow();
        let control = flow.control.clone();
        let mut target_writers = FlowTable::new();
        target_writers.insert(1, FlowSlot::Tcp(flow));

        abort_client_flow(1, &mut target_writers);

        assert!(target_writers.is_empty());
        assert!(control.is_aborted());
    }

    #[test]
    fn client_flow_status_cancels_pending_open() {
        let cancel = OpenFlowCancel::default();
        let mut target_writers = FlowTable::new();
        target_writers.insert(1, FlowSlot::OpeningTcp(cancel.clone()));

        abort_client_flow(1, &mut target_writers);

        assert!(target_writers.is_empty());
        assert!(cancel.is_cancelled());
    }

    #[test]
    fn client_flow_status_ignores_unknown_flow() {
        let mut target_writers = FlowTable::new();

        abort_client_flow(1, &mut target_writers);

        assert!(target_writers.is_empty());
    }

    #[test]
    fn maps_clean_carrier_eof_to_peer_closed() {
        assert!(matches!(
            map_frame_event(Err(FrameIoError::Closed)),
            SessionEvent::PeerClosed
        ));
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
            validate_session_control_frame(&control_frame(FrameType::Ping, 1), FrameType::Ping)
                .is_err()
        );
        assert!(
            validate_session_control_frame(&control_frame(FrameType::Pong, 1), FrameType::Pong)
                .is_err()
        );
    }

    #[test]
    fn classifies_tcp_data_for_known_and_unknown_flows() {
        let mut target_writers = FlowTable::new();
        target_writers.insert(1, test_open_flow_slot());

        assert_eq!(
            tcp_data_disposition(3, &Bytes::from_static(b"data"), &target_writers),
            TcpDataDisposition::UnknownFlow
        );
        assert_eq!(
            tcp_data_disposition(1, &Bytes::new(), &target_writers),
            TcpDataDisposition::EmptyPayload
        );
        assert_eq!(
            tcp_data_disposition(1, &Bytes::from_static(b"data"), &target_writers),
            TcpDataDisposition::ForwardPayload
        );
    }

    #[tokio::test]
    async fn classifies_tcp_data_for_udp_flow_as_other_protocol() {
        let mut target_writers = FlowTable::new();
        target_writers.insert(1, FlowSlot::Udp(test_udp_flow().await));

        assert_eq!(
            tcp_data_disposition(1, &Bytes::from_static(b"data"), &target_writers),
            TcpDataDisposition::OtherProtocolFlow
        );
    }

    #[tokio::test]
    async fn classifies_udp_data_for_flow_kinds() {
        let mut target_writers = FlowTable::new();
        target_writers.insert(1, FlowSlot::Udp(test_udp_flow().await));
        target_writers.insert(3, FlowSlot::OpeningUdp(OpenFlowCancel::default()));
        target_writers.insert(5, test_open_flow_slot());
        target_writers.insert(7, test_opening_flow_slot());

        assert_eq!(
            udp_data_disposition(9, &target_writers),
            UdpDataDisposition::UnknownFlow
        );
        assert_eq!(
            udp_data_disposition(1, &target_writers),
            UdpDataDisposition::ForwardPayload
        );
        assert_eq!(
            udp_data_disposition(3, &target_writers),
            UdpDataDisposition::OpeningFlow
        );
        assert_eq!(
            udp_data_disposition(5, &target_writers),
            UdpDataDisposition::TcpFlow
        );
        assert_eq!(
            udp_data_disposition(7, &target_writers),
            UdpDataDisposition::TcpFlow
        );
    }

    #[test]
    fn pending_open_slot_counts_against_stream_limit() {
        let mut target_writers = FlowTable::new();
        target_writers.insert(1, test_opening_flow_slot());

        assert_eq!(
            check_open_slot(3, &target_writers, 1),
            Err(OpenSlotRejection::ResourceLimit)
        );
    }

    #[test]
    fn classifies_tcp_data_for_pending_open_flow() {
        let mut target_writers = FlowTable::new();
        target_writers.insert(1, test_opening_flow_slot());

        assert_eq!(
            tcp_data_disposition(1, &Bytes::from_static(b"early"), &target_writers),
            TcpDataDisposition::OpeningFlow
        );
    }

    #[test]
    fn removing_pending_open_slot_cancels_connect_task() {
        let cancel = OpenFlowCancel::default();
        let mut target_writers = FlowTable::new();
        target_writers.insert(1, FlowSlot::OpeningTcp(cancel.clone()));

        remove_flow_slot(&mut target_writers, 1);

        assert!(cancel.is_cancelled());
        assert!(target_writers.is_empty());
    }

    #[test]
    fn closing_session_cancels_pending_open_slots() {
        let cancel = OpenFlowCancel::default();
        let mut target_writers = FlowTable::new();
        target_writers.insert(1, FlowSlot::OpeningTcp(cancel.clone()));
        target_writers.insert(3, test_open_flow_slot());

        close_target_flows(&mut target_writers);

        assert!(cancel.is_cancelled());
        assert!(target_writers.is_empty());
    }

    #[tokio::test]
    async fn closing_session_aborts_udp_flows_and_cancels_pending_udp_opens() {
        let cancel = OpenFlowCancel::default();
        let udp_flow = test_udp_flow().await;
        let control = udp_flow.control.clone();
        let mut target_writers = FlowTable::new();
        target_writers.insert(1, FlowSlot::OpeningUdp(cancel.clone()));
        target_writers.insert(3, FlowSlot::Udp(udp_flow));

        close_target_flows(&mut target_writers);

        assert!(cancel.is_cancelled());
        assert!(control.is_aborted());
        assert!(target_writers.is_empty());
    }

    #[tokio::test]
    async fn optional_timeout_maps_elapsed_to_target_timeout() {
        let result = with_optional_timeout(Some(Duration::from_millis(1)), async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            Ok(())
        })
        .await;

        assert!(matches!(result, Err(OpenFailure::TargetTimeout)));
    }

    #[tokio::test]
    async fn target_connect_uses_later_candidate_while_first_is_pending() {
        let first_addr = SocketAddr::from(([127, 0, 0, 1], 10_001));
        let second_addr = SocketAddr::from(([127, 0, 0, 1], 10_002));
        let addrs = [first_addr, second_addr];
        let limiter = OpenDialLimiter::new(2);
        let connector: TargetConnector<SocketAddr> =
            Arc::new(move |addr| -> BoxedConnectFuture<SocketAddr> {
                Box::pin(async move {
                    if addr == first_addr {
                        tokio::time::sleep(Duration::from_secs(60)).await;
                        return (
                            addr,
                            Err(io::Error::new(io::ErrorKind::TimedOut, "still pending")),
                        );
                    }
                    (addr, Ok(addr))
                })
            });

        let connected = tokio::time::timeout(
            Duration::from_millis(100),
            connect_first_successful(&addrs, &connector, &limiter),
        )
        .await
        .expect("later candidate should complete before the first candidate")
        .expect("later candidate should succeed");

        assert_eq!(connected, second_addr);
    }

    #[tokio::test]
    async fn target_connect_rejects_when_dial_limiter_is_exhausted() {
        let addr = SocketAddr::from(([127, 0, 0, 1], 10_001));
        let addrs = [addr];
        let limiter = OpenDialLimiter::new(0);
        let calls = Arc::new(AtomicUsize::new(0));
        let connector: TargetConnector<SocketAddr> = {
            let calls = Arc::clone(&calls);
            Arc::new(move |addr| -> BoxedConnectFuture<SocketAddr> {
                let calls = Arc::clone(&calls);
                Box::pin(async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    (addr, Ok(addr))
                })
            })
        };

        let result = connect_first_successful(&addrs, &connector, &limiter).await;

        assert!(matches!(result, Err(OpenFailure::ResourceLimit)));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn target_connect_limits_concurrent_candidate_dials() {
        let first_addr = SocketAddr::from(([127, 0, 0, 1], 10_001));
        let second_addr = SocketAddr::from(([127, 0, 0, 1], 10_002));
        let addrs = [first_addr, second_addr];
        let limiter = OpenDialLimiter::new(1);
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let connector: TargetConnector<SocketAddr> = {
            let active = Arc::clone(&active);
            let max_active = Arc::clone(&max_active);
            Arc::new(move |addr| -> BoxedConnectFuture<SocketAddr> {
                let active = Arc::clone(&active);
                let max_active = Arc::clone(&max_active);
                Box::pin(async move {
                    let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                    max_active.fetch_max(current, Ordering::SeqCst);
                    let result = if addr == first_addr {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        Err(io::Error::new(io::ErrorKind::TimedOut, "first failed"))
                    } else {
                        Ok(addr)
                    };
                    active.fetch_sub(1, Ordering::SeqCst);
                    (addr, result)
                })
            })
        };

        let connected = tokio::time::timeout(
            Duration::from_secs(1),
            connect_first_successful(&addrs, &connector, &limiter),
        )
        .await
        .expect("connect should not hang")
        .expect("second candidate should succeed");

        assert_eq!(connected, second_addr);
        assert_eq!(max_active.load(Ordering::SeqCst), 1);
        assert_eq!(limiter.available_permits(), 1);
    }

    #[tokio::test]
    async fn udp_target_connect_binds_matching_ip_family() {
        let target = SocketAddr::from(([127, 0, 0, 1], 9));

        let (candidate, socket) = connect_udp_socket_addr(target).await;
        let socket = socket.unwrap();

        assert_eq!(candidate, target);
        assert!(socket.local_addr().unwrap().is_ipv4());
        assert_eq!(socket.peer_addr().unwrap(), target);
    }

    #[test]
    fn caps_tcp_data_frame_size_to_frame_limit() {
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
    fn accepts_server_session_transition_to_relaying() {
        let valid = [
            (
                ServerSessionState::Authenticated,
                ServerSessionState::Relaying,
            ),
            (ServerSessionState::Relaying, ServerSessionState::Closing),
            (ServerSessionState::Relaying, ServerSessionState::Closed),
            (ServerSessionState::Closing, ServerSessionState::Closed),
        ];

        for (from, next) in valid {
            assert!(is_valid_session_transition(from, next));
        }
    }

    #[test]
    fn rejects_server_session_state_regression() {
        assert!(!is_valid_session_transition(
            ServerSessionState::Relaying,
            ServerSessionState::Authenticated
        ));
        assert!(!is_valid_session_transition(
            ServerSessionState::Closed,
            ServerSessionState::Relaying
        ));
    }
}
