//! Server-side UK TCP relay.

use std::{
    collections::HashMap,
    error::Error,
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, WriteHalf},
    net::{
        TcpStream, lookup_host,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::{Mutex, mpsc},
};
use tokio_rustls::server::TlsStream;
use tracing::{debug, info, warn};
use uk_auth::Credential;
use uk_policy::{PolicyContext, PolicyDecision, PolicySet};
use uk_proto::{
    ErrorCode, ErrorPayload, Frame, FrameIoError, FrameLimits, FrameType, TCP_CLOSE_ERROR,
    TCP_CLOSE_NORMAL, TCP_OPEN_FLAGS_NONE, Target, TcpClose, TcpOpen, is_client_initiated_flow_id,
    read_frame, validate_connection_frame, write_frame,
};

const RELAY_BUFFER_SIZE: usize = 16 * 1024;
const TARGET_WRITE_QUEUE_CAPACITY: usize = 32;

type AnyError = Box<dyn Error + Send + Sync>;
type CarrierWriter = Arc<Mutex<WriteHalf<TlsStream<TcpStream>>>>;
type FlowTable = HashMap<u64, FlowSlot>;

#[derive(Debug, Clone, Copy)]
pub(crate) struct RelayLimits {
    frame: FrameLimits,
    max_streams: u64,
    data_frame_size: usize,
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
    ReadClosed(u64),
    ReadDrainExpired(u64),
    WriteClosed(u64),
    Activity,
}

enum SessionEvent {
    Flow(Option<FlowEvent>),
    Frame(Frame),
    IdleTimeout,
    PeerClosed,
}

#[derive(Debug)]
enum TargetCommand {
    Data(Bytes),
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
    EmptyPayload,
    ForwardPayload,
}

#[derive(Debug, Clone)]
struct TargetFlowControl {
    buffered_bytes: Arc<AtomicUsize>,
    closed: Arc<AtomicBool>,
    aborted: Arc<AtomicBool>,
}

#[derive(Debug, Clone)]
enum FlowSlot {
    Opening,
    Open(TargetFlow),
}

#[derive(Debug, Clone)]
struct TargetFlow {
    commands: Option<mpsc::Sender<TargetCommand>>,
    control: TargetFlowControl,
    target_to_client_open: bool,
    client_to_target_open: bool,
}

#[derive(Debug, Clone)]
struct SessionShutdown {
    closed: Arc<AtomicBool>,
}

struct RelaySessionContext<'a> {
    credential: Credential,
    policy_set: Arc<PolicySet>,
    carrier_writer: &'a CarrierWriter,
    event_tx: &'a mpsc::UnboundedSender<FlowEvent>,
    limits: RelayLimits,
    shutdown: SessionShutdown,
}

pub(crate) async fn relay_session(
    carrier: TlsStream<TcpStream>,
    credential: Credential,
    policy_set: Arc<PolicySet>,
    limits: RelayLimits,
    idle_timeout: Option<Duration>,
) -> Result<(), AnyError> {
    let mut state = ServerSessionState::Authenticated;
    transition(&mut state, ServerSessionState::Relaying);

    let (mut carrier_reader, carrier_writer) = tokio::io::split(carrier);
    let carrier_writer = Arc::new(Mutex::new(carrier_writer));
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let mut target_writers = FlowTable::new();
    let shutdown = SessionShutdown::default();
    let context = RelaySessionContext {
        credential,
        policy_set,
        carrier_writer: &carrier_writer,
        event_tx: &event_tx,
        limits,
        shutdown: shutdown.clone(),
    };

    let result = loop {
        let event = match next_session_event(
            &mut carrier_reader,
            &mut event_rx,
            limits.frame,
            idle_timeout,
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
            SessionEvent::IdleTimeout => {
                info!(event = "server.session.idle_timeout");
                break Ok(());
            }
            SessionEvent::PeerClosed => {
                info!(event = "server.session.peer_closed");
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
        Some(FlowEvent::ReadClosed(flow_id)) => {
            handle_target_read_closed(flow_id, context, target_writers);
        }
        Some(FlowEvent::ReadDrainExpired(flow_id)) => {
            handle_read_drain_expired(flow_id, context, target_writers).await?;
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
        target.mark_target_to_client_closed();
        info!(event = "tcp.target_read_closed", flow_id);
        if target.client_to_target_open {
            if let Some(timeout) = context.limits.tcp_half_close_timeout {
                spawn_half_close_timer(flow_id, timeout, context.event_tx.clone());
            }
        }
        if target.is_fully_closed() {
            target_writers.remove(&flow_id);
            info!(event = "tcp.closed", flow_id);
        }
    }
}

async fn handle_read_drain_expired(
    flow_id: u64,
    context: &RelaySessionContext<'_>,
    target_writers: &mut FlowTable,
) -> Result<(), AnyError> {
    let (should_remove, should_close_peer) =
        if let Some(target) = open_target_flow_mut(target_writers, flow_id) {
            let should_close_peer = !target.target_to_client_open && target.client_to_target_open;
            if should_close_peer {
                target.close_client_to_target();
            }
            (target.is_fully_closed(), should_close_peer)
        } else {
            (false, false)
        };
    if should_close_peer {
        send_tcp_close(context.carrier_writer, flow_id, TCP_CLOSE_NORMAL).await?;
    }
    if should_remove {
        target_writers.remove(&flow_id);
        info!(event = "tcp.half_close_timeout", flow_id);
    }
    Ok(())
}

fn handle_target_write_closed(flow_id: u64, target_writers: &mut FlowTable) {
    if let Some(target) = open_target_flow_mut(target_writers, flow_id) {
        target.mark_client_to_target_closed();
        if target.is_fully_closed() {
            target_writers.remove(&flow_id);
            info!(event = "tcp.closed", flow_id);
        }
    }
}

async fn next_session_event(
    carrier_reader: &mut tokio::io::ReadHalf<TlsStream<TcpStream>>,
    event_rx: &mut mpsc::UnboundedReceiver<FlowEvent>,
    limits: FrameLimits,
    idle_timeout: Option<Duration>,
) -> Result<SessionEvent, AnyError> {
    if let Some(idle_timeout) = idle_timeout {
        tokio::select! {
            event = event_rx.recv() => Ok(SessionEvent::Flow(event)),
            frame = read_frame(carrier_reader, limits) => map_frame_event(frame),
            () = tokio::time::sleep(idle_timeout) => Ok(SessionEvent::IdleTimeout),
        }
    } else {
        tokio::select! {
            event = event_rx.recv() => Ok(SessionEvent::Flow(event)),
            frame = read_frame(carrier_reader, limits) => map_frame_event(frame),
        }
    }
}

fn map_frame_event(result: Result<Frame, FrameIoError>) -> Result<SessionEvent, AnyError> {
    match result {
        Ok(frame) => Ok(SessionEvent::Frame(frame)),
        Err(FrameIoError::Closed) => Ok(SessionEvent::PeerClosed),
        Err(err) => Err(err.into()),
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
        TcpDataDisposition::UnknownFlow => {
            send_error(context.carrier_writer, flow_id, ErrorCode::Protocol).await?;
        }
        TcpDataDisposition::OpeningFlow => {
            send_error(context.carrier_writer, flow_id, ErrorCode::Protocol).await?;
            send_tcp_close(context.carrier_writer, flow_id, TCP_CLOSE_ERROR).await?;
            target_writers.remove(&flow_id);
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
    match target.enqueue_data(payload, context.limits.max_buffered_bytes_per_flow) {
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
        target_writers.remove(&flow_id);
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
    let should_remove = match target_writers.get_mut(&flow_id) {
        Some(FlowSlot::Opening) => true,
        Some(FlowSlot::Open(target)) => {
            if close.close_code == TCP_CLOSE_NORMAL {
                target.close_client_to_target();
            } else {
                target.abort();
            }
            target.is_fully_closed()
        }
        None => false,
    };
    if should_remove {
        target_writers.remove(&flow_id);
    }
    Ok(())
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

fn check_tcp_open_slot(
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
        Some(FlowSlot::Opening) => TcpDataDisposition::OpeningFlow,
        Some(FlowSlot::Open(_)) if payload.is_empty() => TcpDataDisposition::EmptyPayload,
        Some(FlowSlot::Open(_)) => TcpDataDisposition::ForwardPayload,
    }
}

async fn handle_tcp_open_frame(
    context: &RelaySessionContext<'_>,
    frame: Frame,
    target_writers: &mut FlowTable,
) -> Result<(), AnyError> {
    match check_tcp_open_slot(frame.header.id, target_writers, context.limits.max_streams) {
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
        target_writers.insert(flow_id, FlowSlot::Opening);
        spawn_target_open(
            flow_id,
            target,
            context.credential.clone(),
            Arc::clone(&context.policy_set),
            context.limits.target_connect_timeout,
            context.event_tx.clone(),
            context.shutdown.clone(),
        );
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

fn spawn_target_open(
    flow_id: u64,
    target: Target,
    credential: Credential,
    policy_set: Arc<PolicySet>,
    target_connect_timeout: Option<Duration>,
    event_tx: mpsc::UnboundedSender<FlowEvent>,
    shutdown: SessionShutdown,
) {
    tokio::spawn(async move {
        let result =
            connect_allowed_target(&target, &credential, &policy_set, target_connect_timeout).await;
        if !shutdown.is_closed() {
            let _ = event_tx.send(FlowEvent::OpenCompleted {
                flow_id,
                target,
                result,
            });
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
    if !matches!(target_writers.get(&flow_id), Some(FlowSlot::Opening)) {
        return Ok(());
    }

    match result {
        Ok(target_stream) => {
            let target_flow = accept_open_target(flow_id, target, target_stream, context).await?;
            target_writers.insert(flow_id, FlowSlot::Open(target_flow));
        }
        Err(err) => {
            reject_open_failure(flow_id, &target, err, context).await?;
            target_writers.remove(&flow_id);
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
    let flow_control = TargetFlowControl::default();
    let target_flow = TargetFlow::new(target_writer_tx, flow_control.clone());
    send_tcp_data(context.carrier_writer, flow_id, Bytes::new()).await?;
    spawn_target_reader(
        flow_id,
        target_reader,
        flow_control.clone(),
        Arc::clone(context.carrier_writer),
        context.event_tx.clone(),
        context.shutdown.clone(),
        context.limits.data_frame_size,
    );
    spawn_target_writer(
        flow_id,
        target_writer,
        target_writer_rx,
        flow_control,
        Arc::clone(context.carrier_writer),
        context.event_tx.clone(),
        context.shutdown.clone(),
    );
    info!(event = "tcp.open", flow_id, target = ?target);
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
    timeout: Duration,
    event_tx: mpsc::UnboundedSender<FlowEvent>,
) {
    tokio::spawn(async move {
        tokio::time::sleep(timeout).await;
        let _ = event_tx.send(FlowEvent::ReadDrainExpired(flow_id));
    });
}

async fn relay_client_to_target(
    mut target_writer: OwnedWriteHalf,
    mut commands: mpsc::Receiver<TargetCommand>,
    flow_control: TargetFlowControl,
    event_tx: &mpsc::UnboundedSender<FlowEvent>,
    shutdown: &SessionShutdown,
) -> Result<(), AnyError> {
    while let Some(command) = commands.recv().await {
        match command {
            TargetCommand::Data(payload) => {
                let payload_len = payload.len();
                if flow_control.is_aborted() || shutdown.is_closed() {
                    flow_control.release_bytes(payload_len);
                    return Ok(());
                }

                let write_result = target_writer.write_all(&payload).await;
                flow_control.release_bytes(payload_len);
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
        max_buffered_bytes_per_flow: usize,
        target_connect_timeout: Option<Duration>,
        tcp_half_close_timeout: Option<Duration>,
    ) -> Self {
        Self {
            frame,
            max_streams,
            data_frame_size: tcp_data_frame_size(frame),
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
        }
    }
}

impl SessionShutdown {
    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
}

impl Default for TargetFlowControl {
    fn default() -> Self {
        Self {
            buffered_bytes: Arc::new(AtomicUsize::new(0)),
            closed: Arc::new(AtomicBool::new(false)),
            aborted: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl TargetFlowControl {
    fn reserve_bytes(&self, amount: usize, limit: usize) -> bool {
        let mut current = self.buffered_bytes.load(Ordering::SeqCst);
        loop {
            let Some(next) = current.checked_add(amount) else {
                return false;
            };
            if next > limit {
                return false;
            }
            match self.buffered_bytes.compare_exchange(
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

    fn release_bytes(&self, amount: usize) {
        let mut current = self.buffered_bytes.load(Ordering::SeqCst);
        loop {
            let next = current.saturating_sub(amount);
            match self.buffered_bytes.compare_exchange(
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
        self.aborted.store(true, Ordering::SeqCst);
        self.close();
    }

    fn is_aborted(&self) -> bool {
        self.aborted.load(Ordering::SeqCst)
    }
}

impl TargetFlow {
    fn new(commands: mpsc::Sender<TargetCommand>, control: TargetFlowControl) -> Self {
        Self {
            commands: Some(commands),
            control,
            target_to_client_open: true,
            client_to_target_open: true,
        }
    }

    fn enqueue_data(&mut self, payload: Bytes, byte_limit: usize) -> Result<(), EnqueueError> {
        if self.control.is_closed() {
            return Err(EnqueueError::Closed);
        }

        let payload_len = payload.len();
        if !self.control.reserve_bytes(payload_len, byte_limit) {
            self.close_client_to_target_queue();
            return Err(EnqueueError::ResourceLimit);
        }

        let Some(commands) = &self.commands else {
            self.control.release_bytes(payload_len);
            return Err(EnqueueError::Closed);
        };

        match commands.try_send(TargetCommand::Data(payload)) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.control.release_bytes(payload_len);
                Err(EnqueueError::Closed)
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.control.release_bytes(payload_len);
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

fn open_target_flow_mut(target_writers: &mut FlowTable, flow_id: u64) -> Option<&mut TargetFlow> {
    match target_writers.get_mut(&flow_id) {
        Some(FlowSlot::Open(target)) => Some(target),
        Some(FlowSlot::Opening) | None => None,
    }
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
        let read = target_reader.read(target_buf.as_mut()).await?;
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

fn close_target_flows(target_writers: &mut FlowTable) {
    for slot in target_writers.drain().map(|(_, target)| target) {
        if let FlowSlot::Open(mut target) = slot {
            target.close_client_to_target();
        }
    }
}

async fn shutdown_carrier_writer(carrier_writer: &CarrierWriter) {
    let mut writer = carrier_writer.lock().await;
    if let Err(err) = writer.shutdown().await {
        debug!(event = "server.session.shutdown.error", error = %err);
    }
}

async fn connect_allowed_target(
    target: &Target,
    credential: &Credential,
    policy_set: &PolicySet,
    target_connect_timeout: Option<Duration>,
) -> Result<TcpStream, OpenFailure> {
    with_optional_timeout(
        target_connect_timeout,
        connect_allowed_target_inner(target, credential, policy_set),
    )
    .await
}

async fn connect_allowed_target_inner(
    target: &Target,
    credential: &Credential,
    policy_set: &PolicySet,
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
    connect_socket_addrs(&addrs).await
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

async fn connect_socket_addrs(addrs: &[SocketAddr]) -> Result<TcpStream, OpenFailure> {
    let mut last_error = None;
    for addr in addrs {
        match TcpStream::connect(*addr).await {
            Ok(stream) => {
                stream
                    .set_nodelay(true)
                    .map_err(OpenFailure::TargetUnavailable)?;
                return Ok(stream);
            }
            Err(err) => last_error = Some(err),
        }
    }

    Err(OpenFailure::TargetUnavailable(last_error.unwrap_or_else(
        || io::Error::new(io::ErrorKind::NotFound, "target has no socket addresses"),
    )))
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
    let mut writer = writer.lock().await;
    write_frame(&mut *writer, frame).await?;
    Ok(())
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

    fn test_target_flow() -> TargetFlow {
        let (commands, _commands_rx) = mpsc::channel(1);
        TargetFlow::new(commands, TargetFlowControl::default())
    }

    fn test_open_flow_slot() -> FlowSlot {
        FlowSlot::Open(test_target_flow())
    }

    fn control_frame(frame_type: FrameType, flow_id: u64) -> Frame {
        Frame::new(frame_type, 0, flow_id, Bytes::new()).unwrap()
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
    fn target_flow_control_tracks_buffered_bytes() {
        let control = TargetFlowControl::default();

        assert!(control.reserve_bytes(8, 10));
        assert_eq!(control.buffered_bytes(), 8);
        assert!(!control.reserve_bytes(3, 10));
        assert_eq!(control.buffered_bytes(), 8);

        control.release_bytes(4);
        assert_eq!(control.buffered_bytes(), 4);
        assert!(control.reserve_bytes(6, 10));
        assert_eq!(control.buffered_bytes(), 10);
    }

    #[test]
    fn target_flow_control_release_saturates_at_zero() {
        let control = TargetFlowControl::default();

        control.release_bytes(1);
        assert_eq!(control.buffered_bytes(), 0);

        assert!(control.reserve_bytes(5, 10));
        control.release_bytes(8);
        assert_eq!(control.buffered_bytes(), 0);
    }

    #[tokio::test]
    async fn half_close_drops_full_target_queue_sender() {
        let (commands, mut commands_rx) = mpsc::channel(1);
        let mut flow = TargetFlow::new(commands, TargetFlowControl::default());

        flow.enqueue_data(Bytes::from_static(b"queued"), 1024)
            .unwrap();
        flow.close_client_to_target();

        assert!(flow.commands.is_none());
        assert!(flow.control.is_closed());
        match commands_rx.recv().await {
            Some(TargetCommand::Data(payload)) => {
                assert_eq!(payload, Bytes::from_static(b"queued"));
            }
            other => panic!("unexpected target command: {other:?}"),
        }
        assert!(commands_rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn half_close_enqueues_close_when_target_queue_has_capacity() {
        let (commands, mut commands_rx) = mpsc::channel(1);
        let mut flow = TargetFlow::new(commands, TargetFlowControl::default());

        flow.close_client_to_target();

        assert!(flow.commands.is_some());
        assert!(flow.control.is_closed());
        assert!(matches!(
            commands_rx.recv().await,
            Some(TargetCommand::Close)
        ));
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

        commands_tx
            .send(TargetCommand::Data(payload.clone()))
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
            check_tcp_open_slot(1, &target_writers, 1),
            Err(OpenSlotRejection::DuplicateFlowId)
        );
    }

    #[test]
    fn new_open_slot_rejects_resource_limit() {
        let mut target_writers = FlowTable::new();
        target_writers.insert(1, test_open_flow_slot());

        assert_eq!(
            check_tcp_open_slot(3, &target_writers, 1),
            Err(OpenSlotRejection::ResourceLimit)
        );
    }

    #[test]
    fn reserved_open_slot_is_left_for_protocol_validation() {
        let mut target_writers = FlowTable::new();
        target_writers.insert(1, test_open_flow_slot());

        assert_eq!(check_tcp_open_slot(2, &target_writers, 1), Ok(()));
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
    fn maps_clean_carrier_eof_to_peer_closed() {
        assert!(matches!(
            map_frame_event(Err(FrameIoError::Closed)).unwrap(),
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

    #[test]
    fn pending_open_slot_counts_against_stream_limit() {
        let mut target_writers = FlowTable::new();
        target_writers.insert(1, FlowSlot::Opening);

        assert_eq!(
            check_tcp_open_slot(3, &target_writers, 1),
            Err(OpenSlotRejection::ResourceLimit)
        );
    }

    #[test]
    fn classifies_tcp_data_for_pending_open_flow() {
        let mut target_writers = FlowTable::new();
        target_writers.insert(1, FlowSlot::Opening);

        assert_eq!(
            tcp_data_disposition(1, &Bytes::from_static(b"early"), &target_writers),
            TcpDataDisposition::OpeningFlow
        );
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
