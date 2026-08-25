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
    task::{Id, JoinError, JoinSet},
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

use super::context::*;
use super::dialer::*;
use super::session::*;
use super::tasks::*;
use super::udp::*;

use crate::observability::{
    ActiveFlowGuard, FlowOpenFailure, RelayDirection, RelayProtocol, ServerMetrics,
};
use crate::security::SecurityState;
pub(crate) const fn should_start_half_close_drain(target: &TargetFlow) -> bool {
    target.client_to_target_open && target.target_to_client_open
}

pub(crate) fn handle_target_read_closed(
    flow_id: u64,
    token: FlowToken,
    tcp_half_close_timeout: Option<Duration>,
    event_tx: &FlowEventSender,
    shutdown: &SessionShutdown,
    target_writers: &mut FlowTable,
    session_tasks: &mut SessionTasks,
) {
    if let Some(target) = open_target_flow_mut(target_writers, flow_id) {
        if target.token != token {
            return;
        }
        target.mark_target_to_client_closed();
        info!(event = "tcp.target_read_closed", flow_id);
        if target.client_to_target_open {
            if let Some(timeout) = tcp_half_close_timeout {
                spawn_half_close_timer(
                    session_tasks,
                    flow_id,
                    token,
                    HalfCloseSide::TargetToClient,
                    timeout,
                    event_tx.clone(),
                    shutdown.clone(),
                );
            }
        }
        if target.is_fully_closed() {
            remove_flow_slot(target_writers, flow_id);
            info!(event = "tcp.closed", flow_id);
        }
    }
}

pub(crate) async fn handle_half_close_drain_expired(
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

pub(crate) fn expire_half_close_drain(
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
pub(crate) enum HalfCloseDrainDecision {
    Ignored,
    ClosePeer { remove: bool },
}

pub(crate) fn handle_target_write_closed(
    flow_id: u64,
    token: FlowToken,
    target_writers: &mut FlowTable,
) {
    if let Some(target) = open_target_flow_mut(target_writers, flow_id) {
        if target.token != token {
            return;
        }
        target.mark_client_to_target_closed();
        if target.is_fully_closed() {
            remove_flow_slot(target_writers, flow_id);
            info!(event = "tcp.closed", flow_id);
        }
    }
}

/// Waits for the next thing the session loop has to act on.
///
/// Every future used as a branch here must be cancellation safe, because
/// `select!` drops the losers. `FrameReader::read_frame` buffers inside the
/// reader rather than inside the future, so a frame that is still arriving when
/// another branch fires is resumed intact on the next call; using the free
/// `read_frame` function here would discard the bytes already taken from the
/// carrier and resynchronise part-way through a frame.
pub(crate) async fn handle_tcp_data_frame(
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
        TcpDataDisposition::OtherProtocolFlow => {
            send_error(context.carrier_writer, flow_id, ErrorCode::Protocol).await?;
            send_udp_close(context.carrier_writer, flow_id, UDP_CLOSE_ERROR).await?;
            remove_flow_slot(target_writers, flow_id);
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

pub(crate) async fn forward_tcp_data_frame(
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

pub(crate) async fn handle_tcp_close_frame(
    frame: Frame,
    context: &RelaySessionContext<'_>,
    target_writers: &mut FlowTable,
    session_tasks: &mut SessionTasks,
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
    let mut should_send_udp_close = false;
    let should_remove = match target_writers.get_mut(&flow_id) {
        Some(FlowSlot::OpeningTcp(_)) => true,
        Some(FlowSlot::Tcp(target)) => {
            if close.close_code == TCP_CLOSE_NORMAL {
                let should_start_drain_timer = should_start_half_close_drain(target);
                let token = target.token;
                target.close_client_to_target();
                if should_start_drain_timer {
                    if let Some(timeout) = context.limits.tcp_half_close_timeout {
                        spawn_half_close_timer(
                            session_tasks,
                            flow_id,
                            token,
                            HalfCloseSide::ClientToTarget,
                            timeout,
                            context.event_tx.clone(),
                            context.shutdown.clone(),
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
            should_send_udp_close = true;
            true
        }
        None => false,
    };
    if should_report_protocol_error {
        send_error(context.carrier_writer, flow_id, ErrorCode::Protocol).await?;
    }
    if should_send_udp_close {
        send_udp_close(context.carrier_writer, flow_id, UDP_CLOSE_ERROR).await?;
    }
    if should_remove {
        remove_flow_slot(target_writers, flow_id);
    }
    Ok(())
}

pub(crate) async fn handle_client_flow_status_frame(
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

pub(crate) fn abort_client_flow(flow_id: u64, target_writers: &mut FlowTable) {
    let protocol = match target_writers.get_mut(&flow_id) {
        Some(FlowSlot::OpeningTcp(_)) => Some("tcp"),
        Some(FlowSlot::OpeningUdp(_)) => Some("udp"),
        Some(FlowSlot::Tcp(target)) => {
            target.abort();
            Some("tcp")
        }
        Some(FlowSlot::Udp(target)) => {
            target.abort();
            Some("udp")
        }
        None => None,
    };
    if let Some(protocol) = protocol {
        remove_flow_slot(target_writers, flow_id);
        info!(event = "client_flow.aborted", flow_id, protocol);
    }
}

pub(crate) fn validate_client_flow_status_payload(
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

pub(crate) fn check_open_slot(
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

pub(crate) fn tcp_data_disposition(
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

pub(crate) async fn handle_tcp_open_frame(
    context: &RelaySessionContext<'_>,
    frame: Frame,
    target_writers: &mut FlowTable,
    session_tasks: &mut SessionTasks,
) -> Result<(), AnyError> {
    context.metrics.record_flow_open_request(RelayProtocol::Tcp);
    match check_open_slot(frame.header.id, target_writers, context.limits.max_streams) {
        Ok(()) => {}
        Err(OpenSlotRejection::DuplicateFlowId) => {
            context
                .metrics
                .record_flow_open_failure(RelayProtocol::Tcp, FlowOpenFailure::Protocol);
            send_error(context.carrier_writer, frame.header.id, ErrorCode::Protocol).await?;
            send_tcp_close(context.carrier_writer, frame.header.id, TCP_CLOSE_ERROR).await?;
            remove_flow_slot(target_writers, frame.header.id);
            return Ok(());
        }
        Err(OpenSlotRejection::ResourceLimit) => {
            context
                .metrics
                .record_flow_open_failure(RelayProtocol::Tcp, FlowOpenFailure::ResourceLimit);
            send_resource_limit(context.carrier_writer, frame.header.id).await?;
            send_tcp_close(context.carrier_writer, frame.header.id, TCP_CLOSE_ERROR).await?;
            return Ok(());
        }
    }

    if let Some((flow_id, target)) = validate_tcp_open_request(context, frame).await? {
        let Some(policy) = context
            .security
            .policy_snapshot(&context.identity, unix_now())
        else {
            reject_open_failure(flow_id, &target, OpenFailure::PolicyDenied, context).await?;
            return Ok(());
        };
        debug!(
            event = "tcp.open.policy_snapshot",
            flow_id,
            security_generation = policy.generation
        );
        let cancel = OpenFlowCancel::new(context.flow_tokens.next());
        target_writers.insert(flow_id, FlowSlot::OpeningTcp(cancel.clone()));
        spawn_target_open(
            session_tasks,
            TargetOpenTask {
                flow_id,
                target,
                identity: context.identity.clone(),
                policy_set: policy.policy_set,
                open_dial_limiter: context.open_dial_limiter.clone(),
                target_connect_timeout: context.limits.target_connect_timeout,
                event_tx: context.event_tx.clone(),
                shutdown: context.shutdown.clone(),
                cancel,
            },
        );
    }
    Ok(())
}

pub(crate) async fn validate_tcp_open_request(
    context: &RelaySessionContext<'_>,
    frame: Frame,
) -> Result<Option<(u64, Target)>, AnyError> {
    let flow_id = frame.header.id;
    if flow_id == 0 {
        context
            .metrics
            .record_flow_open_failure(RelayProtocol::Tcp, FlowOpenFailure::Protocol);
        send_error(context.carrier_writer, flow_id, ErrorCode::Protocol).await?;
        return Err("tcp flow id must be non-zero".into());
    }
    if !is_client_initiated_flow_id(flow_id) {
        context
            .metrics
            .record_flow_open_failure(RelayProtocol::Tcp, FlowOpenFailure::Protocol);
        send_error(context.carrier_writer, flow_id, ErrorCode::Protocol).await?;
        send_tcp_close(context.carrier_writer, flow_id, TCP_CLOSE_ERROR).await?;
        warn!(event = "tcp.open.reserved_flow_id", flow_id);
        return Ok(None);
    }

    let mut payload = frame.payload;
    let open = match TcpOpen::decode(&mut payload) {
        Ok(open) => open,
        Err(err) => {
            context
                .metrics
                .record_flow_open_failure(RelayProtocol::Tcp, FlowOpenFailure::Protocol);
            send_error(
                context.carrier_writer,
                flow_id,
                ErrorCode::from_protocol_error(&err),
            )
            .await?;
            send_tcp_close(context.carrier_writer, flow_id, TCP_CLOSE_ERROR).await?;
            warn!(event = "tcp.open.invalid", flow_id, error = %err);
            return Ok(None);
        }
    };
    if open.open_flags != TCP_OPEN_FLAGS_NONE {
        context
            .metrics
            .record_flow_open_failure(RelayProtocol::Tcp, FlowOpenFailure::Protocol);
        send_error(context.carrier_writer, flow_id, ErrorCode::Protocol).await?;
        send_tcp_close(context.carrier_writer, flow_id, TCP_CLOSE_ERROR).await?;
        return Ok(None);
    }

    Ok(Some((flow_id, open.target)))
}

pub(crate) async fn handle_tcp_open_completed(
    flow_id: u64,
    token: FlowToken,
    target: Target,
    result: Result<TcpStream, OpenFailure>,
    context: &RelaySessionContext<'_>,
    target_writers: &mut FlowTable,
    session_tasks: &mut SessionTasks,
) -> Result<(), AnyError> {
    // The token must match *this* open attempt, not merely "some open is
    // pending": the producer's cancellation check is not atomic with the send,
    // so a close plus re-open can slip in between and would otherwise get the
    // previous attempt's stream wired in, under a target the client never
    // requested for that flow.
    if !matches!(
        target_writers.get(&flow_id),
        Some(FlowSlot::OpeningTcp(cancel)) if cancel.token == token
    ) {
        return Ok(());
    }

    match result {
        Ok(target_stream) => {
            let target_flow =
                accept_open_target(flow_id, target, target_stream, context, session_tasks).await?;
            target_writers.insert(flow_id, FlowSlot::Tcp(target_flow));
        }
        Err(err) => {
            reject_open_failure(flow_id, &target, err, context).await?;
            remove_flow_slot(target_writers, flow_id);
        }
    }
    Ok(())
}

pub(crate) async fn accept_open_target(
    flow_id: u64,
    target: Target,
    target_stream: TcpStream,
    context: &RelaySessionContext<'_>,
    session_tasks: &mut SessionTasks,
) -> Result<TargetFlow, AnyError> {
    let (target_reader, target_writer) = target_stream.into_split();
    let (target_writer_tx, target_writer_rx) = mpsc::channel(target_write_queue_capacity(
        context.limits.max_buffered_bytes_per_flow,
    ));
    let flow_control = TargetFlowControl::new(context.session_buffer.clone());
    let token = context.flow_tokens.next();
    let identity = TargetFlowIdentity { flow_id, token };
    send_tcp_data(context.carrier_writer, flow_id, Bytes::new()).await?;
    let target_flow = TargetFlow::new(token, target_writer_tx, flow_control.clone())
        .track_metrics(context.metrics.begin_flow(RelayProtocol::Tcp));
    spawn_target_reader(
        session_tasks,
        TargetReaderTask {
            identity,
            target_reader,
            flow_control: flow_control.clone(),
            carrier_writer: context.carrier_writer.clone(),
            event_tx: context.event_tx.clone(),
            shutdown: context.shutdown.clone(),
            data_frame_size: context.limits.data_frame_size,
        },
    );
    spawn_target_writer(
        session_tasks,
        TargetWriterTask {
            identity,
            target_writer,
            commands: target_writer_rx,
            flow_control,
            carrier_writer: context.carrier_writer.clone(),
            event_tx: context.event_tx.clone(),
            shutdown: context.shutdown.clone(),
        },
    );
    info!(event = "tcp.open", flow_id, target = %target.log_safe());
    Ok(target_flow)
}

pub(crate) async fn reject_open_failure(
    flow_id: u64,
    target: &Target,
    failure: OpenFailure,
    context: &RelaySessionContext<'_>,
) -> Result<(), AnyError> {
    match failure {
        OpenFailure::PolicyDenied => {
            context
                .metrics
                .record_flow_open_failure(RelayProtocol::Tcp, FlowOpenFailure::PolicyDenied);
            warn!(event = "policy.denied", flow_id, target = %target.log_safe());
            send_policy_denied(context.carrier_writer, flow_id).await?;
            send_tcp_close(context.carrier_writer, flow_id, TCP_CLOSE_NORMAL).await?;
        }
        OpenFailure::ResourceLimit => {
            context
                .metrics
                .record_flow_open_failure(RelayProtocol::Tcp, FlowOpenFailure::ResourceLimit);
            warn!(event = "tcp.open.dial_limit", flow_id, target = %target.log_safe());
            send_resource_limit(context.carrier_writer, flow_id).await?;
            send_tcp_close(context.carrier_writer, flow_id, TCP_CLOSE_ERROR).await?;
        }
        OpenFailure::TargetUnavailable(err) => {
            context
                .metrics
                .record_flow_open_failure(RelayProtocol::Tcp, FlowOpenFailure::TargetUnavailable);
            warn!(
                event = "target.unavailable",
                flow_id,
                target = %target.log_safe(),
                error = %err
            );
            send_error(
                context.carrier_writer,
                flow_id,
                ErrorCode::TargetUnavailable,
            )
            .await?;
            send_tcp_close(context.carrier_writer, flow_id, TCP_CLOSE_ERROR).await?;
        }
        OpenFailure::TargetTimeout => {
            context
                .metrics
                .record_flow_open_failure(RelayProtocol::Tcp, FlowOpenFailure::TargetTimeout);
            warn!(event = "target.timeout", flow_id, target = %target.log_safe());
            send_error(context.carrier_writer, flow_id, ErrorCode::TargetTimeout).await?;
            send_tcp_close(context.carrier_writer, flow_id, TCP_CLOSE_ERROR).await?;
        }
    }
    Ok(())
}

pub(crate) async fn send_tcp_data(
    writer: &CarrierWriter,
    flow_id: u64,
    payload: Bytes,
) -> Result<(), AnyError> {
    let frame = Frame::new(FrameType::TcpData, 0, flow_id, payload)?;
    write_frame_locked(writer, &frame).await
}

pub(crate) async fn send_tcp_close(
    writer: &CarrierWriter,
    flow_id: u64,
    close_code: u16,
) -> Result<(), AnyError> {
    let mut payload = BytesMut::new();
    TcpClose::new(close_code).encode(&mut payload)?;
    let frame = Frame::new(FrameType::TcpClose, 0, flow_id, payload.freeze())?;
    write_frame_locked(writer, &frame).await
}
