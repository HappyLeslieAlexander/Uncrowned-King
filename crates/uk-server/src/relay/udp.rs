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
use super::tcp::*;

use crate::observability::{
    ActiveFlowGuard, FlowOpenFailure, RelayDirection, RelayProtocol, ServerMetrics,
};
use crate::security::SecurityState;
pub(crate) fn handle_udp_read_closed(
    flow_id: u64,
    token: FlowToken,
    target_writers: &mut FlowTable,
) {
    if matches!(
        target_writers.get(&flow_id),
        Some(FlowSlot::Udp(target)) if target.token == token
    ) {
        remove_flow_slot(target_writers, flow_id);
        info!(event = "udp.closed", flow_id);
    }
}

/// Whether a `TCP_CLOSE(NORMAL)` should start a half-close drain timer.
///
/// Only the close that actually half-closes the flow qualifies. Testing the
/// target read side alone would arm a fresh timer for every duplicate
/// `TCP_CLOSE`, since a repeat leaves the slot in place with that side open.
pub(crate) async fn handle_udp_open_frame(
    context: &RelaySessionContext<'_>,
    frame: Frame,
    target_writers: &mut FlowTable,
    session_tasks: &mut SessionTasks,
) -> Result<(), AnyError> {
    context.metrics.record_flow_open_request(RelayProtocol::Udp);
    match check_udp_open_slot(
        frame.header.id,
        target_writers,
        context.limits.max_streams,
        context.limits.max_udp_flows,
    ) {
        Ok(()) => {}
        Err(UdpOpenSlotRejection::DuplicateFlowId) => {
            context
                .metrics
                .record_flow_open_failure(RelayProtocol::Udp, FlowOpenFailure::Protocol);
            send_error(context.carrier_writer, frame.header.id, ErrorCode::Protocol).await?;
            send_udp_close(context.carrier_writer, frame.header.id, UDP_CLOSE_ERROR).await?;
            remove_flow_slot(target_writers, frame.header.id);
            return Ok(());
        }
        Err(UdpOpenSlotRejection::ResourceLimit | UdpOpenSlotRejection::UdpFlowLimit) => {
            context
                .metrics
                .record_flow_open_failure(RelayProtocol::Udp, FlowOpenFailure::ResourceLimit);
            send_resource_limit(context.carrier_writer, frame.header.id).await?;
            send_udp_close(context.carrier_writer, frame.header.id, UDP_CLOSE_ERROR).await?;
            return Ok(());
        }
    }

    if let Some((flow_id, target)) = validate_udp_open_request(context, frame).await? {
        let Some(policy) = context
            .security
            .policy_snapshot(&context.identity, unix_now())
        else {
            reject_udp_open_failure(flow_id, &target, OpenFailure::PolicyDenied, context).await?;
            return Ok(());
        };
        debug!(
            event = "udp.open.policy_snapshot",
            flow_id,
            security_generation = policy.generation
        );
        let cancel = OpenFlowCancel::new(context.flow_tokens.next());
        target_writers.insert(flow_id, FlowSlot::OpeningUdp(cancel.clone()));
        spawn_udp_open(
            session_tasks,
            UdpOpenTask {
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

pub(crate) async fn validate_udp_open_request(
    context: &RelaySessionContext<'_>,
    frame: Frame,
) -> Result<Option<(u64, Target)>, AnyError> {
    let flow_id = frame.header.id;
    if flow_id == 0 {
        context
            .metrics
            .record_flow_open_failure(RelayProtocol::Udp, FlowOpenFailure::Protocol);
        send_error(context.carrier_writer, flow_id, ErrorCode::Protocol).await?;
        return Err("udp flow id must be non-zero".into());
    }
    if !is_client_initiated_flow_id(flow_id) {
        context
            .metrics
            .record_flow_open_failure(RelayProtocol::Udp, FlowOpenFailure::Protocol);
        send_error(context.carrier_writer, flow_id, ErrorCode::Protocol).await?;
        send_udp_close(context.carrier_writer, flow_id, UDP_CLOSE_ERROR).await?;
        warn!(event = "udp.open.reserved_flow_id", flow_id);
        return Ok(None);
    }

    let mut payload = frame.payload;
    let open = match UdpOpen::decode(&mut payload) {
        Ok(open) => open,
        Err(err) => {
            context
                .metrics
                .record_flow_open_failure(RelayProtocol::Udp, FlowOpenFailure::Protocol);
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

pub(crate) async fn handle_udp_data_frame(
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
        UdpDataDisposition::UnknownFlow => {
            send_error(context.carrier_writer, flow_id, ErrorCode::Protocol).await?;
        }
        UdpDataDisposition::TcpFlow => {
            send_error(context.carrier_writer, flow_id, ErrorCode::Protocol).await?;
            send_tcp_close(context.carrier_writer, flow_id, TCP_CLOSE_ERROR).await?;
            remove_flow_slot(target_writers, flow_id);
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

pub(crate) async fn forward_udp_data_frame(
    flow_id: u64,
    payload: Bytes,
    context: &RelaySessionContext<'_>,
    target_writers: &mut FlowTable,
) -> Result<(), AnyError> {
    let Some(target) = udp_target_flow_mut(target_writers, flow_id) else {
        send_error(context.carrier_writer, flow_id, ErrorCode::Protocol).await?;
        return Ok(());
    };
    target.record_activity();
    match target.socket.try_send(&payload) {
        Ok(written) => context.metrics.record_relay_bytes(
            RelayProtocol::Udp,
            RelayDirection::ClientToTarget,
            written,
        ),
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
            debug!(event = "udp.target.send_buffer_full", flow_id);
        }
        Err(err) => {
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
    }
    Ok(())
}

/// Forwards an inbound QUIC datagram payload to the target socket.
///
/// Unlike the reliable `UDP_DATA` frame path, datagrams are unreliable and
/// unordered: a datagram for an unknown/closed flow or a failed target send is
/// dropped silently rather than erroring the session.
pub(crate) fn forward_udp_datagram(
    flow_id: u64,
    payload: &Bytes,
    context: &RelaySessionContext<'_>,
    target_writers: &mut FlowTable,
) {
    let Some(target) = udp_target_flow_mut(target_writers, flow_id) else {
        debug!(event = "udp.datagram.unknown_flow", flow_id);
        return;
    };
    target.record_activity();
    match target.socket.try_send(payload) {
        Ok(written) => context.metrics.record_relay_bytes(
            RelayProtocol::Udp,
            RelayDirection::ClientToTarget,
            written,
        ),
        Err(err) => {
            debug!(event = "udp.datagram.target_write_error", flow_id, error = %err);
        }
    }
}

pub(crate) async fn handle_udp_close_frame(
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
    let mut should_send_tcp_close = false;
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
            should_send_tcp_close = true;
            true
        }
        None => false,
    };
    if should_send_tcp_close {
        send_tcp_close(context.carrier_writer, flow_id, TCP_CLOSE_ERROR).await?;
    }
    if should_remove {
        remove_flow_slot(target_writers, flow_id);
    }
    Ok(())
}

pub(crate) async fn close_idle_udp_flows(
    context: &RelaySessionContext<'_>,
    target_writers: &mut FlowTable,
) -> Result<(), AnyError> {
    let Some(idle_timeout) = context.limits.udp_flow_idle_timeout else {
        return Ok(());
    };
    let now = time::Instant::now();
    let expired = target_writers
        .iter()
        .filter_map(|(flow_id, slot)| match slot {
            FlowSlot::Udp(target) if now.duration_since(target.last_activity) >= idle_timeout => {
                Some(*flow_id)
            }
            _ => None,
        })
        .collect::<Vec<_>>();

    for flow_id in expired {
        send_udp_close(context.carrier_writer, flow_id, UDP_CLOSE_NORMAL).await?;
        remove_flow_slot(target_writers, flow_id);
        info!(event = "udp.idle_timeout", flow_id);
    }
    Ok(())
}

pub(crate) fn udp_data_disposition(flow_id: u64, target_writers: &FlowTable) -> UdpDataDisposition {
    match target_writers.get(&flow_id) {
        None => UdpDataDisposition::UnknownFlow,
        Some(FlowSlot::OpeningUdp(_)) => UdpDataDisposition::OpeningFlow,
        Some(FlowSlot::OpeningTcp(_) | FlowSlot::Tcp(_)) => UdpDataDisposition::TcpFlow,
        Some(FlowSlot::Udp(_)) => UdpDataDisposition::ForwardPayload,
    }
}

pub(crate) fn check_udp_open_slot(
    flow_id: u64,
    target_writers: &FlowTable,
    max_streams: u64,
    max_udp_flows: u64,
) -> Result<(), UdpOpenSlotRejection> {
    check_open_slot(flow_id, target_writers, max_streams).map_err(|err| match err {
        OpenSlotRejection::DuplicateFlowId => UdpOpenSlotRejection::DuplicateFlowId,
        OpenSlotRejection::ResourceLimit => UdpOpenSlotRejection::ResourceLimit,
    })?;
    let max_udp_flows = usize::try_from(max_udp_flows).unwrap_or(usize::MAX);
    if is_client_initiated_flow_id(flow_id) && udp_flow_count(target_writers) >= max_udp_flows {
        return Err(UdpOpenSlotRejection::UdpFlowLimit);
    }
    Ok(())
}

pub(crate) fn udp_flow_count(target_writers: &FlowTable) -> usize {
    target_writers
        .values()
        .filter(|slot| matches!(slot, FlowSlot::OpeningUdp(_) | FlowSlot::Udp(_)))
        .count()
}

pub(crate) async fn handle_udp_open_completed(
    flow_id: u64,
    token: FlowToken,
    target: Target,
    result: Result<UdpSocket, OpenFailure>,
    context: &RelaySessionContext<'_>,
    target_writers: &mut FlowTable,
    session_tasks: &mut SessionTasks,
) -> Result<(), AnyError> {
    if !matches!(
        target_writers.get(&flow_id),
        Some(FlowSlot::OpeningUdp(cancel)) if cancel.token == token
    ) {
        return Ok(());
    }

    match result {
        Ok(target_socket) => {
            let target_flow =
                accept_open_udp_target(flow_id, target, target_socket, context, session_tasks)
                    .await?;
            target_writers.insert(flow_id, FlowSlot::Udp(target_flow));
        }
        Err(err) => {
            reject_udp_open_failure(flow_id, &target, err, context).await?;
            remove_flow_slot(target_writers, flow_id);
        }
    }
    Ok(())
}

/// Depth of the client-to-target write queue, derived from a flow's per-flow
/// byte limit so the configured byte budget — not a small fixed frame count —
/// governs when an overwhelmed upload is shed. Memory stays bounded by the byte
/// accounting, so a deeper queue only raises the shed threshold for a
/// momentarily-slow target.
pub(crate) async fn accept_open_udp_target(
    flow_id: u64,
    target: Target,
    target_socket: UdpSocket,
    context: &RelaySessionContext<'_>,
    session_tasks: &mut SessionTasks,
) -> Result<UdpTargetFlow, AnyError> {
    let target_socket = Arc::new(target_socket);
    let flow_control = TargetFlowControl::new(context.session_buffer.clone());
    let token = context.flow_tokens.next();
    send_udp_data(context.carrier_writer, flow_id, Bytes::new()).await?;
    let target_flow = UdpTargetFlow::new(token, Arc::clone(&target_socket), flow_control.clone())
        .track_metrics(context.metrics.begin_flow(RelayProtocol::Udp));
    spawn_udp_reader(
        session_tasks,
        UdpReaderTask {
            flow_id,
            token,
            target_socket,
            flow_control,
            carrier_writer: context.carrier_writer.clone(),
            datagrams: context.datagrams.clone(),
            event_tx: context.event_tx.clone(),
            shutdown: context.shutdown.clone(),
            data_frame_size: context.limits.data_frame_size,
        },
    );
    info!(event = "udp.open", flow_id, target = %target.log_safe());
    Ok(target_flow)
}

pub(crate) async fn reject_udp_open_failure(
    flow_id: u64,
    target: &Target,
    failure: OpenFailure,
    context: &RelaySessionContext<'_>,
) -> Result<(), AnyError> {
    match failure {
        OpenFailure::PolicyDenied => {
            context
                .metrics
                .record_flow_open_failure(RelayProtocol::Udp, FlowOpenFailure::PolicyDenied);
            warn!(event = "udp.policy.denied", flow_id, target = %target.log_safe());
            send_policy_denied(context.carrier_writer, flow_id).await?;
            send_udp_close(context.carrier_writer, flow_id, UDP_CLOSE_NORMAL).await?;
        }
        OpenFailure::ResourceLimit => {
            context
                .metrics
                .record_flow_open_failure(RelayProtocol::Udp, FlowOpenFailure::ResourceLimit);
            warn!(event = "udp.open.dial_limit", flow_id, target = %target.log_safe());
            send_resource_limit(context.carrier_writer, flow_id).await?;
            send_udp_close(context.carrier_writer, flow_id, UDP_CLOSE_ERROR).await?;
        }
        OpenFailure::TargetUnavailable(err) => {
            context
                .metrics
                .record_flow_open_failure(RelayProtocol::Udp, FlowOpenFailure::TargetUnavailable);
            warn!(
                event = "udp.target.unavailable",
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
            send_udp_close(context.carrier_writer, flow_id, UDP_CLOSE_ERROR).await?;
        }
        OpenFailure::TargetTimeout => {
            context
                .metrics
                .record_flow_open_failure(RelayProtocol::Udp, FlowOpenFailure::TargetTimeout);
            warn!(event = "udp.target.timeout", flow_id, target = %target.log_safe());
            send_error(context.carrier_writer, flow_id, ErrorCode::TargetTimeout).await?;
            send_udp_close(context.carrier_writer, flow_id, UDP_CLOSE_ERROR).await?;
        }
    }
    Ok(())
}

/// Outcome of relaying one target-to-client UDP payload.
pub(crate) enum UdpEmit {
    /// The payload was sent (via QUIC DATAGRAM or a `UDP_DATA` frame).
    Sent,
    /// The payload exceeded both the datagram size and the frame limit and was
    /// dropped, as UDP permits.
    DroppedTooLarge,
}

/// Sends one target-to-client UDP payload, preferring the QUIC DATAGRAM path
/// and falling back to a reliable `UDP_DATA` frame when datagrams are
/// unavailable or the payload is too large for the current datagram size.
pub(crate) async fn emit_udp_to_client(
    carrier_writer: &CarrierWriter,
    datagrams: Option<&BoxedDatagramChannel>,
    flow_id: u64,
    payload: &[u8],
    data_frame_size: usize,
) -> Result<UdpEmit, AnyError> {
    if let Some(channel) = datagrams {
        match try_send_udp_datagram(channel, flow_id, payload) {
            DatagramAttempt::Sent => return Ok(UdpEmit::Sent),
            DatagramAttempt::FallBack => {}
        }
    }
    if udp_payload_exceeds_frame_limit(payload.len(), data_frame_size) {
        return Ok(UdpEmit::DroppedTooLarge);
    }
    send_udp_data(carrier_writer, flow_id, Bytes::copy_from_slice(payload)).await?;
    Ok(UdpEmit::Sent)
}

pub(crate) enum DatagramAttempt {
    Sent,
    FallBack,
}

/// Attempts to send one UDP payload over the datagram channel. Returns
/// `FallBack` when the datagram is too large for the current size or datagrams
/// are unavailable, so the caller can use the reliable frame path.
pub(crate) fn try_send_udp_datagram(
    channel: &BoxedDatagramChannel,
    flow_id: u64,
    payload: &[u8],
) -> DatagramAttempt {
    let Some(max_datagram_size) = channel.max_datagram_size() else {
        return DatagramAttempt::FallBack;
    };
    let Ok(overhead) = datagram::overhead(flow_id) else {
        return DatagramAttempt::FallBack;
    };
    if overhead.saturating_add(payload.len()) > max_datagram_size {
        return DatagramAttempt::FallBack;
    }
    let mut encoded = BytesMut::with_capacity(overhead + payload.len());
    if datagram::encode(flow_id, payload, &mut encoded).is_err() {
        return DatagramAttempt::FallBack;
    }
    match channel.send(encoded.freeze()) {
        DatagramSendOutcome::Sent => DatagramAttempt::Sent,
        DatagramSendOutcome::TooLarge | DatagramSendOutcome::Unavailable => {
            DatagramAttempt::FallBack
        }
    }
}

pub(crate) fn udp_payload_exceeds_frame_limit(payload_len: usize, max_payload_len: usize) -> bool {
    payload_len > max_payload_len
}

pub(crate) async fn send_udp_data(
    writer: &CarrierWriter,
    flow_id: u64,
    payload: Bytes,
) -> Result<(), AnyError> {
    let frame = Frame::new(FrameType::UdpData, 0, flow_id, payload)?;
    write_frame_locked(writer, &frame).await
}

pub(crate) async fn send_udp_close(
    writer: &CarrierWriter,
    flow_id: u64,
    close_code: u16,
) -> Result<(), AnyError> {
    let mut payload = BytesMut::new();
    UdpClose::new(close_code).encode(&mut payload)?;
    let frame = Frame::new(FrameType::UdpClose, 0, flow_id, payload.freeze())?;
    write_frame_locked(writer, &frame).await
}
