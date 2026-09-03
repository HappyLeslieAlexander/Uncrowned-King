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
    ErrorPayload, FIRST_CLIENT_FLOW_ID, FLOW_ID_STEP, Frame, FrameIoError, FrameLimits,
    FrameReader, FrameType, NegotiatedSettings, TCP_CLOSE_ERROR, TCP_CLOSE_NORMAL,
    TCP_OPEN_FLAGS_NONE, Target, TcpClose, TcpOpen, UDP_CLOSE_ERROR, UDP_CLOSE_NORMAL, UdpClose,
    UdpOpen, datagram, is_client_initiated_flow_id, read_frame, validate_connection_frame,
    varint::MAX_VARINT, write_frame,
};

use super::context::*;
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
pub(crate) async fn peek_when_pending_buffer_full(local: &TcpStream) -> PendingOpenLocalRead {
    let mut byte = [0_u8; 1];
    match local.peek(&mut byte).await {
        Ok(0) | Err(_) => PendingOpenLocalRead::Closed,
        Ok(_) => PendingOpenLocalRead::ResourceLimit,
    }
}

pub(crate) fn allocate_client_flow_id(next_flow_id: &AtomicU64) -> Option<u64> {
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

pub(crate) fn next_keepalive_nonce(counter: &AtomicU64) -> Option<u64> {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let next = current.checked_add(1)?;
        match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return Some(next),
            Err(actual) => current = actual,
        }
    }
}

pub(crate) fn keepalive_nonce_payload(nonce: u64) -> Bytes {
    Bytes::copy_from_slice(&nonce.to_be_bytes())
}

pub(crate) fn decode_keepalive_nonce(payload: &Bytes) -> Option<u64> {
    let bytes: [u8; 8] = payload.as_ref().try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

pub(crate) fn record_matching_pong(
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

pub(crate) async fn spawn_carrier_reader(
    carrier_reader: BoxedCarrierReader,
    session: Arc<ClientSession>,
) {
    let correlation_id = session.correlation_id;
    let task_session = Arc::clone(&session);
    let mut frame_reader = FrameReader::new(carrier_reader, task_session.limits);
    let task = async move {
        loop {
            let frame = tokio::select! {
                frame = frame_reader.read_frame() => frame,
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
pub(crate) async fn spawn_datagram_reader(session: Arc<ClientSession>) {
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
pub(crate) async fn spawn_keepalive(session: Arc<ClientSession>, interval: Duration) {
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

pub(crate) async fn close_session(session: &ClientSession) {
    session.close().await;
}

pub(crate) async fn handle_carrier_frame(
    session: &ClientSession,
    frame: Frame,
) -> Result<(), AnyError> {
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

pub(crate) async fn send_flow_error_close(
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

pub(crate) async fn report_protocol_error(session: &ClientSession) {
    let _ = session.send_connection_error(ErrorCode::Protocol).await;
}

pub(crate) async fn report_frame_io_error(session: &ClientSession, error: &FrameIoError) {
    if let FrameIoError::Protocol(error) = error {
        let _ = session
            .send_connection_error(ErrorCode::from_protocol_error(error))
            .await;
    }
}

pub(crate) fn validate_session_control_frame(
    frame: &Frame,
    expected_type: FrameType,
) -> Result<(), AnyError> {
    validate_connection_frame(frame, expected_type)?;
    Ok(())
}

pub(crate) fn validate_server_flow_frame(frame: &Frame) -> Result<(), AnyError> {
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

pub(crate) fn is_connection_error_frame(frame: &Frame) -> bool {
    frame.header.frame_type == FrameType::Error && frame.header.id == 0
}

pub(crate) fn route_flow_frame(
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

pub(crate) fn flow_frame_matches_protocol(protocol: FlowProtocol, frame_type: FrameType) -> bool {
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

pub(crate) fn validate_flow_status(frame_type: FrameType, payload: Bytes) -> Result<(), AnyError> {
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

pub(crate) fn status_frame(
    frame_type: FrameType,
    flow_id: u64,
    code: ErrorCode,
) -> Result<Frame, AnyError> {
    let mut payload = BytesMut::new();
    ErrorPayload::new(code).encode(&mut payload)?;
    Ok(Frame::new(frame_type, 0, flow_id, payload.freeze())?)
}

pub(crate) fn decode_open_response(frame: Frame) -> Result<OpenResponse, AnyError> {
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

pub(crate) fn decode_udp_open_response(frame: Frame) -> Result<OpenResponse, AnyError> {
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

pub(crate) fn expect_error_payload(mut payload: Bytes, code: ErrorCode) -> Result<(), AnyError> {
    let status = ErrorPayload::decode(&mut payload)?;
    if status.code == code {
        Ok(())
    } else {
        Err("unexpected error payload code".into())
    }
}

pub(crate) fn map_error_payload(mut payload: Bytes) -> Result<socks5::Reply, AnyError> {
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

pub(crate) async fn write_frame_locked(
    writer: &CarrierWriter,
    frame: &Frame,
    shutdown: &ClientSessionShutdown,
    write_timeout: Option<Duration>,
) -> Result<(), AnyError> {
    let mut writer = tokio::select! {
        writer = writer.lock() => writer,
        () = shutdown.closed() => return Err(session_shutdown_error().into()),
    };
    if shutdown.is_closed() {
        return Err(session_shutdown_error().into());
    }
    write_frame_or_shutdown(&mut *writer, frame, shutdown, write_timeout).await?;
    Ok(())
}

/// Writes one frame with an optional timeout, refusing to start if the session
/// is already closing.
///
/// The write is bounded by `write_timeout` but is *not* raced against shutdown
/// via `select!`: `write_frame` uses `write_all` + `flush` and is not
/// cancellation safe, so dropping it mid-frame would leave a partial frame on
/// the wire. Instead, a timeout on the whole write ensures that a stalled
/// carrier does not block the writer forever; the caller tears down the session
/// when the timeout fires, so the partial write is harmless.
pub(crate) async fn write_frame_or_shutdown<W>(
    writer: &mut W,
    frame: &Frame,
    shutdown: &ClientSessionShutdown,
    write_timeout: Option<Duration>,
) -> Result<(), AnyError>
where
    W: AsyncWrite + Unpin,
{
    if shutdown.is_closed() {
        return Err(session_shutdown_error().into());
    }
    match write_timeout {
        Some(timeout) => {
            time::timeout(timeout, write_frame(writer, frame))
                .await
                .map_err(|_| -> AnyError {
                    io::Error::new(io::ErrorKind::TimedOut, "carrier write timed out").into()
                })??;
        }
        None => {
            write_frame(writer, frame).await?;
        }
    }
    Ok(())
}

pub(crate) fn session_shutdown_error() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "session shutdown")
}
