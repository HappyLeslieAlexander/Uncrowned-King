#![allow(unused_imports)]

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
use super::context::*;
use super::listener::*;
use super::session_manager::*;
use super::udp::*;
use crate::{
    ClientReloadReceiver, ClientReloadRequest,
    config::{ClientConfig, validate_endpoint},
    config_state::{ClientConfigSnapshot, ClientConfigState},
    observability::{ActiveFlowGuard, ClientMetrics, RelayDirection, RelayProtocol},
    session, socks5,
};
pub(crate) async fn handle_socks_connection(
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

pub(crate) async fn negotiate_socks_request(
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

pub(crate) async fn relay_tcp(
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
pub(crate) const LOCAL_WRITE_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

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
pub(crate) async fn write_all_or_shutdown<W>(
    writer: &mut W,
    payload: &[u8],
    shutdown_rx: &mut watch::Receiver<bool>,
) -> Result<bool, AnyError>
where
    W: AsyncWrite + Unpin,
{
    write_all_or_shutdown_within(writer, payload, shutdown_rx, LOCAL_WRITE_SHUTDOWN_GRACE).await
}

pub(crate) async fn write_all_or_shutdown_within<W>(
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
pub(crate) async fn flush_buffered_frames_before_shutdown<W>(
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

pub(crate) async fn flush_pending_local_data(flow: &mut ClientFlow) -> Result<(), AnyError> {
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
