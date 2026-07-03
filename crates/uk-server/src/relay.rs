//! Server-side UK TCP relay.

use std::{
    error::Error,
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use bytes::{Bytes, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, lookup_host},
};
use tokio_rustls::server::TlsStream;
use tracing::{debug, info, warn};
use uk_auth::Credential;
use uk_policy::{PolicyContext, PolicyDecision, PolicySet};
use uk_proto::{
    Frame, FrameLimits, FrameType, TCP_CLOSE_ERROR, TCP_CLOSE_NORMAL, TCP_OPEN_FLAGS_NONE, Target,
    TcpClose, TcpOpen, read_frame, write_frame,
};

const RELAY_BUFFER_SIZE: usize = 16 * 1024;

type AnyError = Box<dyn Error + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerSessionState {
    Authenticated,
    Opening,
    Relaying,
    Closed,
}

#[derive(Debug)]
enum OpenFailure {
    PolicyDenied,
    TargetUnavailable(io::Error),
}

pub(crate) async fn relay_session(
    mut carrier: TlsStream<TcpStream>,
    credential: Credential,
    policy_set: Arc<PolicySet>,
    limits: FrameLimits,
) -> Result<(), AnyError> {
    let mut state = ServerSessionState::Authenticated;

    loop {
        let frame = read_frame(&mut carrier, limits).await?;
        match frame.header.frame_type {
            FrameType::TcpOpen => {
                transition(&mut state, ServerSessionState::Opening);
                handle_tcp_open(&mut carrier, frame, &credential, &policy_set, limits).await?;
                transition(&mut state, ServerSessionState::Closed);
                return Ok(());
            }
            FrameType::Ping => write_pong(&mut carrier, &frame).await?,
            FrameType::Pong => {}
            _ => return Err("expected TCP_OPEN after authentication".into()),
        }
    }
}

async fn handle_tcp_open(
    carrier: &mut TlsStream<TcpStream>,
    frame: Frame,
    credential: &Credential,
    policy_set: &PolicySet,
    limits: FrameLimits,
) -> Result<(), AnyError> {
    let flow_id = frame.header.id;
    if flow_id == 0 {
        send_error(carrier, flow_id).await?;
        return Err("tcp flow id must be non-zero".into());
    }

    let mut payload = frame.payload;
    let open = TcpOpen::decode(&mut payload)?;
    if open.open_flags != TCP_OPEN_FLAGS_NONE {
        send_error(carrier, flow_id).await?;
        send_tcp_close(carrier, flow_id, TCP_CLOSE_ERROR).await?;
        return Ok(());
    }

    let target = open.target;
    let target_stream = match connect_allowed_target(&target, credential, policy_set).await {
        Ok(stream) => stream,
        Err(OpenFailure::PolicyDenied) => {
            warn!(event = "policy.denied", flow_id, target = ?target);
            send_policy_denied(carrier, flow_id).await?;
            send_tcp_close(carrier, flow_id, TCP_CLOSE_NORMAL).await?;
            return Ok(());
        }
        Err(OpenFailure::TargetUnavailable(err)) => {
            warn!(event = "target.unavailable", flow_id, target = ?target, error = %err);
            send_error(carrier, flow_id).await?;
            send_tcp_close(carrier, flow_id, TCP_CLOSE_ERROR).await?;
            return Ok(());
        }
    };

    info!(event = "tcp.open", flow_id, target = ?target);
    send_tcp_data(carrier, flow_id, Bytes::new()).await?;
    relay_tcp_flow(carrier, target_stream, flow_id, limits).await
}

async fn connect_allowed_target(
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
            Ok(stream) => return Ok(stream),
            Err(err) => last_error = Some(err),
        }
    }

    Err(OpenFailure::TargetUnavailable(last_error.unwrap_or_else(
        || io::Error::new(io::ErrorKind::NotFound, "target has no socket addresses"),
    )))
}

async fn relay_tcp_flow(
    carrier: &mut TlsStream<TcpStream>,
    mut target: TcpStream,
    flow_id: u64,
    limits: FrameLimits,
) -> Result<(), AnyError> {
    let mut state = ServerSessionState::Relaying;
    let mut client_to_target_open = true;
    let mut target_to_client_open = true;
    let mut target_buf = Box::new([0_u8; RELAY_BUFFER_SIZE]);

    while client_to_target_open || target_to_client_open {
        tokio::select! {
            frame = read_frame(carrier, limits), if client_to_target_open => {
                let frame = frame?;
                match frame.header.frame_type {
                    FrameType::TcpData if frame.header.id == flow_id => {
                        if !frame.payload.is_empty() {
                            target.write_all(&frame.payload).await?;
                        }
                    }
                    FrameType::TcpClose if frame.header.id == flow_id => {
                        let mut payload = frame.payload;
                        let _close = TcpClose::decode(&mut payload)?;
                        target.shutdown().await?;
                        client_to_target_open = false;
                    }
                    FrameType::Ping => write_pong(carrier, &frame).await?,
                    FrameType::Pong => {}
                    _ => return Err("unexpected frame while relaying tcp flow".into()),
                }
            }
            read = target.read(target_buf.as_mut()), if target_to_client_open => {
                let read = read?;
                if read == 0 {
                    send_tcp_close(carrier, flow_id, TCP_CLOSE_NORMAL).await?;
                    target_to_client_open = false;
                } else {
                    send_tcp_data(carrier, flow_id, Bytes::copy_from_slice(&target_buf[..read])).await?;
                }
            }
        }
    }

    transition(&mut state, ServerSessionState::Closed);
    Ok(())
}

async fn send_tcp_data<W>(writer: &mut W, flow_id: u64, payload: Bytes) -> Result<(), AnyError>
where
    W: AsyncWrite + Unpin,
{
    let frame = Frame::new(FrameType::TcpData, 0, flow_id, payload)?;
    write_frame(writer, &frame).await?;
    Ok(())
}

async fn send_tcp_close<W>(writer: &mut W, flow_id: u64, close_code: u16) -> Result<(), AnyError>
where
    W: AsyncWrite + Unpin,
{
    let mut payload = BytesMut::new();
    TcpClose::new(close_code).encode(&mut payload)?;
    let frame = Frame::new(FrameType::TcpClose, 0, flow_id, payload.freeze())?;
    write_frame(writer, &frame).await?;
    Ok(())
}

async fn send_policy_denied<W>(writer: &mut W, flow_id: u64) -> Result<(), AnyError>
where
    W: AsyncWrite + Unpin,
{
    let frame = Frame::new(FrameType::PolicyDenied, 0, flow_id, Bytes::new())?;
    write_frame(writer, &frame).await?;
    Ok(())
}

async fn send_error<W>(writer: &mut W, flow_id: u64) -> Result<(), AnyError>
where
    W: AsyncWrite + Unpin,
{
    let frame = Frame::new(FrameType::Error, 0, flow_id, Bytes::new())?;
    write_frame(writer, &frame).await?;
    Ok(())
}

async fn write_pong<W>(writer: &mut W, request_frame: &Frame) -> Result<(), AnyError>
where
    W: AsyncWrite + Unpin,
{
    let pong_frame = Frame::new(
        FrameType::Pong,
        0,
        request_frame.header.id,
        request_frame.payload.clone(),
    )?;
    write_frame(writer, &pong_frame).await?;
    Ok(())
}

fn transition(state: &mut ServerSessionState, next: ServerSessionState) {
    debug!(event = "server.session.state", from = ?*state, to = ?next);
    *state = next;
}
