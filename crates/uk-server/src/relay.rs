//! Server-side UK TCP relay.

use std::{
    collections::HashMap,
    error::Error,
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
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
    ErrorCode, ErrorPayload, Frame, FrameLimits, FrameType, TCP_CLOSE_ERROR, TCP_CLOSE_NORMAL,
    TCP_OPEN_FLAGS_NONE, Target, TcpClose, TcpOpen, read_frame, write_frame,
};

const RELAY_BUFFER_SIZE: usize = 16 * 1024;
const TARGET_WRITE_QUEUE_CAPACITY: usize = 32;

type AnyError = Box<dyn Error + Send + Sync>;
type CarrierWriter = Arc<Mutex<WriteHalf<TlsStream<TcpStream>>>>;
type FlowTable = HashMap<u64, mpsc::Sender<TargetCommand>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerSessionState {
    Authenticated,
    Relaying,
}

#[derive(Debug)]
enum OpenFailure {
    PolicyDenied,
    TargetUnavailable(io::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlowEvent {
    TargetClosed(u64),
    TargetActivity,
}

enum SessionEvent {
    Flow(Option<FlowEvent>),
    Frame(Frame),
    IdleTimeout,
}

#[derive(Debug)]
enum TargetCommand {
    Data(Bytes),
    Close,
}

pub(crate) async fn relay_session(
    carrier: TlsStream<TcpStream>,
    credential: Credential,
    policy_set: Arc<PolicySet>,
    limits: FrameLimits,
    max_streams: u64,
    idle_timeout: Option<Duration>,
) -> Result<(), AnyError> {
    let mut state = ServerSessionState::Authenticated;
    transition(&mut state, ServerSessionState::Relaying);

    let (mut carrier_reader, carrier_writer) = tokio::io::split(carrier);
    let carrier_writer = Arc::new(Mutex::new(carrier_writer));
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let mut target_writers = FlowTable::new();

    loop {
        match next_session_event(&mut carrier_reader, &mut event_rx, limits, idle_timeout).await? {
            SessionEvent::Flow(Some(FlowEvent::TargetClosed(flow_id))) => {
                if target_writers.remove(&flow_id).is_some() {
                    info!(event = "tcp.closed", flow_id);
                }
            }
            SessionEvent::Flow(Some(FlowEvent::TargetActivity) | None) => {}
            SessionEvent::Frame(frame) => {
                handle_session_frame(
                    frame,
                    &credential,
                    &policy_set,
                    &carrier_writer,
                    &event_tx,
                    &mut target_writers,
                    max_streams,
                )
                .await?;
            }
            SessionEvent::IdleTimeout => {
                info!(event = "server.session.idle_timeout");
                return Ok(());
            }
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
            frame = read_frame(carrier_reader, limits) => Ok(SessionEvent::Frame(frame?)),
            () = tokio::time::sleep(idle_timeout) => Ok(SessionEvent::IdleTimeout),
        }
    } else {
        tokio::select! {
            event = event_rx.recv() => Ok(SessionEvent::Flow(event)),
            frame = read_frame(carrier_reader, limits) => Ok(SessionEvent::Frame(frame?)),
        }
    }
}

async fn handle_session_frame(
    frame: Frame,
    credential: &Credential,
    policy_set: &PolicySet,
    carrier_writer: &CarrierWriter,
    event_tx: &mpsc::UnboundedSender<FlowEvent>,
    target_writers: &mut FlowTable,
    max_streams: u64,
) -> Result<(), AnyError> {
    match frame.header.frame_type {
        FrameType::TcpOpen => {
            if target_writers.len() as u64 >= max_streams {
                send_resource_limit(carrier_writer, frame.header.id).await?;
                send_tcp_close(carrier_writer, frame.header.id, TCP_CLOSE_ERROR).await?;
                return Ok(());
            }
            if target_writers.contains_key(&frame.header.id) {
                send_error(carrier_writer, frame.header.id, ErrorCode::Protocol).await?;
                send_tcp_close(carrier_writer, frame.header.id, TCP_CLOSE_ERROR).await?;
                return Ok(());
            }
            if let Some((flow_id, target_writer_tx)) =
                handle_tcp_open(carrier_writer, event_tx, frame, credential, policy_set).await?
            {
                target_writers.insert(flow_id, target_writer_tx);
            }
            Ok(())
        }
        FrameType::TcpData => {
            if !frame.payload.is_empty() {
                let flow_id = frame.header.id;
                if let Some(target) = target_writers.get(&flow_id) {
                    if target
                        .send(TargetCommand::Data(frame.payload))
                        .await
                        .is_err()
                    {
                        target_writers.remove(&flow_id);
                    }
                } else {
                    send_error(carrier_writer, flow_id, ErrorCode::Protocol).await?;
                }
            }
            Ok(())
        }
        FrameType::TcpClose => {
            let mut payload = frame.payload;
            let _close = TcpClose::decode(&mut payload)?;
            if let Some(target) = target_writers.remove(&frame.header.id) {
                let _ = target.send(TargetCommand::Close).await;
            }
            Ok(())
        }
        FrameType::Ping => write_pong(carrier_writer, &frame).await,
        FrameType::Pong => Ok(()),
        _ => Err("unexpected frame while relaying session".into()),
    }
}

async fn handle_tcp_open(
    carrier_writer: &CarrierWriter,
    event_tx: &mpsc::UnboundedSender<FlowEvent>,
    frame: Frame,
    credential: &Credential,
    policy_set: &PolicySet,
) -> Result<Option<(u64, mpsc::Sender<TargetCommand>)>, AnyError> {
    let flow_id = frame.header.id;
    if flow_id == 0 {
        send_error(carrier_writer, flow_id, ErrorCode::Protocol).await?;
        return Err("tcp flow id must be non-zero".into());
    }

    let mut payload = frame.payload;
    let open = match TcpOpen::decode(&mut payload) {
        Ok(open) => open,
        Err(err) => {
            send_error(carrier_writer, flow_id, ErrorCode::InvalidTarget).await?;
            send_tcp_close(carrier_writer, flow_id, TCP_CLOSE_ERROR).await?;
            warn!(event = "tcp.open.invalid", flow_id, error = %err);
            return Ok(None);
        }
    };
    if open.open_flags != TCP_OPEN_FLAGS_NONE {
        send_error(carrier_writer, flow_id, ErrorCode::Protocol).await?;
        send_tcp_close(carrier_writer, flow_id, TCP_CLOSE_ERROR).await?;
        return Ok(None);
    }

    let target = open.target;
    let target_stream = match connect_allowed_target(&target, credential, policy_set).await {
        Ok(stream) => stream,
        Err(OpenFailure::PolicyDenied) => {
            warn!(event = "policy.denied", flow_id, target = ?target);
            send_policy_denied(carrier_writer, flow_id).await?;
            send_tcp_close(carrier_writer, flow_id, TCP_CLOSE_NORMAL).await?;
            return Ok(None);
        }
        Err(OpenFailure::TargetUnavailable(err)) => {
            warn!(event = "target.unavailable", flow_id, target = ?target, error = %err);
            send_error(carrier_writer, flow_id, ErrorCode::TargetUnavailable).await?;
            send_tcp_close(carrier_writer, flow_id, TCP_CLOSE_ERROR).await?;
            return Ok(None);
        }
    };

    let (target_reader, target_writer) = target_stream.into_split();
    let (target_writer_tx, target_writer_rx) = mpsc::channel(TARGET_WRITE_QUEUE_CAPACITY);
    send_tcp_data(carrier_writer, flow_id, Bytes::new()).await?;
    spawn_target_reader(
        flow_id,
        target_reader,
        Arc::clone(carrier_writer),
        event_tx.clone(),
    );
    spawn_target_writer(
        flow_id,
        target_writer,
        target_writer_rx,
        Arc::clone(carrier_writer),
        event_tx.clone(),
    );
    info!(event = "tcp.open", flow_id, target = ?target);
    Ok(Some((flow_id, target_writer_tx)))
}

fn spawn_target_reader(
    flow_id: u64,
    target_reader: OwnedReadHalf,
    carrier_writer: CarrierWriter,
    event_tx: mpsc::UnboundedSender<FlowEvent>,
) {
    tokio::spawn(async move {
        if let Err(err) =
            relay_target_to_client(flow_id, target_reader, &carrier_writer, &event_tx).await
        {
            warn!(event = "tcp.target.read.error", flow_id, error = %err);
            let _ = send_error(&carrier_writer, flow_id, ErrorCode::TargetUnavailable).await;
            let _ = send_tcp_close(&carrier_writer, flow_id, TCP_CLOSE_ERROR).await;
        }
        let _ = event_tx.send(FlowEvent::TargetClosed(flow_id));
    });
}

fn spawn_target_writer(
    flow_id: u64,
    target_writer: OwnedWriteHalf,
    commands: mpsc::Receiver<TargetCommand>,
    carrier_writer: CarrierWriter,
    event_tx: mpsc::UnboundedSender<FlowEvent>,
) {
    tokio::spawn(async move {
        if let Err(err) = relay_client_to_target(target_writer, commands).await {
            warn!(event = "tcp.target.write.error", flow_id, error = %err);
            let _ = send_error(&carrier_writer, flow_id, ErrorCode::TargetUnavailable).await;
            let _ = send_tcp_close(&carrier_writer, flow_id, TCP_CLOSE_ERROR).await;
        }
        let _ = event_tx.send(FlowEvent::TargetClosed(flow_id));
    });
}

async fn relay_client_to_target(
    mut target_writer: OwnedWriteHalf,
    mut commands: mpsc::Receiver<TargetCommand>,
) -> Result<(), AnyError> {
    while let Some(command) = commands.recv().await {
        match command {
            TargetCommand::Data(payload) => target_writer.write_all(&payload).await?,
            TargetCommand::Close => {
                target_writer.shutdown().await?;
                return Ok(());
            }
        }
    }
    Ok(())
}

async fn relay_target_to_client(
    flow_id: u64,
    mut target_reader: OwnedReadHalf,
    carrier_writer: &CarrierWriter,
    event_tx: &mpsc::UnboundedSender<FlowEvent>,
) -> Result<(), AnyError> {
    let mut target_buf = Box::new([0_u8; RELAY_BUFFER_SIZE]);
    loop {
        let read = target_reader.read(target_buf.as_mut()).await?;
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
        let _ = event_tx.send(FlowEvent::TargetActivity);
    }
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
    debug!(event = "server.session.state", from = ?*state, to = ?next);
    *state = next;
}
