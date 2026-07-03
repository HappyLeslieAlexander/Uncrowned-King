//! SOCKS5-to-UK TCP relay.

use std::{
    collections::{HashMap, hash_map::Entry},
    error::Error,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use bytes::{Bytes, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    net::{TcpListener, TcpStream},
    sync::{Mutex, mpsc},
};
use tokio_rustls::client::TlsStream;
use tracing::{debug, info, warn};
use uk_proto::{
    ErrorCode, ErrorPayload, FIRST_CLIENT_FLOW_ID, FLOW_ID_STEP, Frame, FrameLimits, FrameType,
    SettingKey, TCP_CLOSE_NORMAL, TCP_OPEN_FLAGS_NONE, Target, TcpClose, TcpOpen,
    frame::DEFAULT_MAX_FRAME_SIZE, is_client_initiated_flow_id, read_frame, write_frame,
};

use crate::{config::ClientConfig, session, socks5};

const FLOW_ID_ALLOCATION_ATTEMPTS: usize = 1024;
const FLOW_FRAME_QUEUE_CAPACITY: usize = 32;
const RELAY_BUFFER_SIZE: usize = 16 * 1024;

type AnyError = Box<dyn Error + Send + Sync>;
type CarrierWriter = Arc<Mutex<WriteHalf<TlsStream<TcpStream>>>>;
type FlowTable = Arc<Mutex<HashMap<u64, mpsc::Sender<Frame>>>>;

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
    closed: AtomicBool,
    next_flow_id: AtomicU64,
}

struct ClientSessionManager {
    config: ClientConfig,
    current: Mutex<Option<Arc<ClientSession>>>,
}

struct ClientFlow {
    id: u64,
    frames: mpsc::Receiver<Frame>,
    session: Arc<ClientSession>,
}

enum OpenOutcome {
    Open(ClientFlow),
    Rejected(socks5::Reply),
}

pub(crate) async fn run_socks5_listener(
    config: ClientConfig,
    listen: String,
) -> Result<(), AnyError> {
    let sessions = Arc::new(ClientSessionManager::new(config));
    let listener = TcpListener::bind(&listen).await?;
    info!(event = "socks5.listen", listen = %listen);

    loop {
        let (local, peer) = listener.accept().await?;
        let sessions = Arc::clone(&sessions);
        tokio::spawn(async move {
            if let Err(err) = handle_socks_connection(local, sessions).await {
                warn!(event = "socks5.connection.error", peer = %peer, error = %err);
            }
        });
    }
}

impl ClientSessionManager {
    fn new(config: ClientConfig) -> Self {
        Self {
            config,
            current: Mutex::new(None),
        }
    }

    async fn open_flow(&self, target: Target) -> Result<OpenOutcome, AnyError> {
        let mut last_error = None;
        for attempt in 0..2 {
            let session = self.current_session().await?;
            match session.open_flow(target.clone()).await {
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
        let mut current = self.current.lock().await;
        if let Some(session) = current.as_ref()
            && !session.is_closed()
        {
            return Ok(Arc::clone(session));
        }

        *current = None;
        info!(event = "client.session.connect");
        let session = ClientSession::connect(&self.config).await?;
        *current = Some(Arc::clone(&session));
        Ok(session)
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
}

impl ClientSession {
    async fn connect(config: &ClientConfig) -> Result<Arc<Self>, AnyError> {
        let (carrier, settings) = session::connect_authenticated(config).await?;
        let limits = frame_limits(&settings);
        let (carrier_reader, carrier_writer) = tokio::io::split(carrier);
        let session = Arc::new(Self {
            writer: Arc::new(Mutex::new(carrier_writer)),
            flows: Arc::new(Mutex::new(HashMap::new())),
            limits,
            closed: AtomicBool::new(false),
            next_flow_id: AtomicU64::new(FIRST_CLIENT_FLOW_ID),
        });
        spawn_carrier_reader(carrier_reader, Arc::clone(&session));
        Ok(session)
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    async fn close(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            self.flows.lock().await.clear();
            let mut writer = self.writer.lock().await;
            if let Err(err) = writer.shutdown().await {
                debug!(event = "client.session.shutdown.error", error = %err);
            }
        }
    }

    async fn open_flow(self: &Arc<Self>, target: Target) -> Result<OpenOutcome, AnyError> {
        if self.is_closed() {
            return Err("uk session is closed".into());
        }
        let (flow_id, frames) = self.reserve_flow().await?;
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
        };
        let frame = flow
            .frames
            .recv()
            .await
            .ok_or("uk session closed while opening flow")?;
        match frame.header.frame_type {
            FrameType::TcpData if frame.payload.is_empty() => Ok(OpenOutcome::Open(flow)),
            FrameType::PolicyDenied => {
                expect_error_payload(frame.payload, ErrorCode::PolicyDenied)?;
                self.flows.lock().await.remove(&flow_id);
                Ok(OpenOutcome::Rejected(socks5::Reply::NotAllowed))
            }
            FrameType::ResourceLimit => {
                expect_error_payload(frame.payload, ErrorCode::ResourceLimit)?;
                self.flows.lock().await.remove(&flow_id);
                Ok(OpenOutcome::Rejected(socks5::Reply::GeneralFailure))
            }
            FrameType::Error => {
                let reply = map_error_payload(frame.payload)?;
                self.flows.lock().await.remove(&flow_id);
                Ok(OpenOutcome::Rejected(reply))
            }
            FrameType::TcpClose => {
                let mut payload = frame.payload;
                let _close = TcpClose::decode(&mut payload)?;
                self.flows.lock().await.remove(&flow_id);
                Ok(OpenOutcome::Rejected(socks5::Reply::ConnectionRefused))
            }
            _ => Err("unexpected frame while opening tcp flow".into()),
        }
    }

    fn allocate_flow_id(&self) -> u64 {
        self.next_flow_id.fetch_add(FLOW_ID_STEP, Ordering::Relaxed)
    }

    async fn reserve_flow(&self) -> Result<(u64, mpsc::Receiver<Frame>), AnyError> {
        for _ in 0..FLOW_ID_ALLOCATION_ATTEMPTS {
            let flow_id = self.allocate_flow_id();
            if !is_client_initiated_flow_id(flow_id) {
                continue;
            }

            let (sender, frames) = mpsc::channel(FLOW_FRAME_QUEUE_CAPACITY);
            let mut flows = self.flows.lock().await;
            if let Entry::Vacant(entry) = flows.entry(flow_id) {
                entry.insert(sender);
                return Ok((flow_id, frames));
            }
        }

        Err("no available client flow id".into())
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

    async fn write_pong(&self, request_frame: &Frame) -> Result<(), AnyError> {
        let pong_frame = Frame::new(
            FrameType::Pong,
            0,
            request_frame.header.id,
            request_frame.payload.clone(),
        )?;
        self.write_frame(&pong_frame).await
    }

    async fn write_frame(&self, frame: &Frame) -> Result<(), AnyError> {
        let result = write_frame_locked(&self.writer, frame).await;
        if result.is_err() {
            self.close().await;
        }
        result
    }
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
                    warn!(event = "client.session.read.error", error = %err);
                    close_session(&session).await;
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
            let flow_id = frame.header.id;
            let sender = session.flows.lock().await.get(&flow_id).cloned();
            if let Some(sender) = sender
                && sender.send(frame).await.is_err()
            {
                session.flows.lock().await.remove(&flow_id);
            }
            Ok(())
        }
        FrameType::Ping => session.write_pong(&frame).await,
        FrameType::Pong => Ok(()),
        _ => Err("unexpected frame on client session".into()),
    }
}

async fn handle_socks_connection(
    mut local: TcpStream,
    sessions: Arc<ClientSessionManager>,
) -> Result<(), AnyError> {
    let mut state = ClientConnectionState::NegotiatingSocks;
    let target = socks5::negotiate_connect(&mut local).await?;

    transition(&mut state, ClientConnectionState::Opening);
    let flow = match sessions.open_flow(target).await {
        Ok(OpenOutcome::Open(flow)) => flow,
        Ok(OpenOutcome::Rejected(reply)) => {
            socks5::send_reply(&mut local, reply).await?;
            transition(&mut state, ClientConnectionState::Closed);
            return Ok(());
        }
        Err(err) => {
            let _ = socks5::send_reply(&mut local, socks5::Reply::GeneralFailure).await;
            transition(&mut state, ClientConnectionState::Closing);
            return Err(err);
        }
    };
    socks5::send_reply(&mut local, socks5::Reply::Succeeded).await?;

    transition(&mut state, ClientConnectionState::Relaying);
    let flow_id = flow.id;
    let flow_session = Arc::clone(&flow.session);
    let relay_result = relay_tcp(local, flow).await;
    flow_session.flows.lock().await.remove(&flow_id);
    transition(&mut state, ClientConnectionState::Closed);
    relay_result
}

async fn relay_tcp(mut local: TcpStream, mut flow: ClientFlow) -> Result<(), AnyError> {
    let mut local_to_remote_open = true;
    let mut remote_to_local_open = true;
    let mut local_buf = Box::new([0_u8; RELAY_BUFFER_SIZE]);

    while local_to_remote_open || remote_to_local_open {
        tokio::select! {
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
            frame = flow.frames.recv(), if remote_to_local_open => {
                let Some(frame) = frame else {
                    local.shutdown().await?;
                    remote_to_local_open = false;
                    continue;
                };
                match frame.header.frame_type {
                    FrameType::TcpData => {
                        if !frame.payload.is_empty() {
                            local.write_all(&frame.payload).await?;
                        }
                    }
                    FrameType::TcpClose => {
                        let mut payload = frame.payload;
                        let _close = TcpClose::decode(&mut payload)?;
                        local.shutdown().await?;
                        remote_to_local_open = false;
                    }
                    FrameType::Error | FrameType::PolicyDenied | FrameType::ResourceLimit => {
                        let mut payload = frame.payload;
                        let _status = ErrorPayload::decode(&mut payload)?;
                        local.shutdown().await?;
                        remote_to_local_open = false;
                    }
                    _ => return Err("unexpected frame while relaying tcp flow".into()),
                }
            }
        }
    }

    Ok(())
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
        ErrorCode::InvalidTarget | ErrorCode::TargetUnavailable => socks5::Reply::HostUnreachable,
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

async fn write_frame_locked(writer: &CarrierWriter, frame: &Frame) -> Result<(), AnyError> {
    let mut writer = writer.lock().await;
    write_frame(&mut *writer, frame).await?;
    Ok(())
}

fn frame_limits(settings: &uk_proto::Settings) -> FrameLimits {
    FrameLimits {
        max_frame_size: settings
            .get(SettingKey::MaxFrameSize)
            .unwrap_or(DEFAULT_MAX_FRAME_SIZE),
    }
}

fn transition(state: &mut ClientConnectionState, next: ClientConnectionState) {
    debug!(event = "client.connection.state", from = ?*state, to = ?next);
    *state = next;
}
