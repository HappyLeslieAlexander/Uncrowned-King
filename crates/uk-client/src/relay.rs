//! SOCKS5-to-UK TCP relay.

use std::error::Error;

use bytes::{Bytes, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::client::TlsStream;
use tracing::{debug, info, warn};
use uk_proto::{
    ErrorCode, ErrorPayload, Frame, FrameLimits, FrameType, SettingKey, TCP_CLOSE_NORMAL,
    TCP_OPEN_FLAGS_NONE, TcpClose, TcpOpen, frame::DEFAULT_MAX_FRAME_SIZE, read_frame, write_frame,
};

use crate::{config::ClientConfig, session, socks5};

const CLIENT_FLOW_ID: u64 = 1;
const RELAY_BUFFER_SIZE: usize = 16 * 1024;

type AnyError = Box<dyn Error + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientSessionState {
    NegotiatingSocks,
    Authenticating,
    Opening,
    Relaying,
    Closing,
    Closed,
}

pub(crate) async fn run_socks5_listener(
    config: ClientConfig,
    listen: String,
) -> Result<(), AnyError> {
    let listener = TcpListener::bind(&listen).await?;
    info!(event = "socks5.listen", listen = %listen);

    loop {
        let (local, peer) = listener.accept().await?;
        let config = config.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_socks_connection(local, &config).await {
                warn!(event = "socks5.connection.error", peer = %peer, error = %err);
            }
        });
    }
}

async fn handle_socks_connection(
    mut local: TcpStream,
    config: &ClientConfig,
) -> Result<(), AnyError> {
    let mut state = ClientSessionState::NegotiatingSocks;
    let target = socks5::negotiate_connect(&mut local).await?;
    transition(&mut state, ClientSessionState::Authenticating);

    let (mut carrier, settings) = match session::connect_authenticated(config).await {
        Ok(session) => session,
        Err(err) => {
            let _ = socks5::send_reply(&mut local, socks5::Reply::GeneralFailure).await;
            transition(&mut state, ClientSessionState::Closing);
            return Err(err);
        }
    };
    let limits = frame_limits(&settings);

    transition(&mut state, ClientSessionState::Opening);
    let reply = match open_flow(&mut carrier, target, limits).await {
        Ok(reply) => reply,
        Err(err) => {
            let _ = socks5::send_reply(&mut local, socks5::Reply::GeneralFailure).await;
            transition(&mut state, ClientSessionState::Closing);
            return Err(err);
        }
    };
    socks5::send_reply(&mut local, reply).await?;
    if reply != socks5::Reply::Succeeded {
        transition(&mut state, ClientSessionState::Closed);
        return Ok(());
    }

    transition(&mut state, ClientSessionState::Relaying);
    relay_tcp(local, carrier, limits).await?;
    transition(&mut state, ClientSessionState::Closed);
    Ok(())
}

async fn open_flow(
    carrier: &mut TlsStream<TcpStream>,
    target: uk_proto::Target,
    limits: FrameLimits,
) -> Result<socks5::Reply, AnyError> {
    let open = TcpOpen::new(target, TCP_OPEN_FLAGS_NONE);
    let mut payload = BytesMut::new();
    open.encode(&mut payload)?;
    let frame = Frame::new(FrameType::TcpOpen, 0, CLIENT_FLOW_ID, payload.freeze())?;
    write_frame(carrier, &frame).await?;

    loop {
        let frame = read_frame(carrier, limits).await?;
        match frame.header.frame_type {
            FrameType::TcpData if frame.header.id == CLIENT_FLOW_ID && frame.payload.is_empty() => {
                return Ok(socks5::Reply::Succeeded);
            }
            FrameType::PolicyDenied if frame.header.id == CLIENT_FLOW_ID => {
                expect_error_payload(frame.payload, ErrorCode::PolicyDenied)?;
                return Ok(socks5::Reply::NotAllowed);
            }
            FrameType::ResourceLimit if frame.header.id == CLIENT_FLOW_ID => {
                expect_error_payload(frame.payload, ErrorCode::ResourceLimit)?;
                return Ok(socks5::Reply::GeneralFailure);
            }
            FrameType::Error if frame.header.id == CLIENT_FLOW_ID => {
                return map_error_payload(frame.payload);
            }
            FrameType::TcpClose if frame.header.id == CLIENT_FLOW_ID => {
                return Ok(socks5::Reply::ConnectionRefused);
            }
            FrameType::Ping => write_pong(carrier, &frame).await?,
            FrameType::Pong => {}
            _ => return Err("unexpected frame while opening tcp flow".into()),
        }
    }
}

async fn relay_tcp(
    mut local: TcpStream,
    mut carrier: TlsStream<TcpStream>,
    limits: FrameLimits,
) -> Result<(), AnyError> {
    let mut local_to_remote_open = true;
    let mut remote_to_local_open = true;
    let mut local_buf = Box::new([0_u8; RELAY_BUFFER_SIZE]);

    while local_to_remote_open || remote_to_local_open {
        tokio::select! {
            read = local.read(local_buf.as_mut()), if local_to_remote_open => {
                let read = read?;
                if read == 0 {
                    send_tcp_close(&mut carrier, CLIENT_FLOW_ID, TCP_CLOSE_NORMAL).await?;
                    local_to_remote_open = false;
                } else {
                    send_tcp_data(&mut carrier, CLIENT_FLOW_ID, Bytes::copy_from_slice(&local_buf[..read])).await?;
                }
            }
            frame = read_frame(&mut carrier, limits), if remote_to_local_open => {
                let frame = frame?;
                match frame.header.frame_type {
                    FrameType::TcpData if frame.header.id == CLIENT_FLOW_ID => {
                        if !frame.payload.is_empty() {
                            local.write_all(&frame.payload).await?;
                        }
                    }
                    FrameType::TcpClose if frame.header.id == CLIENT_FLOW_ID => {
                        let mut payload = frame.payload;
                        let _close = TcpClose::decode(&mut payload)?;
                        local.shutdown().await?;
                        remote_to_local_open = false;
                    }
                    FrameType::Error | FrameType::PolicyDenied | FrameType::ResourceLimit
                        if frame.header.id == CLIENT_FLOW_ID =>
                    {
                        let mut payload = frame.payload;
                        let _status = ErrorPayload::decode(&mut payload)?;
                        local.shutdown().await?;
                        remote_to_local_open = false;
                    }
                    FrameType::Ping => write_pong(&mut carrier, &frame).await?,
                    FrameType::Pong => {}
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

fn frame_limits(settings: &uk_proto::Settings) -> FrameLimits {
    FrameLimits {
        max_frame_size: settings
            .get(SettingKey::MaxFrameSize)
            .unwrap_or(DEFAULT_MAX_FRAME_SIZE),
    }
}

fn transition(state: &mut ClientSessionState, next: ClientSessionState) {
    debug!(event = "client.session.state", from = ?*state, to = ?next);
    *state = next;
}
