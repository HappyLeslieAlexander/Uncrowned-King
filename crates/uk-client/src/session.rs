//! Client-side UK session setup.

use std::{error::Error, time::Duration};

use bytes::BytesMut;
use tokio::{net::TcpStream, time};
use tokio_rustls::client::TlsStream;
use tracing::info;
use uk_auth::{AuthChallenge, AuthResponse, unix_now};
use uk_proto::{Frame, FrameLimits, FrameType, Settings, read_frame, write_frame};

use crate::{config::ClientConfig, tls};

type AnyError = Box<dyn Error + Send + Sync>;

/// Connects to the configured server and completes UK authentication.
pub async fn connect_authenticated(
    config: &ClientConfig,
) -> Result<(TlsStream<TcpStream>, Settings), AnyError> {
    config.validate_auth_material()?;
    if let Some(timeout) = handshake_timeout(config.handshake_timeout_seconds()) {
        match time::timeout(timeout, connect_authenticated_inner(config)).await {
            Ok(result) => result,
            Err(_) => Err("client handshake timeout".into()),
        }
    } else {
        connect_authenticated_inner(config).await
    }
}

async fn connect_authenticated_inner(
    config: &ClientConfig,
) -> Result<(TlsStream<TcpStream>, Settings), AnyError> {
    let connector = tls::connector(&config.ca_cert_path)?;
    let tcp = TcpStream::connect(&config.server_addr).await?;
    let server_name = tls::server_name(config.server_name.clone())?;
    let mut stream = connector.connect(server_name, tcp).await?;
    let exporter = tls::exporter(&stream)?;

    let challenge_frame = read_frame(&mut stream, FrameLimits::default()).await?;
    if challenge_frame.header.frame_type != FrameType::AuthChallenge {
        return Err("expected AUTH_CHALLENGE".into());
    }
    let mut challenge_payload = challenge_frame.payload;
    let challenge = AuthChallenge::decode(&mut challenge_payload)?;

    let response = AuthResponse::for_challenge(
        config.key_id.as_bytes(),
        config.secret.as_bytes(),
        &exporter,
        &challenge,
        unix_now(),
        Vec::new(),
    )?;
    let mut response_payload = BytesMut::new();
    response.encode(&mut response_payload)?;
    let response_frame = Frame::new(FrameType::AuthResponse, 0, 0, response_payload.freeze())?;
    write_frame(&mut stream, &response_frame).await?;

    let settings_frame = read_frame(&mut stream, FrameLimits::default()).await?;
    if settings_frame.header.frame_type != FrameType::Settings {
        return Err("expected SETTINGS".into());
    }
    let mut settings_payload = settings_frame.payload;
    let settings = Settings::decode(&mut settings_payload)?;
    info!(
        event = "auth.success",
        max_frame_size = ?settings.get(uk_proto::SettingKey::MaxFrameSize)
    );
    Ok((stream, settings))
}

fn handshake_timeout(seconds: u64) -> Option<Duration> {
    (seconds != 0).then(|| Duration::from_secs(seconds))
}
