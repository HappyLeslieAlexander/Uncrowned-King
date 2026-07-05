//! Client-side UK session setup.

use std::{error::Error, time::Duration};

use bytes::BytesMut;
use rustls::pki_types::ServerName;
use tokio::{net::TcpStream, time};
use tokio_rustls::{TlsConnector, client::TlsStream};
use tracing::{info, warn};
use uk_auth::{AuthChallenge, AuthResponse, unix_now};
use uk_proto::{
    ErrorCode, ErrorPayload, Frame, FrameLimits, FrameType, MAX_FRAME_PAYLOAD_SIZE,
    MIN_TCP_RELAY_FRAME_SIZE, SettingKey, Settings, read_frame, validate_connection_frame,
    write_frame,
};

use crate::{config::ClientConfig, tls};

type AnyError = Box<dyn Error + Send + Sync>;

/// Connects to the configured server and completes UK authentication.
pub async fn connect_authenticated(
    config: &ClientConfig,
) -> Result<(TlsStream<TcpStream>, Settings), AnyError> {
    config.validate_network_endpoints()?;
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
    let server_name = tls::server_name(config.server_name.clone())?;
    let mut last_error = None;

    for endpoint in config.server_endpoints() {
        match connect_authenticated_endpoint(config, &connector, server_name.clone(), endpoint)
            .await
        {
            Ok(session) => return Ok(session),
            Err(err) => {
                warn!(
                    event = "client.session.connect_endpoint_failed",
                    server_addr = %endpoint,
                    error = %err
                );
                last_error = Some(err);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| "no server endpoints configured".into()))
}

async fn connect_authenticated_endpoint(
    config: &ClientConfig,
    connector: &TlsConnector,
    server_name: ServerName<'static>,
    endpoint: &str,
) -> Result<(TlsStream<TcpStream>, Settings), AnyError> {
    let tcp = TcpStream::connect(endpoint).await?;
    tcp.set_nodelay(true)?;
    let mut stream = connector.connect(server_name, tcp).await?;
    tls::verify_alpn(&stream)?;
    let exporter = tls::exporter(&stream)?;

    let challenge_frame = read_frame(&mut stream, FrameLimits::default()).await?;
    validate_connection_frame(&challenge_frame, FrameType::AuthChallenge)?;
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
    let settings = decode_server_settings_frame(settings_frame)?;
    info!(
        event = "auth.success",
        max_frame_size = ?settings.get(SettingKey::MaxFrameSize)
    );
    Ok((stream, settings))
}

fn decode_server_settings_frame(frame: Frame) -> Result<Settings, AnyError> {
    match frame.header.frame_type {
        FrameType::Settings => {
            validate_connection_frame(&frame, FrameType::Settings)?;
            let mut settings_payload = frame.payload;
            let settings = Settings::decode(&mut settings_payload)?;
            validate_server_settings(&settings)?;
            Ok(settings)
        }
        FrameType::Error => {
            validate_connection_frame(&frame, FrameType::Error)?;
            let mut payload = frame.payload;
            let status = ErrorPayload::decode(&mut payload)?;
            match status.code {
                ErrorCode::AuthFailed => Err("authentication failed".into()),
                code => Err(format!("server returned handshake error: {code:?}").into()),
            }
        }
        _ => {
            validate_connection_frame(&frame, FrameType::Settings)?;
            Err("unexpected connection frame type".into())
        }
    }
}

fn validate_server_settings(settings: &Settings) -> Result<(), AnyError> {
    let Some(revision) = settings.get(SettingKey::ProtocolRevision) else {
        return Err("missing protocol revision".into());
    };
    if revision != 1 {
        return Err(format!("unsupported protocol revision {revision}").into());
    }
    reject_zero_setting(settings, SettingKey::MaxFrameSize, "max_frame_size")?;
    reject_zero_setting(settings, SettingKey::MaxStreams, "max_streams")?;
    reject_boolean_setting(
        settings,
        SettingKey::SupportsUdpDatagram,
        "supports_udp_datagram",
    )?;
    reject_boolean_setting(
        settings,
        SettingKey::SupportsUdpStreamFallback,
        "supports_udp_stream_fallback",
    )?;
    reject_small_setting(
        settings,
        SettingKey::MaxFrameSize,
        "max_frame_size",
        MIN_TCP_RELAY_FRAME_SIZE,
    )?;
    reject_large_setting(
        settings,
        SettingKey::MaxFrameSize,
        "max_frame_size",
        MAX_FRAME_PAYLOAD_SIZE,
    )?;
    Ok(())
}

fn reject_zero_setting(
    settings: &Settings,
    key: SettingKey,
    name: &'static str,
) -> Result<(), AnyError> {
    if settings.get(key) == Some(0) {
        Err(format!("{name} must be greater than zero").into())
    } else {
        Ok(())
    }
}

fn reject_boolean_setting(
    settings: &Settings,
    key: SettingKey,
    name: &'static str,
) -> Result<(), AnyError> {
    if settings.get(key).is_some_and(|value| value > 1) {
        Err(format!("{name} must be 0 or 1").into())
    } else {
        Ok(())
    }
}

fn reject_small_setting(
    settings: &Settings,
    key: SettingKey,
    name: &'static str,
    minimum: u64,
) -> Result<(), AnyError> {
    if settings.get(key).is_some_and(|value| value < minimum) {
        Err(format!("{name} must be at least {minimum}").into())
    } else {
        Ok(())
    }
}

fn reject_large_setting(
    settings: &Settings,
    key: SettingKey,
    name: &'static str,
    maximum: u64,
) -> Result<(), AnyError> {
    if settings.get(key).is_some_and(|value| value > maximum) {
        Err(format!("{name} must be at most {maximum}").into())
    } else {
        Ok(())
    }
}

fn handshake_timeout(seconds: u64) -> Option<Duration> {
    (seconds != 0).then(|| Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings_frame(settings: &Settings) -> Frame {
        let mut payload = BytesMut::new();
        settings.encode(&mut payload).unwrap();
        Frame::new(FrameType::Settings, 0, 0, payload.freeze()).unwrap()
    }

    fn error_frame(code: ErrorCode) -> Frame {
        let mut payload = BytesMut::new();
        ErrorPayload::new(code).encode(&mut payload).unwrap();
        Frame::new(FrameType::Error, 0, 0, payload.freeze()).unwrap()
    }

    #[test]
    fn accepts_supported_protocol_revision() {
        let mut settings = Settings::default();
        settings.set(SettingKey::ProtocolRevision, 1);

        assert!(validate_server_settings(&settings).is_ok());
    }

    #[test]
    fn decodes_server_settings_frame() {
        let mut settings = Settings::default();
        settings.set(SettingKey::ProtocolRevision, 1);
        settings.set(SettingKey::MaxFrameSize, 4096);
        settings.set(SettingKey::MaxStreams, 8);

        assert_eq!(
            decode_server_settings_frame(settings_frame(&settings)).unwrap(),
            settings
        );
    }

    #[test]
    fn maps_auth_failed_error_frame() {
        let error = decode_server_settings_frame(error_frame(ErrorCode::AuthFailed)).unwrap_err();

        assert!(error.to_string().contains("authentication failed"));
    }

    #[test]
    fn rejects_non_auth_handshake_error_frame() {
        let error = decode_server_settings_frame(error_frame(ErrorCode::Protocol)).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("server returned handshake error")
        );
    }

    #[test]
    fn rejects_missing_protocol_revision() {
        let settings = Settings::default();

        assert!(validate_server_settings(&settings).is_err());
    }

    #[test]
    fn rejects_unsupported_protocol_revision() {
        let mut settings = Settings::default();
        settings.set(SettingKey::ProtocolRevision, 2);

        assert!(validate_server_settings(&settings).is_err());
    }

    #[test]
    fn rejects_zero_max_frame_size() {
        let mut settings = Settings::default();
        settings.set(SettingKey::ProtocolRevision, 1);
        settings.set(SettingKey::MaxFrameSize, 0);

        assert!(validate_server_settings(&settings).is_err());
    }

    #[test]
    fn rejects_too_small_max_frame_size() {
        let mut settings = Settings::default();
        settings.set(SettingKey::ProtocolRevision, 1);
        settings.set(SettingKey::MaxFrameSize, MIN_TCP_RELAY_FRAME_SIZE - 1);

        assert!(validate_server_settings(&settings).is_err());
    }

    #[test]
    fn rejects_too_large_max_frame_size() {
        let mut settings = Settings::default();
        settings.set(SettingKey::ProtocolRevision, 1);
        settings.set(SettingKey::MaxFrameSize, MAX_FRAME_PAYLOAD_SIZE + 1);

        assert!(validate_server_settings(&settings).is_err());
    }

    #[test]
    fn rejects_zero_max_streams() {
        let mut settings = Settings::default();
        settings.set(SettingKey::ProtocolRevision, 1);
        settings.set(SettingKey::MaxStreams, 0);

        assert!(validate_server_settings(&settings).is_err());
    }

    #[test]
    fn accepts_boolean_udp_support_settings() {
        let mut settings = Settings::default();
        settings.set(SettingKey::ProtocolRevision, 1);
        settings.set(SettingKey::SupportsUdpDatagram, 0);
        settings.set(SettingKey::SupportsUdpStreamFallback, 1);

        assert!(validate_server_settings(&settings).is_ok());
    }

    #[test]
    fn rejects_non_boolean_udp_support_settings() {
        let mut settings = Settings::default();
        settings.set(SettingKey::ProtocolRevision, 1);
        settings.set(SettingKey::SupportsUdpStreamFallback, 2);

        assert!(validate_server_settings(&settings).is_err());
    }
}
