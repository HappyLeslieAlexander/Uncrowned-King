//! Client-side UK session setup.

use std::{error::Error, fmt, time::Duration};

use bytes::BytesMut;
use rustls::pki_types::ServerName;
use tokio::{net::TcpStream, time};
use tokio_rustls::{TlsConnector, client::TlsStream};
use tracing::{info, warn};
use uk_auth::{AuthChallenge, AuthResponse, unix_now};
use uk_proto::{
    ErrorCode, ErrorPayload, Frame, FrameLimits, FrameType, Settings, read_frame,
    validate_connection_frame, write_frame,
};

use crate::{config::ClientConfig, tls};

type AnyError = Box<dyn Error + Send + Sync>;

#[derive(Debug)]
struct EndpointAttemptError {
    index: usize,
    endpoint: String,
    error: AnyError,
}

#[derive(Debug)]
struct ConnectAttemptsError {
    attempts: Vec<EndpointAttemptError>,
}

impl fmt::Display for ConnectAttemptsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.attempts.is_empty() {
            return formatter.write_str("no server endpoints configured");
        }

        write!(
            formatter,
            "failed to establish authenticated UK session after {} endpoint attempt(s)",
            self.attempts.len()
        )?;
        for attempt in &self.attempts {
            write!(
                formatter,
                "; [{}] {}: {}",
                attempt.index, attempt.endpoint, attempt.error
            )?;
        }
        Ok(())
    }
}

impl Error for ConnectAttemptsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.attempts
            .last()
            .map(|attempt| attempt.error.as_ref() as &(dyn Error + 'static))
    }
}

#[derive(Debug)]
struct HandshakePhaseError {
    phase: &'static str,
    source: AnyError,
}

impl fmt::Display for HandshakePhaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} failed: {}", self.phase, self.source)
    }
}

impl Error for HandshakePhaseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

/// Connects to the configured server and completes UK authentication.
pub async fn connect_authenticated(
    config: &ClientConfig,
) -> Result<(TlsStream<TcpStream>, Settings), AnyError> {
    config.validate_network_endpoints()?;
    config.validate_auth_material()?;
    connect_authenticated_inner(
        config,
        handshake_timeout(config.handshake_timeout_seconds()),
    )
    .await
}

async fn connect_authenticated_inner(
    config: &ClientConfig,
    endpoint_timeout: Option<Duration>,
) -> Result<(TlsStream<TcpStream>, Settings), AnyError> {
    let connector = tls::connector(&config.ca_cert_path)?;
    let server_name = tls::server_name(config.server_name.clone())?;
    let mut attempts = Vec::new();

    for (index, endpoint) in config.server_endpoints().into_iter().enumerate() {
        match connect_authenticated_endpoint_with_timeout(
            config,
            &connector,
            server_name.clone(),
            endpoint,
            endpoint_timeout,
        )
        .await
        {
            Ok(session) => return Ok(session),
            Err(err) => {
                warn!(
                    event = "client.session.connect_endpoint_failed",
                    attempt = index,
                    server_addr = %endpoint,
                    error = %err
                );
                attempts.push(EndpointAttemptError {
                    index,
                    endpoint: endpoint.to_owned(),
                    error: err,
                });
            }
        }
    }

    Err(Box::new(ConnectAttemptsError { attempts }))
}

async fn connect_authenticated_endpoint_with_timeout(
    config: &ClientConfig,
    connector: &TlsConnector,
    server_name: ServerName<'static>,
    endpoint: &str,
    endpoint_timeout: Option<Duration>,
) -> Result<(TlsStream<TcpStream>, Settings), AnyError> {
    if let Some(timeout) = endpoint_timeout {
        match time::timeout(
            timeout,
            connect_authenticated_endpoint(config, connector, server_name, endpoint),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(phase_error(
                "client handshake",
                format!("deadline exceeded for {endpoint} after {timeout:?}"),
            )),
        }
    } else {
        connect_authenticated_endpoint(config, connector, server_name, endpoint).await
    }
}

async fn connect_authenticated_endpoint(
    config: &ClientConfig,
    connector: &TlsConnector,
    server_name: ServerName<'static>,
    endpoint: &str,
) -> Result<(TlsStream<TcpStream>, Settings), AnyError> {
    let tcp = TcpStream::connect(endpoint)
        .await
        .map_err(|err| phase_error("tcp connect", err))?;
    tcp.set_nodelay(true)
        .map_err(|err| phase_error("tcp nodelay", err))?;
    let mut stream = connector
        .connect(server_name, tcp)
        .await
        .map_err(|err| phase_error("tls connect", err))?;
    tls::verify_alpn(&stream).map_err(|err| phase_error("tls alpn verify", err))?;
    let exporter = tls::exporter(&stream).map_err(|err| phase_error("tls exporter", err))?;

    let challenge_frame = read_frame(&mut stream, FrameLimits::default())
        .await
        .map_err(|err| phase_error("read auth challenge", err))?;
    validate_connection_frame(&challenge_frame, FrameType::AuthChallenge)
        .map_err(|err| phase_error("validate auth challenge", err))?;
    let mut challenge_payload = challenge_frame.payload;
    let challenge = AuthChallenge::decode(&mut challenge_payload)
        .map_err(|err| phase_error("decode auth challenge", err))?;

    let response = AuthResponse::for_challenge(
        config.key_id.as_bytes(),
        config.secret.as_bytes(),
        &exporter,
        &challenge,
        unix_now(),
        Vec::new(),
    )
    .map_err(|err| phase_error("build auth response", err))?;
    let mut response_payload = BytesMut::new();
    response
        .encode(&mut response_payload)
        .map_err(|err| phase_error("encode auth response", err))?;
    let response_frame = Frame::new(FrameType::AuthResponse, 0, 0, response_payload.freeze())
        .map_err(|err| phase_error("build auth response frame", err))?;
    write_frame(&mut stream, &response_frame)
        .await
        .map_err(|err| phase_error("write auth response", err))?;

    let settings_frame = read_frame(&mut stream, FrameLimits::default())
        .await
        .map_err(|err| phase_error("read server settings", err))?;
    let settings = decode_server_settings_frame(settings_frame)
        .map_err(|err| phase_error("decode server settings", err))?;
    let negotiated = settings.negotiated_v0_1()?;
    info!(
        event = "auth.success",
        max_frame_size = negotiated.max_frame_size
    );
    Ok((stream, settings))
}

fn decode_server_settings_frame(frame: Frame) -> Result<Settings, AnyError> {
    match frame.header.frame_type {
        FrameType::Settings => {
            validate_connection_frame(&frame, FrameType::Settings)?;
            let mut settings_payload = frame.payload;
            let settings = Settings::decode(&mut settings_payload)?;
            settings.negotiated_v0_1()?;
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

fn phase_error<E>(phase: &'static str, source: E) -> AnyError
where
    E: Into<AnyError>,
{
    Box::new(HandshakePhaseError {
        phase,
        source: source.into(),
    })
}

fn handshake_timeout(seconds: u64) -> Option<Duration> {
    (seconds != 0).then(|| Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;
    use uk_proto::{MAX_FRAME_PAYLOAD_SIZE, MIN_TCP_RELAY_FRAME_SIZE, SettingKey};

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

    fn attempt_error(index: usize, endpoint: &str, error: &str) -> EndpointAttemptError {
        EndpointAttemptError {
            index,
            endpoint: endpoint.to_owned(),
            error: error.to_owned().into(),
        }
    }

    #[test]
    fn accepts_supported_protocol_revision() {
        let mut settings = Settings::default();
        settings.set(SettingKey::ProtocolRevision, 1);

        assert!(settings.negotiated_v0_1().is_ok());
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
    fn endpoint_attempt_error_reports_every_failure() {
        let error = ConnectAttemptsError {
            attempts: vec![
                attempt_error(0, "127.0.0.1:1", "connection refused"),
                attempt_error(1, "127.0.0.1:2", "handshake timeout"),
            ],
        };
        let text = error.to_string();

        assert!(text.contains("2 endpoint attempt"));
        assert!(text.contains("[0] 127.0.0.1:1: connection refused"));
        assert!(text.contains("[1] 127.0.0.1:2: handshake timeout"));
    }

    #[test]
    fn empty_endpoint_attempt_error_reports_no_endpoints() {
        let error = ConnectAttemptsError {
            attempts: Vec::new(),
        };

        assert_eq!(error.to_string(), "no server endpoints configured");
    }

    #[test]
    fn handshake_phase_error_reports_phase_and_source() {
        let error = phase_error("tls connect", "certificate verify failed");

        assert_eq!(
            error.to_string(),
            "tls connect failed: certificate verify failed"
        );
        assert!(error.source().is_some());
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

        assert!(settings.negotiated_v0_1().is_err());
    }

    #[test]
    fn rejects_unsupported_protocol_revision() {
        let mut settings = Settings::default();
        settings.set(SettingKey::ProtocolRevision, 2);

        assert!(settings.negotiated_v0_1().is_err());
    }

    #[test]
    fn rejects_zero_max_frame_size() {
        let mut settings = Settings::default();
        settings.set(SettingKey::ProtocolRevision, 1);
        settings.set(SettingKey::MaxFrameSize, 0);

        assert!(settings.negotiated_v0_1().is_err());
    }

    #[test]
    fn rejects_too_small_max_frame_size() {
        let mut settings = Settings::default();
        settings.set(SettingKey::ProtocolRevision, 1);
        settings.set(SettingKey::MaxFrameSize, MIN_TCP_RELAY_FRAME_SIZE - 1);

        assert!(settings.negotiated_v0_1().is_err());
    }

    #[test]
    fn rejects_too_large_max_frame_size() {
        let mut settings = Settings::default();
        settings.set(SettingKey::ProtocolRevision, 1);
        settings.set(SettingKey::MaxFrameSize, MAX_FRAME_PAYLOAD_SIZE + 1);

        assert!(settings.negotiated_v0_1().is_err());
    }

    #[test]
    fn rejects_zero_max_streams() {
        let mut settings = Settings::default();
        settings.set(SettingKey::ProtocolRevision, 1);
        settings.set(SettingKey::MaxStreams, 0);

        assert!(settings.negotiated_v0_1().is_err());
    }

    #[test]
    fn rejects_udp_flow_limit_above_stream_limit() {
        let mut settings = Settings::default();
        settings.set(SettingKey::ProtocolRevision, 1);
        settings.set(SettingKey::MaxStreams, 8);
        settings.set(SettingKey::MaxUdpFlows, 9);

        let error = settings.negotiated_v0_1().unwrap_err();
        assert!(error.to_string().contains("max_udp_flows"));
    }

    #[test]
    fn rejects_udp_flow_limit_above_default_stream_limit() {
        let mut settings = Settings::default();
        settings.set(SettingKey::ProtocolRevision, 1);
        settings.set(SettingKey::MaxUdpFlows, uk_proto::DEFAULT_MAX_STREAMS + 1);

        let error = settings.negotiated_v0_1().unwrap_err();
        assert!(error.to_string().contains("max_udp_flows"));
    }

    #[test]
    fn accepts_boolean_udp_support_settings() {
        let mut settings = Settings::default();
        settings.set(SettingKey::ProtocolRevision, 1);
        settings.set(SettingKey::SupportsUdpDatagram, 0);
        settings.set(SettingKey::SupportsUdpStreamFallback, 1);

        assert!(settings.negotiated_v0_1().is_ok());
    }

    #[test]
    fn rejects_non_boolean_udp_support_settings() {
        let mut settings = Settings::default();
        settings.set(SettingKey::ProtocolRevision, 1);
        settings.set(SettingKey::SupportsUdpStreamFallback, 2);

        assert!(settings.negotiated_v0_1().is_err());
    }
}
