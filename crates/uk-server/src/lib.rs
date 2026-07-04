//! Uncrowned King server library.

pub mod config;

mod relay;
mod tls;

use std::{future, future::Future, io, sync::Arc, time::Duration};

use bytes::BytesMut;
use tokio::{
    net::TcpListener,
    sync::{Mutex, Semaphore, watch},
    task::JoinSet,
    time,
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tracing::{debug, info, warn};
use uk_auth::{AuthChallenge, AuthResponse, ReplayCache, unix_now, verify_auth_response};
use uk_proto::{
    ErrorCode, ErrorPayload, Frame, FrameIoError, FrameLimits, FrameType, SettingKey, Settings,
    read_frame, validate_connection_frame, write_frame,
};

use crate::config::ServerConfig;

/// Server error type.
pub type AnyError = Box<dyn std::error::Error + Send + Sync>;

/// Runs the UK server listener until the task is cancelled or the listener fails.
pub async fn run(config: ServerConfig) -> Result<(), AnyError> {
    run_until_shutdown(config, future::pending()).await
}

/// Runs the UK server listener until `shutdown` resolves or the listener fails.
pub async fn run_until_shutdown<F>(config: ServerConfig, shutdown: F) -> Result<(), AnyError>
where
    F: Future<Output = ()> + Send,
{
    config.validate_network_endpoints()?;
    config.validate_limits()?;
    let credentials = Arc::new(config.credentials()?);
    let policy_set = Arc::new(config.policy_set()?);
    let replay_cache = Arc::new(Mutex::new(ReplayCache::with_max_entries(
        Duration::from_secs(config.replay_cache_window_seconds()),
        usize_limit(config.replay_cache_max_entries()),
    )));
    let tls_config = tls::server_config(&config.cert_path, &config.key_path)?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let listener = TcpListener::bind(&config.listen).await?;
    let max_sessions = usize_limit(config.max_sessions());
    let session_permits = Arc::new(Semaphore::new(max_sessions));

    info!(event = "server.listen", listen = %config.listen);

    let (shutdown_tx, _shutdown_rx) = watch::channel(false);
    let mut connections = JoinSet::new();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            () = &mut shutdown => {
                info!(event = "server.shutdown");
                let _ = shutdown_tx.send(true);
                break;
            }
            accepted = listener.accept() => {
                let (tcp, peer) = accepted?;
                let Ok(session_permit) = Arc::clone(&session_permits).try_acquire_owned() else {
                    warn!(event = "server.session.limit", peer = %peer, max_sessions);
                    continue;
                };
                let acceptor = acceptor.clone();
                let credentials = Arc::clone(&credentials);
                let policy_set = Arc::clone(&policy_set);
                let replay_cache = Arc::clone(&replay_cache);
                let config = config.clone();
                let shutdown_rx = shutdown_tx.subscribe();

                connections.spawn(async move {
                    let _session_permit = session_permit;
                    if let Err(err) =
                        handle_connection(
                            acceptor,
                            tcp,
                            credentials,
                            policy_set,
                            replay_cache,
                            config,
                            shutdown_rx,
                        )
                        .await
                    {
                        if is_clean_tls_handshake_disconnect(&err) {
                            debug!(event = "tls.handshake.closed", peer = %peer);
                        } else {
                            warn!(event = "protocol.error", peer = %peer, error = %err);
                        }
                    }
                });
            }
            joined = connections.join_next(), if !connections.is_empty() => {
                log_connection_task_result(joined);
            }
        }
    }

    while let Some(joined) = connections.join_next().await {
        log_connection_task_result(Some(joined));
    }

    Ok(())
}

fn log_connection_task_result(result: Option<Result<(), tokio::task::JoinError>>) {
    if let Some(Err(err)) = result {
        warn!(event = "server.connection.task_error", error = %err);
    }
}

async fn handle_connection(
    acceptor: TlsAcceptor,
    tcp: tokio::net::TcpStream,
    credentials: Arc<Vec<uk_auth::Credential>>,
    policy_set: Arc<uk_policy::PolicySet>,
    replay_cache: Arc<Mutex<ReplayCache>>,
    config: ServerConfig,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), AnyError> {
    tcp.set_nodelay(true)?;
    if *shutdown_rx.borrow() {
        return Ok(());
    }

    let handshake = async {
        if let Some(timeout) = handshake_timeout(config.handshake_timeout_seconds()) {
            match time::timeout(
                timeout,
                complete_handshake(acceptor, tcp, credentials, replay_cache, &config),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => Err("handshake timeout".into()),
            }
        } else {
            complete_handshake(acceptor, tcp, credentials, replay_cache, &config).await
        }
    };

    let (stream, credential) = tokio::select! {
        result = handshake => result?,
        changed = shutdown_rx.changed() => {
            let _ = changed;
            return Ok(());
        }
    };
    if *shutdown_rx.borrow() {
        return Ok(());
    }

    relay::relay_session(
        stream,
        credential,
        policy_set,
        relay::RelayLimits::new(
            FrameLimits {
                max_frame_size: config.max_frame_size(),
            },
            config.max_streams(),
            usize_limit(config.max_outbound_dials_per_session()),
            usize_limit(config.max_buffered_bytes_per_session()),
            usize_limit(config.max_buffered_bytes_per_flow()),
            target_connect_timeout(config.target_connect_timeout_seconds()),
            tcp_half_close_timeout(config.tcp_half_close_timeout_seconds()),
        ),
        idle_timeout(config.idle_timeout_seconds()),
        shutdown_rx,
    )
    .await
}

/// Validates server config, credentials, policy, and TLS material.
pub fn check_config(config: &ServerConfig) -> Result<(), AnyError> {
    config.validate_network_endpoints()?;
    config.validate_limits()?;
    let _credentials = config.credentials()?;
    let _policy_set = config.policy_set()?;
    let _tls_config = tls::server_config(&config.cert_path, &config.key_path)?;
    Ok(())
}

async fn complete_handshake(
    acceptor: TlsAcceptor,
    tcp: tokio::net::TcpStream,
    credentials: Arc<Vec<uk_auth::Credential>>,
    replay_cache: Arc<Mutex<ReplayCache>>,
    config: &ServerConfig,
) -> Result<(TlsStream<tokio::net::TcpStream>, uk_auth::Credential), AnyError> {
    let mut stream = acceptor.accept(tcp).await?;
    tls::verify_alpn(&stream)?;
    let exporter = tls::exporter(&stream)?;
    let challenge = AuthChallenge::generate(unix_now());

    let mut payload = BytesMut::new();
    challenge.encode(&mut payload)?;
    let challenge_frame = Frame::new(FrameType::AuthChallenge, 0, 0, payload.freeze())?;
    write_frame(&mut stream, &challenge_frame).await?;

    let response_frame = match read_frame(
        &mut stream,
        FrameLimits {
            max_frame_size: config.max_pre_auth_bytes(),
        },
    )
    .await
    {
        Ok(frame) => frame,
        Err(err) => {
            report_handshake_frame_io_error(&mut stream, &err).await;
            return Err(err.into());
        }
    };

    if let Err(err) = validate_connection_frame(&response_frame, FrameType::AuthResponse) {
        let _ = write_connection_error(&mut stream, ErrorCode::Protocol).await;
        return Err(err.into());
    }

    let mut response_payload = response_frame.payload;
    let response = match AuthResponse::decode(&mut response_payload) {
        Ok(response) => response,
        Err(err) => {
            let _ = write_connection_error(&mut stream, ErrorCode::AuthFailed).await;
            return Err(err.into());
        }
    };
    let now = unix_now();
    let verification = {
        let mut replay_cache = replay_cache.lock().await;
        verify_auth_response(
            &credentials,
            &exporter,
            &challenge,
            &response,
            now,
            Duration::from_secs(config.auth_skew_seconds.unwrap_or(30)),
            &mut replay_cache,
        )
    };
    let credential = match verification {
        Ok(credential) => credential,
        Err(err) => {
            let _ = write_connection_error(&mut stream, ErrorCode::AuthFailed).await;
            return Err(err.into());
        }
    };

    info!(
        event = "auth.success",
        key_id = %String::from_utf8_lossy(&credential.key_id)
    );

    let settings = server_settings(config);
    let mut settings_payload = BytesMut::new();
    settings.encode(&mut settings_payload)?;
    let settings_frame = Frame::new(FrameType::Settings, 0, 0, settings_payload.freeze())?;
    write_frame(&mut stream, &settings_frame).await?;

    Ok((stream, credential))
}

async fn write_connection_error(
    stream: &mut TlsStream<tokio::net::TcpStream>,
    code: ErrorCode,
) -> Result<(), AnyError> {
    let frame = connection_error_frame(code)?;
    write_frame(stream, &frame).await?;
    Ok(())
}

async fn report_handshake_frame_io_error(
    stream: &mut TlsStream<tokio::net::TcpStream>,
    error: &FrameIoError,
) {
    if let FrameIoError::Protocol(error) = error {
        let _ = write_connection_error(stream, ErrorCode::from_protocol_error(error)).await;
    }
}

fn connection_error_frame(code: ErrorCode) -> Result<Frame, AnyError> {
    let mut payload = BytesMut::new();
    ErrorPayload::new(code).encode(&mut payload)?;
    Ok(Frame::new(FrameType::Error, 0, 0, payload.freeze())?)
}

fn server_settings(config: &ServerConfig) -> Settings {
    let mut settings = Settings::default();
    settings.set(SettingKey::ProtocolRevision, 1);
    settings.set(SettingKey::MaxFrameSize, config.max_frame_size());
    settings.set(SettingKey::MaxStreams, config.max_streams());
    settings.set(
        SettingKey::IdleTimeoutSeconds,
        config.idle_timeout_seconds(),
    );
    settings
}

fn idle_timeout(seconds: u64) -> Option<Duration> {
    (seconds != 0).then(|| Duration::from_secs(seconds))
}

fn handshake_timeout(seconds: u64) -> Option<Duration> {
    (seconds != 0).then(|| Duration::from_secs(seconds))
}

fn target_connect_timeout(seconds: u64) -> Option<Duration> {
    (seconds != 0).then(|| Duration::from_secs(seconds))
}

fn tcp_half_close_timeout(seconds: u64) -> Option<Duration> {
    (seconds != 0).then(|| Duration::from_secs(seconds))
}

fn is_clean_tls_handshake_disconnect(error: &AnyError) -> bool {
    error
        .as_ref()
        .downcast_ref::<io::Error>()
        .is_some_and(|error| {
            matches!(
                error.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::NotConnected
            ) || is_tls_handshake_eof(error)
        })
        || error.to_string() == "tls handshake eof"
}

fn is_tls_handshake_eof(error: &io::Error) -> bool {
    error.to_string() == "tls handshake eof"
}

fn usize_limit(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CredentialConfig, LimitConfig};

    fn minimal_config() -> ServerConfig {
        ServerConfig {
            listen: "127.0.0.1:1".to_owned(),
            cert_path: "cert.pem".to_owned(),
            key_path: "key.pem".to_owned(),
            auth_skew_seconds: None,
            limits: None,
            policy_path: None,
            credentials: vec![CredentialConfig {
                key_id: "client".to_owned(),
                secret: "0123456789abcdef0123456789abcdef".to_owned(),
                status: Some("active".to_owned()),
                not_before: None,
                not_after: None,
                policy_group: None,
            }],
        }
    }

    #[test]
    fn server_settings_include_protocol_and_limits() {
        let mut config = minimal_config();
        config.limits = Some(LimitConfig {
            max_pre_auth_bytes: None,
            max_frame_size: Some(32_768),
            max_sessions: None,
            max_streams: Some(17),
            max_outbound_dials_per_session: None,
            max_buffered_bytes_per_session: None,
            idle_timeout_seconds: Some(42),
            max_buffered_bytes_per_flow: None,
            handshake_timeout_seconds: None,
            target_connect_timeout_seconds: None,
            tcp_half_close_timeout_seconds: None,
            replay_cache_window_seconds: None,
            replay_cache_max_entries: None,
        });

        let settings = server_settings(&config);

        assert_eq!(settings.get(SettingKey::ProtocolRevision), Some(1));
        assert_eq!(settings.get(SettingKey::MaxFrameSize), Some(32_768));
        assert_eq!(settings.get(SettingKey::MaxStreams), Some(17));
        assert_eq!(settings.get(SettingKey::IdleTimeoutSeconds), Some(42));
    }

    #[test]
    fn connection_error_frame_encodes_error_code() {
        let frame = connection_error_frame(ErrorCode::AuthFailed).unwrap();

        assert_eq!(frame.header.frame_type, FrameType::Error);
        assert_eq!(frame.header.id, 0);
        let mut payload = frame.payload;
        assert_eq!(
            ErrorPayload::decode(&mut payload).unwrap().code,
            ErrorCode::AuthFailed
        );
    }

    #[test]
    fn classifies_clean_tls_handshake_disconnects() {
        let unexpected_eof: AnyError =
            io::Error::new(io::ErrorKind::UnexpectedEof, "client closed").into();
        let connection_reset: AnyError =
            io::Error::new(io::ErrorKind::ConnectionReset, "client reset").into();
        let broken_pipe: AnyError =
            io::Error::new(io::ErrorKind::BrokenPipe, "client pipe closed").into();
        let not_connected: AnyError =
            io::Error::new(io::ErrorKind::NotConnected, "client gone").into();
        let rustls_eof: AnyError =
            io::Error::new(io::ErrorKind::InvalidData, "tls handshake eof").into();
        let protocol_error: AnyError =
            io::Error::new(io::ErrorKind::InvalidData, "invalid certificate").into();

        assert!(is_clean_tls_handshake_disconnect(&unexpected_eof));
        assert!(is_clean_tls_handshake_disconnect(&connection_reset));
        assert!(is_clean_tls_handshake_disconnect(&broken_pipe));
        assert!(is_clean_tls_handshake_disconnect(&not_connected));
        assert!(is_clean_tls_handshake_disconnect(&rustls_eof));
        assert!(!is_clean_tls_handshake_disconnect(&protocol_error));
    }
}
