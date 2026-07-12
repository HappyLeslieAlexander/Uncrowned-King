//! Uncrowned King server library.

pub mod config;

mod relay;
mod tls;

use std::{
    error::Error,
    fmt, future,
    future::Future,
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use bytes::BytesMut;
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    sync::{Mutex, OwnedSemaphorePermit, Semaphore, watch},
    task::JoinSet,
    time,
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tracing::{Instrument, debug, info, info_span, warn};
use uk_auth::{
    AuthChallenge, AuthResponse, AuthenticatedIdentity, ReplayCache, unix_now,
    verify_auth_response_identity,
};
use uk_proto::{
    ErrorCode, ErrorPayload, Frame, FrameIoError, FrameLimits, FrameType, SettingKey, Settings,
    read_frame, validate_connection_frame, write_frame,
};
use zeroize::Zeroize;

use crate::config::ServerConfig;

/// Server error type.
pub type AnyError = Box<dyn Error + Send + Sync>;

const ACCEPT_RETRY_BASE_MILLIS: u64 = 10;
const ACCEPT_RETRY_MAX_MILLIS: u64 = 1_000;
static NEXT_CONNECTION_CORRELATION_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Default)]
struct ListenerAcceptBackoff {
    consecutive_failures: u32,
}

impl ListenerAcceptBackoff {
    fn next_delay(&mut self) -> Duration {
        let shift = self.consecutive_failures.min(7);
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        Duration::from_millis(
            ACCEPT_RETRY_BASE_MILLIS
                .saturating_mul(1_u64 << shift)
                .min(ACCEPT_RETRY_MAX_MILLIS),
        )
    }

    fn reset(&mut self) {
        self.consecutive_failures = 0;
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

struct ServerRuntime {
    config: Arc<ServerConfig>,
    credentials: Arc<Vec<uk_auth::Credential>>,
    policy_set: Arc<uk_policy::PolicySet>,
    replay_cache: Arc<Mutex<ReplayCache>>,
    acceptor: TlsAcceptor,
    max_sessions: usize,
    max_handshakes: usize,
}

#[derive(Clone)]
struct ConnectionRuntime {
    acceptor: TlsAcceptor,
    credentials: Arc<Vec<uk_auth::Credential>>,
    policy_set: Arc<uk_policy::PolicySet>,
    replay_cache: Arc<Mutex<ReplayCache>>,
    session_permits: Arc<Semaphore>,
    config: Arc<ServerConfig>,
    max_sessions: usize,
}

/// Runs the UK server listener until the task is cancelled or the listener fails.
pub async fn run(config: ServerConfig) -> Result<(), AnyError> {
    run_until_shutdown(config, future::pending()).await
}

/// Runs the UK server listener until `shutdown` resolves or the listener fails.
pub async fn run_until_shutdown<F>(config: ServerConfig, shutdown: F) -> Result<(), AnyError>
where
    F: Future<Output = ()> + Send,
{
    let runtime = prepare_server_runtime(config)?;
    let listener = TcpListener::bind(&runtime.config.listen).await?;
    run_on_listener_inner(runtime, listener, shutdown).await
}

/// Runs the UK server on an already-bound listener until the task is cancelled or the listener fails.
pub async fn run_on_listener(config: ServerConfig, listener: TcpListener) -> Result<(), AnyError> {
    run_on_listener_until_shutdown(config, listener, future::pending()).await
}

/// Runs the UK server on an already-bound listener until `shutdown` resolves or the listener fails.
pub async fn run_on_listener_until_shutdown<F>(
    mut config: ServerConfig,
    listener: TcpListener,
    shutdown: F,
) -> Result<(), AnyError>
where
    F: Future<Output = ()> + Send,
{
    config.listen = listener.local_addr()?.to_string();
    let runtime = prepare_server_runtime(config)?;
    run_on_listener_inner(runtime, listener, shutdown).await
}

async fn run_on_listener_inner<F>(
    runtime: ServerRuntime,
    listener: TcpListener,
    shutdown: F,
) -> Result<(), AnyError>
where
    F: Future<Output = ()> + Send,
{
    let ServerRuntime {
        config,
        credentials,
        policy_set,
        replay_cache,
        acceptor,
        max_sessions,
        max_handshakes,
    } = runtime;
    let listen = listener.local_addr()?;
    let session_permits = Arc::new(Semaphore::new(max_sessions));
    let handshake_permits = Arc::new(Semaphore::new(max_handshakes));
    let shutdown_timeout = listener_shutdown_timeout(config.shutdown_timeout_seconds());

    info!(event = "server.listen", listen = %listen);

    let (shutdown_tx, _shutdown_rx) = watch::channel(false);
    let mut connections = JoinSet::new();
    let mut accept_backoff = ListenerAcceptBackoff::default();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            () = &mut shutdown => {
                info!(event = "server.shutdown");
                let _ = shutdown_tx.send(true);
                break;
            }
            accepted = listener.accept() => {
                let (mut tcp, peer) = match accepted {
                    Ok(connection) => {
                        accept_backoff.reset();
                        connection
                    }
                    Err(err) => {
                        let retry_delay = accept_backoff.next_delay();
                        warn!(
                            event = "server.accept.error",
                            error = %err,
                            retry_delay_ms = retry_delay.as_millis()
                        );
                        time::sleep(retry_delay).await;
                        continue;
                    }
                };
                let Ok(handshake_permit) = Arc::clone(&handshake_permits).try_acquire_owned() else {
                    warn!(event = "server.handshake.limit", peer = %peer, max_handshakes);
                    if let Err(err) = tcp.shutdown().await {
                        debug!(
                            event = "server.handshake.limit_shutdown_error",
                            peer = %peer,
                            error = %err
                        );
                    }
                    continue;
                };
                let connection_runtime = ConnectionRuntime {
                    acceptor: acceptor.clone(),
                    credentials: Arc::clone(&credentials),
                    policy_set: Arc::clone(&policy_set),
                    replay_cache: Arc::clone(&replay_cache),
                    session_permits: Arc::clone(&session_permits),
                    config: Arc::clone(&config),
                    max_sessions,
                };
                let shutdown_rx = shutdown_tx.subscribe();
                let connection_id =
                    NEXT_CONNECTION_CORRELATION_ID.fetch_add(1, Ordering::Relaxed);

                let connection = async move {
                    if let Err(err) =
                        handle_connection(connection_runtime, tcp, handshake_permit, peer, shutdown_rx)
                            .await
                    {
                        if is_clean_tls_handshake_disconnect(&err) {
                            debug!(event = "tls.handshake.closed", peer = %peer);
                        } else {
                            warn!(event = "protocol.error", peer = %peer, error = %err);
                        }
                    }
                };
                connections.spawn(connection.instrument(info_span!(
                    "server.connection",
                    connection_id,
                    peer = %peer
                )));
            }
            joined = connections.join_next(), if !connections.is_empty() => {
                log_connection_task_result(joined);
            }
        }
    }

    drain_connection_tasks(&mut connections, shutdown_timeout).await;

    Ok(())
}

fn prepare_server_runtime(mut config: ServerConfig) -> Result<ServerRuntime, AnyError> {
    config.validate_network_endpoints()?;
    config.validate_limits()?;
    config.validate_sensitive_paths()?;
    let credentials = Arc::new(take_runtime_credentials(&mut config)?);
    let policy_set = Arc::new(config.policy_set()?);
    let replay_cache = Arc::new(Mutex::new(ReplayCache::with_max_entries(
        Duration::from_secs(config.replay_cache_window_seconds()),
        usize_limit(
            "replay_cache_max_entries",
            config.replay_cache_max_entries(),
        )?,
    )));
    let tls_config = tls::server_config(&config.cert_path, &config.key_path)?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let max_sessions = usize_limit("max_sessions", config.max_sessions())?;
    let max_handshakes = usize_limit("max_handshakes", config.max_handshakes())?;

    Ok(ServerRuntime {
        config: Arc::new(config),
        credentials,
        policy_set,
        replay_cache,
        acceptor,
        max_sessions,
        max_handshakes,
    })
}

fn take_runtime_credentials(
    config: &mut ServerConfig,
) -> Result<Vec<uk_auth::Credential>, uk_auth::AuthError> {
    let credentials = config.credentials();
    for credential in &mut config.credentials {
        credential.secret.zeroize();
    }
    config.credentials.clear();
    credentials
}

fn log_connection_task_result(result: Option<Result<(), tokio::task::JoinError>>) {
    if let Some(Err(err)) = result {
        warn!(event = "server.connection.task_error", error = %err);
    }
}

async fn drain_connection_tasks(connections: &mut JoinSet<()>, shutdown_timeout: Option<Duration>) {
    if let Some(timeout) = shutdown_timeout {
        if time::timeout(timeout, join_connection_tasks(connections))
            .await
            .is_err()
        {
            warn!(
                event = "server.shutdown.timeout",
                remaining_connections = connections.len(),
                timeout_seconds = timeout.as_secs()
            );
            connections.abort_all();
            join_connection_tasks(connections).await;
        }
    } else {
        join_connection_tasks(connections).await;
    }
}

async fn join_connection_tasks(connections: &mut JoinSet<()>) {
    while let Some(joined) = connections.join_next().await {
        log_connection_task_result(Some(joined));
    }
}

async fn handle_connection(
    runtime: ConnectionRuntime,
    tcp: tokio::net::TcpStream,
    handshake_permit: OwnedSemaphorePermit,
    peer: SocketAddr,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), AnyError> {
    let ConnectionRuntime {
        acceptor,
        credentials,
        policy_set,
        replay_cache,
        session_permits,
        config,
        max_sessions,
    } = runtime;
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

    let (mut stream, identity) = tokio::select! {
        result = handshake => result?,
        changed = shutdown_rx.changed() => {
            let _ = changed;
            return Ok(());
        }
    };
    drop(handshake_permit);
    if *shutdown_rx.borrow() {
        return Ok(());
    }

    let Ok(session_permit) = session_permits.try_acquire_owned() else {
        warn!(event = "server.session.limit", peer = %peer, max_sessions);
        let _ = write_connection_error(&mut stream, ErrorCode::ResourceLimit).await;
        let _ = stream.shutdown().await;
        return Err("authenticated session limit exceeded".into());
    };
    let _session_permit = session_permit;

    write_server_settings(&mut stream, &config).await?;

    relay::relay_session(
        stream,
        identity,
        policy_set,
        relay::RelayLimits::new(relay::RelayLimitConfig {
            frame: FrameLimits {
                max_frame_size: config.max_frame_size(),
            },
            max_streams: config.max_streams(),
            max_udp_flows: config.max_udp_flows(),
            max_outbound_dials_per_session: usize_limit(
                "max_outbound_dials_per_session",
                config.max_outbound_dials_per_session(),
            )?,
            max_buffered_bytes_per_session: usize_limit(
                "max_buffered_bytes_per_session",
                config.max_buffered_bytes_per_session(),
            )?,
            max_buffered_bytes_per_flow: usize_limit(
                "max_buffered_bytes_per_flow",
                config.max_buffered_bytes_per_flow(),
            )?,
            target_connect_timeout: target_connect_timeout(config.target_connect_timeout_seconds()),
            tcp_half_close_timeout: tcp_half_close_timeout(config.tcp_half_close_timeout_seconds()),
            udp_flow_idle_timeout: udp_flow_idle_timeout(config.udp_flow_idle_timeout_seconds()),
            session_task_shutdown_timeout: listener_shutdown_timeout(
                config.shutdown_timeout_seconds(),
            ),
        }),
        idle_timeout(config.idle_timeout_seconds()),
        shutdown_rx,
    )
    .await
}

/// Validates server config, credentials, policy, and TLS material.
pub fn check_config(config: &ServerConfig) -> Result<(), AnyError> {
    config.validate_network_endpoints()?;
    config.validate_limits()?;
    config.validate_sensitive_paths()?;
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
) -> Result<(TlsStream<tokio::net::TcpStream>, AuthenticatedIdentity), AnyError> {
    let mut stream = acceptor
        .accept(tcp)
        .await
        .map_err(|err| phase_error("tls accept", err))?;
    tls::verify_alpn(&stream).map_err(|err| phase_error("tls alpn verify", err))?;
    let exporter = tls::exporter(&stream).map_err(|err| phase_error("tls exporter", err))?;
    let challenge = AuthChallenge::generate(unix_now());

    let mut payload = BytesMut::new();
    challenge
        .encode(&mut payload)
        .map_err(|err| phase_error("encode auth challenge", err))?;
    let challenge_frame = Frame::new(FrameType::AuthChallenge, 0, 0, payload.freeze())
        .map_err(|err| phase_error("build auth challenge frame", err))?;
    write_frame(&mut stream, &challenge_frame)
        .await
        .map_err(|err| phase_error("write auth challenge", err))?;

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
            return Err(phase_error("read auth response", err));
        }
    };

    if let Err(err) = validate_connection_frame(&response_frame, FrameType::AuthResponse) {
        let _ = write_connection_error(&mut stream, ErrorCode::Protocol).await;
        return Err(phase_error("validate auth response", err));
    }

    let mut response_payload = response_frame.payload;
    let response = match AuthResponse::decode(&mut response_payload) {
        Ok(response) => response,
        Err(err) => {
            let _ = write_connection_error(&mut stream, ErrorCode::AuthFailed).await;
            return Err(phase_error("decode auth response", err));
        }
    };
    let now = unix_now();
    let verification = {
        let mut replay_cache = replay_cache.lock().await;
        verify_auth_response_identity(
            &credentials,
            &exporter,
            &challenge,
            &response,
            now,
            Duration::from_secs(config.auth_skew_seconds()),
            &mut replay_cache,
        )
    };
    let identity = match verification {
        Ok(identity) => identity,
        Err(err) => {
            let _ = write_connection_error(&mut stream, ErrorCode::AuthFailed).await;
            return Err(phase_error("verify auth response", err));
        }
    };

    info!(
        event = "auth.success",
        key_id_hex = %hex_encode(&identity.key_id)
    );

    Ok((stream, identity))
}

async fn write_server_settings(
    stream: &mut TlsStream<tokio::net::TcpStream>,
    config: &ServerConfig,
) -> Result<(), AnyError> {
    let settings = server_settings(config);
    let mut settings_payload = BytesMut::new();
    settings
        .encode(&mut settings_payload)
        .map_err(|err| phase_error("encode server settings", err))?;
    let settings_frame = Frame::new(FrameType::Settings, 0, 0, settings_payload.freeze())
        .map_err(|err| phase_error("build server settings frame", err))?;
    write_frame(stream, &settings_frame)
        .await
        .map_err(|err| phase_error("write server settings", err))?;
    Ok(())
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
    settings.set(SettingKey::MaxUdpFlows, config.max_udp_flows());
    settings.set(SettingKey::SupportsUdpDatagram, 0);
    settings.set(
        SettingKey::SupportsUdpStreamFallback,
        u64::from(config.max_udp_flows() != 0),
    );
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

fn udp_flow_idle_timeout(seconds: u64) -> Option<Duration> {
    (seconds != 0).then(|| Duration::from_secs(seconds))
}

fn listener_shutdown_timeout(seconds: u64) -> Option<Duration> {
    (seconds != 0).then(|| Duration::from_secs(seconds))
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

fn is_clean_tls_handshake_disconnect(error: &AnyError) -> bool {
    find_io_error(error.as_ref()).is_some_and(|error| {
        matches!(
            error.kind(),
            io::ErrorKind::UnexpectedEof
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::BrokenPipe
                | io::ErrorKind::NotConnected
        ) || is_tls_handshake_eof(error)
    }) || error.to_string() == "tls handshake eof"
}

fn find_io_error<'a>(error: &'a (dyn Error + 'static)) -> Option<&'a io::Error> {
    let mut current = Some(error);
    while let Some(error) = current {
        if let Some(error) = error.downcast_ref::<io::Error>() {
            return Some(error);
        }
        current = error.source();
    }
    None
}

fn is_tls_handshake_eof(error: &io::Error) -> bool {
    error.to_string() == "tls handshake eof"
}

fn usize_limit(name: &str, value: u64) -> Result<usize, AnyError> {
    usize::try_from(value).map_err(|_| format!("{name} is too large for this platform").into())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
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
            max_frame_size: Some(32_768),
            max_streams: Some(17),
            max_udp_flows: Some(11),
            idle_timeout_seconds: Some(42),
            ..LimitConfig::default()
        });

        let settings = server_settings(&config);

        assert_eq!(settings.get(SettingKey::ProtocolRevision), Some(1));
        assert_eq!(settings.get(SettingKey::MaxFrameSize), Some(32_768));
        assert_eq!(settings.get(SettingKey::MaxStreams), Some(17));
        assert_eq!(settings.get(SettingKey::MaxUdpFlows), Some(11));
        assert_eq!(settings.get(SettingKey::SupportsUdpDatagram), Some(0));
        assert_eq!(settings.get(SettingKey::SupportsUdpStreamFallback), Some(1));
        assert_eq!(settings.get(SettingKey::IdleTimeoutSeconds), Some(42));
    }

    #[test]
    fn runtime_credentials_remove_secrets_from_server_config() {
        let mut config = minimal_config();

        let credentials = take_runtime_credentials(&mut config).unwrap();

        assert_eq!(credentials.len(), 1);
        assert_eq!(credentials[0].key_id, b"client");
        assert!(config.credentials.is_empty());
    }

    #[test]
    fn invalid_runtime_credentials_still_clear_server_config_secrets() {
        let mut config = minimal_config();
        config.credentials[0].secret = "too-short".to_owned();

        assert_eq!(
            take_runtime_credentials(&mut config),
            Err(uk_auth::AuthError::SecretTooShort)
        );
        assert!(config.credentials.is_empty());
    }

    #[test]
    fn server_settings_disable_udp_stream_fallback_without_udp_flows() {
        let mut config = minimal_config();
        config.limits = Some(LimitConfig {
            max_udp_flows: Some(0),
            ..LimitConfig::default()
        });

        let settings = server_settings(&config);

        assert_eq!(settings.get(SettingKey::MaxUdpFlows), Some(0));
        assert_eq!(settings.get(SettingKey::SupportsUdpStreamFallback), Some(0));
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
    fn hex_encode_keeps_opaque_key_ids_log_safe() {
        assert_eq!(hex_encode(b"client"), "636c69656e74");
        assert_eq!(hex_encode(&[0x00, 0x1f, 0x7f, 0x80, 0xff]), "001f7f80ff");
    }

    #[test]
    fn listener_accept_backoff_grows_caps_and_resets() {
        let mut backoff = ListenerAcceptBackoff::default();

        assert_eq!(backoff.next_delay(), Duration::from_millis(10));
        assert_eq!(backoff.next_delay(), Duration::from_millis(20));
        assert_eq!(backoff.next_delay(), Duration::from_millis(40));
        for _ in 0..16 {
            let delay = backoff.next_delay();
            assert!(delay <= Duration::from_secs(1));
        }
        assert_eq!(backoff.next_delay(), Duration::from_secs(1));

        backoff.reset();
        assert_eq!(backoff.next_delay(), Duration::from_millis(10));
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

    #[test]
    fn handshake_phase_error_reports_phase_and_source() {
        let error = phase_error("tls accept", "client closed");

        assert_eq!(error.to_string(), "tls accept failed: client closed");
        assert!(error.source().is_some());
    }

    #[test]
    fn classifies_clean_disconnects_through_handshake_phase_error() {
        let error = phase_error(
            "tls accept",
            io::Error::new(io::ErrorKind::UnexpectedEof, "client closed"),
        );

        assert!(is_clean_tls_handshake_disconnect(&error));
    }

    #[tokio::test]
    async fn server_shutdown_timeout_aborts_pending_connection_tasks() {
        let mut connections = JoinSet::new();
        connections.spawn(std::future::pending::<()>());

        tokio::time::timeout(
            Duration::from_secs(1),
            drain_connection_tasks(&mut connections, Some(Duration::from_millis(10))),
        )
        .await
        .unwrap();

        assert!(connections.is_empty());
    }

    #[tokio::test]
    async fn server_shutdown_drain_waits_for_completed_connection_tasks() {
        let mut connections = JoinSet::new();
        connections.spawn(async {});

        drain_connection_tasks(&mut connections, Some(Duration::from_secs(1))).await;

        assert!(connections.is_empty());
    }
}
