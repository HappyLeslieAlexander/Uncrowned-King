//! Uncrowned King server library.

pub mod config;

mod relay;
mod tls;

use std::{sync::Arc, time::Duration};

use bytes::BytesMut;
use tokio::{net::TcpListener, sync::Mutex, time};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tracing::{info, warn};
use uk_auth::{AuthChallenge, AuthResponse, ReplayCache, unix_now, verify_auth_response};
use uk_proto::{
    Frame, FrameLimits, FrameType, SettingKey, Settings, read_frame, validate_connection_frame,
    write_frame,
};

use crate::config::ServerConfig;

/// Server error type.
pub type AnyError = Box<dyn std::error::Error + Send + Sync>;

/// Runs the UK server listener until the task is cancelled or the listener fails.
pub async fn run(config: ServerConfig) -> Result<(), AnyError> {
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

    info!(event = "server.listen", listen = %config.listen);

    loop {
        let (tcp, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let credentials = Arc::clone(&credentials);
        let policy_set = Arc::clone(&policy_set);
        let replay_cache = Arc::clone(&replay_cache);
        let config = config.clone();

        tokio::spawn(async move {
            if let Err(err) =
                handle_connection(acceptor, tcp, credentials, policy_set, replay_cache, config)
                    .await
            {
                warn!(event = "protocol.error", peer = %peer, error = %err);
            }
        });
    }
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

async fn handle_connection(
    acceptor: TlsAcceptor,
    tcp: tokio::net::TcpStream,
    credentials: Arc<Vec<uk_auth::Credential>>,
    policy_set: Arc<uk_policy::PolicySet>,
    replay_cache: Arc<Mutex<ReplayCache>>,
    config: ServerConfig,
) -> Result<(), AnyError> {
    let (stream, credential) =
        if let Some(timeout) = handshake_timeout(config.handshake_timeout_seconds()) {
            match time::timeout(
                timeout,
                complete_handshake(acceptor, tcp, credentials, replay_cache, &config),
            )
            .await
            {
                Ok(result) => result?,
                Err(_) => return Err("handshake timeout".into()),
            }
        } else {
            complete_handshake(acceptor, tcp, credentials, replay_cache, &config).await?
        };

    relay::relay_session(
        stream,
        credential,
        policy_set,
        relay::RelayLimits::new(
            FrameLimits {
                max_frame_size: config.max_frame_size(),
            },
            config.max_streams(),
            usize_limit(config.max_buffered_bytes_per_flow()),
            target_connect_timeout(config.target_connect_timeout_seconds()),
            tcp_half_close_timeout(config.tcp_half_close_timeout_seconds()),
        ),
        idle_timeout(config.idle_timeout_seconds()),
    )
    .await
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

    let response_frame = read_frame(
        &mut stream,
        FrameLimits {
            max_frame_size: config.max_pre_auth_bytes(),
        },
    )
    .await?;

    validate_connection_frame(&response_frame, FrameType::AuthResponse)?;

    let mut response_payload = response_frame.payload;
    let response = AuthResponse::decode(&mut response_payload)?;
    let now = unix_now();
    let credential = {
        let mut replay_cache = replay_cache.lock().await;
        verify_auth_response(
            &credentials,
            &exporter,
            &challenge,
            &response,
            now,
            Duration::from_secs(config.auth_skew_seconds.unwrap_or(30)),
            &mut replay_cache,
        )?
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
            max_streams: Some(17),
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
}
