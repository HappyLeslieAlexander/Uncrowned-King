//! UncrownedKing server binary.

mod config;
mod relay;
mod tls;

use std::{sync::Arc, time::Duration};

use bytes::BytesMut;
use clap::Parser;
use tokio::{net::TcpListener, sync::Mutex};
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};
use uk_auth::{AuthChallenge, AuthResponse, ReplayCache, unix_now, verify_auth_response};
use uk_proto::{Frame, FrameLimits, FrameType, SettingKey, Settings, read_frame, write_frame};

use crate::config::ServerConfig;

/// UK server command line.
#[derive(Debug, Parser)]
#[command(name = "uk-server", about = "UncrownedKing server")]
struct Args {
    /// Path to server TOML config.
    #[arg(long)]
    config: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let config = ServerConfig::load(&args.config)?;
    run(config).await
}

async fn run(config: ServerConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let credentials = Arc::new(config.credentials()?);
    let policy_set = Arc::new(config.policy_set()?);
    let replay_cache = Arc::new(Mutex::new(ReplayCache::default()));
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

async fn handle_connection(
    acceptor: TlsAcceptor,
    tcp: tokio::net::TcpStream,
    credentials: Arc<Vec<uk_auth::Credential>>,
    policy_set: Arc<uk_policy::PolicySet>,
    replay_cache: Arc<Mutex<ReplayCache>>,
    config: ServerConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut stream = acceptor.accept(tcp).await?;
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

    if response_frame.header.frame_type != FrameType::AuthResponse {
        return Err("expected AUTH_RESPONSE".into());
    }

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

    let mut settings = Settings::default();
    settings.set(SettingKey::ProtocolRevision, 1);
    settings.set(SettingKey::MaxFrameSize, config.max_frame_size());
    settings.set(SettingKey::MaxStreams, config.max_streams());
    let mut settings_payload = BytesMut::new();
    settings.encode(&mut settings_payload)?;
    let settings_frame = Frame::new(FrameType::Settings, 0, 0, settings_payload.freeze())?;
    write_frame(&mut stream, &settings_frame).await?;

    relay::relay_session(
        stream,
        credential,
        policy_set,
        FrameLimits {
            max_frame_size: config.max_frame_size(),
        },
        config.max_streams(),
    )
    .await
}
