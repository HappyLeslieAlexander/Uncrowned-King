//! Uncrowned King client library.

pub mod config;

mod config_state;
mod observability;
mod quic;
mod relay;
mod session;
mod socks5;
mod tls;

use std::{error::Error, fmt, future, future::Future};

use tokio::sync::{mpsc, oneshot};

use crate::config::ClientConfig;
pub use crate::session::ClientCarrier;

const RELOAD_CHANNEL_CAPACITY: usize = 1;

/// Client error type.
pub type AnyError = Box<dyn std::error::Error + Send + Sync>;

/// Sends validated config reloads to a running SOCKS5 client.
#[derive(Clone, Debug)]
pub struct ClientReloadHandle {
    tx: mpsc::Sender<ClientReloadRequest>,
}

/// Receives config reloads inside the SOCKS5 listener loop.
#[derive(Debug)]
pub struct ClientReloadReceiver {
    rx: mpsc::Receiver<ClientReloadRequest>,
}

#[derive(Debug)]
struct ClientReloadRequest {
    config: ClientConfig,
    response: oneshot::Sender<Result<u64, String>>,
}

/// Error returned when a client config reload cannot be applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientReloadError {
    /// The client stopped before it could apply the reload.
    ClientStopped,
    /// The candidate config was rejected without changing the active generation.
    Rejected(String),
}

impl fmt::Display for ClientReloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClientStopped => formatter.write_str("client stopped before config reload"),
            Self::Rejected(reason) => write!(formatter, "client rejected config reload: {reason}"),
        }
    }
}

impl Error for ClientReloadError {}

impl ClientReloadHandle {
    /// Queues a candidate config and waits until the listener accepts or rejects it.
    pub async fn reload(&self, config: ClientConfig) -> Result<u64, ClientReloadError> {
        let (response, result) = oneshot::channel();
        self.tx
            .send(ClientReloadRequest { config, response })
            .await
            .map_err(|_| ClientReloadError::ClientStopped)?;
        result
            .await
            .map_err(|_| ClientReloadError::ClientStopped)?
            .map_err(ClientReloadError::Rejected)
    }
}

/// Creates a bounded client config reload channel.
pub fn client_reload_channel() -> (ClientReloadHandle, ClientReloadReceiver) {
    let (tx, rx) = mpsc::channel(RELOAD_CHANNEL_CAPACITY);
    (ClientReloadHandle { tx }, ClientReloadReceiver { rx })
}

/// Validates client config and TLS trust material without connecting.
pub fn check_config(config: &ClientConfig) -> Result<(), AnyError> {
    config.validate_network_endpoints()?;
    config.validate_resource_limits()?;
    config.validate_auth_material()?;
    let _connector = tls::connector(&config.ca_cert_path)?;
    let _server_name = tls::server_name(config.server_name.clone())?;
    Ok(())
}

/// Connects to the server and completes UK authentication.
pub async fn run_handshake(config: ClientConfig) -> Result<(), AnyError> {
    let (_stream, _settings) = connect_authenticated_carrier(config).await?;
    Ok(())
}

/// Connects to the server, authenticates, and returns the live UK carrier.
pub async fn connect_authenticated_carrier(
    config: ClientConfig,
) -> Result<(ClientCarrier, uk_proto::Settings), AnyError> {
    session::connect_authenticated(&config).await
}

/// Starts a SOCKS5 listener backed by UK TCP and UDP relay.
///
/// This library API does not add SOCKS authentication or restrict the listen
/// address. Callers should use loopback or enforce separate network access
/// controls. The `uk-client` binary requires an explicit override for
/// non-loopback addresses.
pub async fn run_socks5_listener(config: ClientConfig, listen: String) -> Result<(), AnyError> {
    run_socks5_listener_until_shutdown(config, listen, future::pending()).await
}

/// Starts a SOCKS5 listener until `shutdown` resolves.
///
/// This library API does not add SOCKS authentication or restrict the listen
/// address. Callers should use loopback or enforce separate network access
/// controls.
pub async fn run_socks5_listener_until_shutdown<F>(
    config: ClientConfig,
    listen: String,
    shutdown: F,
) -> Result<(), AnyError>
where
    F: Future<Output = ()> + Send,
{
    relay::run_socks5_listener_until_shutdown(config, listen, shutdown).await
}

/// Starts a SOCKS5 listener until shutdown and applies validated config reloads.
pub async fn run_socks5_listener_until_shutdown_with_reload<F>(
    config: ClientConfig,
    listen: String,
    reload_rx: ClientReloadReceiver,
    shutdown: F,
) -> Result<(), AnyError>
where
    F: Future<Output = ()> + Send,
{
    relay::run_socks5_listener_until_shutdown_with_reload(config, listen, reload_rx, shutdown).await
}

/// Starts a SOCKS5 service on an already-bound listener.
///
/// The caller owns listener exposure and access control. SOCKS authentication
/// is not provided by this API.
pub async fn run_socks5_listener_on(
    config: ClientConfig,
    listener: tokio::net::TcpListener,
) -> Result<(), AnyError> {
    run_socks5_listener_on_until_shutdown(config, listener, future::pending()).await
}

/// Starts a SOCKS5 service on an already-bound listener until `shutdown` resolves.
///
/// The caller owns listener exposure and access control. SOCKS authentication
/// is not provided by this API.
pub async fn run_socks5_listener_on_until_shutdown<F>(
    config: ClientConfig,
    listener: tokio::net::TcpListener,
    shutdown: F,
) -> Result<(), AnyError>
where
    F: Future<Output = ()> + Send,
{
    relay::run_socks5_listener_on_until_shutdown(config, listener, shutdown).await
}

/// Starts an already-bound SOCKS5 service until shutdown and applies config reloads.
///
/// The caller owns listener exposure and access control. SOCKS authentication
/// is not provided by this API.
pub async fn run_socks5_listener_on_until_shutdown_with_reload<F>(
    config: ClientConfig,
    listener: tokio::net::TcpListener,
    reload_rx: ClientReloadReceiver,
    shutdown: F,
) -> Result<(), AnyError>
where
    F: Future<Output = ()> + Send,
{
    relay::run_socks5_listener_on_until_shutdown_with_reload(config, listener, reload_rx, shutdown)
        .await
}
