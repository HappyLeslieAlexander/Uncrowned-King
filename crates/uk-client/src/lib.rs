//! Uncrowned King client library.

pub mod config;

mod relay;
mod session;
mod socks5;
mod tls;

use crate::config::ClientConfig;

/// Client error type.
pub type AnyError = Box<dyn std::error::Error + Send + Sync>;

/// Validates client config and TLS trust material without connecting.
pub fn check_config(config: &ClientConfig) -> Result<(), AnyError> {
    config.validate_network_endpoints()?;
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
) -> Result<
    (
        tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
        uk_proto::Settings,
    ),
    AnyError,
> {
    session::connect_authenticated(&config).await
}

/// Starts a local SOCKS5 listener backed by UK TCP relay.
pub async fn run_socks5_listener(config: ClientConfig, listen: String) -> Result<(), AnyError> {
    relay::run_socks5_listener(config, listen).await
}
