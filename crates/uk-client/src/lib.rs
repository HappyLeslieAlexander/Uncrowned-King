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
    config.validate_auth_material()?;
    let _connector = tls::connector(&config.ca_cert_path)?;
    let _server_name = tls::server_name(config.server_name.clone())?;
    Ok(())
}

/// Connects to the server and completes UK authentication.
pub async fn run_handshake(config: ClientConfig) -> Result<(), AnyError> {
    let (_stream, _settings) = session::connect_authenticated(&config).await?;
    Ok(())
}

/// Starts a local SOCKS5 listener backed by UK TCP relay.
pub async fn run_socks5_listener(config: ClientConfig, listen: String) -> Result<(), AnyError> {
    relay::run_socks5_listener(config, listen).await
}
