//! Uncrowned King client library.

pub mod config;

mod relay;
mod session;
mod socks5;
mod tls;

use std::{future, future::Future};

use crate::config::ClientConfig;

/// Client error type.
pub type AnyError = Box<dyn std::error::Error + Send + Sync>;

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
) -> Result<
    (
        tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
        uk_proto::Settings,
    ),
    AnyError,
> {
    session::connect_authenticated(&config).await
}

/// Starts a local SOCKS5 listener backed by UK TCP and UDP relay.
pub async fn run_socks5_listener(config: ClientConfig, listen: String) -> Result<(), AnyError> {
    run_socks5_listener_until_shutdown(config, listen, future::pending()).await
}

/// Starts a local SOCKS5 listener until `shutdown` resolves.
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

/// Starts a local SOCKS5 service on an already-bound listener.
pub async fn run_socks5_listener_on(
    config: ClientConfig,
    listener: tokio::net::TcpListener,
) -> Result<(), AnyError> {
    run_socks5_listener_on_until_shutdown(config, listener, future::pending()).await
}

/// Starts a local SOCKS5 service on an already-bound listener until `shutdown` resolves.
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
