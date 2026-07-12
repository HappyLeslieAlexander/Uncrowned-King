//! Uncrowned King client binary.

use std::net::SocketAddr;

use clap::{ArgAction, Parser, Subcommand};
use tokio::net::TcpListener;
use tracing::warn;
use tracing_subscriber::EnvFilter;
use uk_client::{
    AnyError, check_config, config::ClientConfig, run_handshake,
    run_socks5_listener_on_until_shutdown,
};
use uk_proto::validate_host_port_endpoint;

/// UK client command line.
#[derive(Debug, Parser)]
#[command(name = "uk-client", version, about = "Uncrowned King client")]
struct Args {
    /// Path to client TOML config.
    #[arg(long, global = true)]
    config: Option<String>,
    /// Client subcommand.
    #[command(subcommand)]
    command: Command,
}

/// Client mode.
#[derive(Debug, Subcommand)]
enum Command {
    /// Validate config and TLS trust files without connecting.
    ConfigCheck,
    /// Connect to the server and complete UK authentication.
    Handshake,
    /// Start a local SOCKS5 listener.
    Socks5 {
        /// Local listen address.
        #[arg(long, default_value = "127.0.0.1:1080")]
        listen: String,
        /// Explicitly allow an unauthenticated SOCKS listener outside loopback.
        #[arg(long, action = ArgAction::SetTrue)]
        allow_non_loopback: bool,
    },
}

#[tokio::main]
async fn main() -> Result<(), AnyError> {
    init_tracing();
    let args = Args::parse();
    let config = ClientConfig::load(config_path(&args)?)?;
    match args.command {
        Command::ConfigCheck => {
            check_config(&config)?;
            println!("uk-client config ok");
        }
        Command::Handshake => {
            run_handshake(config).await?;
            println!("uk-client handshake ok");
        }
        Command::Socks5 {
            listen,
            allow_non_loopback,
        } => {
            check_config(&config)?;
            validate_host_port_endpoint("socks listen", &listen)?;
            let listener = TcpListener::bind(&listen).await?;
            let listen = listener.local_addr()?;
            validate_socks_listener_scope(listen, allow_non_loopback)?;
            if allow_non_loopback && !listen.ip().is_loopback() {
                warn!(event = "socks5.non_loopback_allowed", listen = %listen);
            }
            run_socks5_listener_on_until_shutdown(config, listener, shutdown_signal()).await?;
        }
    }
    Ok(())
}

fn validate_socks_listener_scope(
    listen: SocketAddr,
    allow_non_loopback: bool,
) -> Result<(), AnyError> {
    if listen.ip().is_loopback() || allow_non_loopback {
        Ok(())
    } else {
        Err(format!(
            "refusing unauthenticated SOCKS5 listener on {listen}; use --allow-non-loopback to acknowledge the exposure"
        )
        .into())
    }
}

fn config_path(args: &Args) -> Result<&str, AnyError> {
    args.config
        .as_deref()
        .ok_or_else(|| "--config is required".into())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    () = wait_for_ctrl_c() => {}
                    _ = terminate.recv() => {}
                }
            }
            Err(err) => {
                warn!(event = "client.signal.install_error", error = %err);
                wait_for_ctrl_c().await;
            }
        }
    }

    #[cfg(not(unix))]
    wait_for_ctrl_c().await;
}

async fn wait_for_ctrl_c() {
    if let Err(err) = tokio::signal::ctrl_c().await {
        warn!(event = "client.signal.ctrl_c_error", error = %err);
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn command_definition_is_valid() {
        Args::command().debug_assert();
    }

    #[test]
    fn parses_config_before_subcommand() {
        let args =
            Args::try_parse_from(["uk-client", "--config", "client.toml", "config-check"]).unwrap();

        assert_eq!(args.config.as_deref(), Some("client.toml"));
        assert!(matches!(args.command, Command::ConfigCheck));
    }

    #[test]
    fn parses_config_after_subcommand() {
        let args =
            Args::try_parse_from(["uk-client", "config-check", "--config", "client.toml"]).unwrap();

        assert_eq!(args.config.as_deref(), Some("client.toml"));
        assert!(matches!(args.command, Command::ConfigCheck));
    }

    #[test]
    fn rejects_missing_config_path() {
        let args = Args::try_parse_from(["uk-client", "config-check"]).unwrap();

        assert!(config_path(&args).is_err());
    }

    #[test]
    fn socks5_defaults_to_loopback_without_exposure_override() {
        let args =
            Args::try_parse_from(["uk-client", "--config", "client.toml", "socks5"]).unwrap();

        assert!(matches!(
            args.command,
            Command::Socks5 {
                ref listen,
                allow_non_loopback: false
            } if listen == "127.0.0.1:1080"
        ));
    }

    #[test]
    fn parses_non_loopback_exposure_override() {
        let args = Args::try_parse_from([
            "uk-client",
            "--config",
            "client.toml",
            "socks5",
            "--listen",
            "0.0.0.0:1080",
            "--allow-non-loopback",
        ])
        .unwrap();

        assert!(matches!(
            args.command,
            Command::Socks5 {
                ref listen,
                allow_non_loopback: true
            } if listen == "0.0.0.0:1080"
        ));
    }

    #[test]
    fn rejects_non_loopback_listener_without_override() {
        let listen = SocketAddr::from(([0, 0, 0, 0], 1080));

        let error = validate_socks_listener_scope(listen, false).unwrap_err();

        assert!(error.to_string().contains("--allow-non-loopback"));
    }

    #[test]
    fn accepts_loopback_and_explicit_non_loopback_listener() {
        let loopback = SocketAddr::from(([127, 0, 0, 1], 1080));
        let non_loopback = SocketAddr::from(([0, 0, 0, 0], 1080));

        assert!(validate_socks_listener_scope(loopback, false).is_ok());
        assert!(validate_socks_listener_scope(non_loopback, true).is_ok());
    }
}
