//! Uncrowned King client binary.

use clap::{Parser, Subcommand};
use tracing::warn;
use tracing_subscriber::EnvFilter;
use uk_client::{
    AnyError, check_config, config::ClientConfig, run_handshake, run_socks5_listener_until_shutdown,
};

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
        Command::Socks5 { listen } => {
            run_socks5_listener_until_shutdown(config, listen, shutdown_signal()).await?;
        }
    }
    Ok(())
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
}
