//! Uncrowned King server binary.

use clap::{Parser, Subcommand};
use tracing::warn;
use tracing_subscriber::EnvFilter;
use uk_server::{AnyError, check_config, config::ServerConfig, run_until_shutdown};

/// UK server command line.
#[derive(Debug, Parser)]
#[command(name = "uk-server", version, about = "Uncrowned King server")]
struct Args {
    /// Path to server TOML config.
    #[arg(long, global = true)]
    config: Option<String>,
    /// Server subcommand.
    #[command(subcommand)]
    command: Option<Command>,
}

/// Server mode.
#[derive(Debug, Clone, Copy, Subcommand)]
enum Command {
    /// Start the UK server listener.
    Serve,
    /// Validate config, credentials, policy, and TLS files without listening.
    ConfigCheck,
}

#[tokio::main]
async fn main() -> Result<(), AnyError> {
    init_tracing();
    let args = Args::parse();
    let config = ServerConfig::load(config_path(&args)?)?;
    match args.command.unwrap_or(Command::Serve) {
        Command::Serve => run_until_shutdown(config, shutdown_signal()).await?,
        Command::ConfigCheck => {
            check_config(&config)?;
            println!("uk-server config ok");
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
                warn!(event = "server.signal.install_error", error = %err);
                wait_for_ctrl_c().await;
            }
        }
    }

    #[cfg(not(unix))]
    wait_for_ctrl_c().await;
}

async fn wait_for_ctrl_c() {
    if let Err(err) = tokio::signal::ctrl_c().await {
        warn!(event = "server.signal.ctrl_c_error", error = %err);
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
            Args::try_parse_from(["uk-server", "--config", "server.toml", "config-check"]).unwrap();

        assert_eq!(args.config.as_deref(), Some("server.toml"));
        assert!(matches!(args.command, Some(Command::ConfigCheck)));
    }

    #[test]
    fn parses_config_after_subcommand() {
        let args =
            Args::try_parse_from(["uk-server", "config-check", "--config", "server.toml"]).unwrap();

        assert_eq!(args.config.as_deref(), Some("server.toml"));
        assert!(matches!(args.command, Some(Command::ConfigCheck)));
    }

    #[test]
    fn rejects_missing_config_path() {
        let args = Args::try_parse_from(["uk-server", "config-check"]).unwrap();

        assert!(config_path(&args).is_err());
    }
}
