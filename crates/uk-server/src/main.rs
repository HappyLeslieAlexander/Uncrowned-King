//! Uncrowned King server binary.

use clap::{Parser, Subcommand, ValueEnum};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use uk_server::{
    AnyError, ServerReloadError, ServerReloadHandle, check_config, config::ServerConfig,
    run_until_shutdown_with_reload, server_reload_channel,
};

/// UK server command line.
#[derive(Debug, Parser)]
#[command(name = "uk-server", version, about = "Uncrowned King server")]
struct Args {
    /// Path to server TOML config.
    #[arg(long, global = true)]
    config: Option<String>,
    /// Log output format.
    #[arg(long, global = true, value_enum, default_value_t = LogFormat::Text)]
    log_format: LogFormat,
    /// Server subcommand.
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum LogFormat {
    Text,
    Json,
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
    let args = Args::parse();
    init_tracing(args.log_format);
    let config_path = config_path(&args)?.to_owned();
    let config = ServerConfig::load(&config_path)?;
    match args.command.unwrap_or(Command::Serve) {
        Command::Serve => {
            let (reload_handle, reload_rx) = server_reload_channel();
            run_until_shutdown_with_reload(
                config,
                reload_rx,
                shutdown_signal(config_path, reload_handle),
            )
            .await?;
        }
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

fn init_tracing(log_format: LogFormat) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    match log_format {
        LogFormat::Text => tracing_subscriber::fmt().with_env_filter(filter).init(),
        LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init(),
    }
}

async fn shutdown_signal(config_path: String, reload_handle: ServerReloadHandle) {
    #[cfg(unix)]
    {
        let mut terminate =
            install_unix_signal("SIGTERM", tokio::signal::unix::SignalKind::terminate());
        let mut hangup = install_unix_signal("SIGHUP", tokio::signal::unix::SignalKind::hangup());
        let ctrl_c = wait_for_ctrl_c();
        tokio::pin!(ctrl_c);

        loop {
            tokio::select! {
                () = &mut ctrl_c => break,
                received = receive_optional_unix_signal(&mut terminate) => {
                    if received {
                        break;
                    }
                    terminate = None;
                }
                received = receive_optional_unix_signal(&mut hangup) => {
                    if !received {
                        hangup = None;
                        continue;
                    }
                    if !queue_config_reload(&config_path, &reload_handle).await {
                        break;
                    }
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = (config_path, reload_handle);
        wait_for_ctrl_c().await;
    }
}

#[cfg(unix)]
fn install_unix_signal(
    name: &'static str,
    kind: tokio::signal::unix::SignalKind,
) -> Option<tokio::signal::unix::Signal> {
    match tokio::signal::unix::signal(kind) {
        Ok(signal) => Some(signal),
        Err(err) => {
            warn!(event = "server.signal.install_error", signal = name, error = %err);
            None
        }
    }
}

#[cfg(unix)]
async fn receive_optional_unix_signal(signal: &mut Option<tokio::signal::unix::Signal>) -> bool {
    match signal {
        Some(signal) => signal.recv().await.is_some(),
        None => std::future::pending().await,
    }
}

#[cfg(unix)]
async fn queue_config_reload(config_path: &str, reload_handle: &ServerReloadHandle) -> bool {
    let load_path = config_path.to_owned();
    let loaded = tokio::task::spawn_blocking(move || ServerConfig::load(load_path)).await;
    let config = match loaded {
        Ok(Ok(config)) => config,
        Ok(Err(err)) => {
            warn!(event = "server.config.reload_load_failure", error = %err);
            return true;
        }
        Err(err) => {
            warn!(event = "server.config.reload_task_failure", error = %err);
            return true;
        }
    };
    match reload_handle.reload(config).await {
        Ok(generation) => {
            info!(
                event = "server.config.reload_applied",
                access_control_generation = generation
            );
            true
        }
        Err(ServerReloadError::Rejected(reason)) => {
            warn!(event = "server.config.reload_rejected", error = %reason);
            true
        }
        Err(ServerReloadError::ServerStopped) => false,
    }
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
    fn parses_json_log_format_after_subcommand() {
        let args = Args::try_parse_from([
            "uk-server",
            "config-check",
            "--config",
            "server.toml",
            "--log-format",
            "json",
        ])
        .unwrap();

        assert_eq!(args.log_format, LogFormat::Json);
    }

    #[test]
    fn rejects_missing_config_path() {
        let args = Args::try_parse_from(["uk-server", "config-check"]).unwrap();

        assert!(config_path(&args).is_err());
    }
}
