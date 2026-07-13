//! Uncrowned King client binary.

use std::net::SocketAddr;

use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use tokio::net::TcpListener;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use uk_client::{
    AnyError, ClientReloadError, ClientReloadHandle, check_config, client_reload_channel,
    config::ClientConfig, run_handshake, run_socks5_listener_on_until_shutdown_with_reload,
};
use uk_proto::validate_host_port_endpoint;

/// UK client command line.
#[derive(Debug, Parser)]
#[command(name = "uk-client", version, about = "Uncrowned King client")]
struct Args {
    /// Path to client TOML config.
    #[arg(long, global = true)]
    config: Option<String>,
    /// Log output format.
    #[arg(long, global = true, value_enum, default_value_t = LogFormat::Text)]
    log_format: LogFormat,
    /// Client subcommand.
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum LogFormat {
    Text,
    Json,
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
    let args = Args::parse();
    init_tracing(args.log_format);
    let config_path = config_path(&args)?.to_owned();
    let config = ClientConfig::load(&config_path)?;
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
            let (reload_handle, reload_rx) = client_reload_channel();
            run_socks5_listener_on_until_shutdown_with_reload(
                config,
                listener,
                reload_rx,
                shutdown_signal(config_path, reload_handle),
            )
            .await?;
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

async fn shutdown_signal(config_path: String, reload_handle: ClientReloadHandle) {
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
            warn!(event = "client.signal.install_error", signal = name, error = %err);
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
async fn queue_config_reload(config_path: &str, reload_handle: &ClientReloadHandle) -> bool {
    let load_path = config_path.to_owned();
    let loaded = tokio::task::spawn_blocking(move || ClientConfig::load(load_path)).await;
    let config = match loaded {
        Ok(Ok(config)) => config,
        Ok(Err(err)) => {
            warn!(event = "client.config.reload_load_failure", error = %err);
            return true;
        }
        Err(err) => {
            warn!(event = "client.config.reload_task_failure", error = %err);
            return true;
        }
    };
    match reload_handle.reload(config).await {
        Ok(generation) => {
            info!(
                event = "client.config.reload_applied",
                config_generation = generation
            );
            true
        }
        Err(ClientReloadError::Rejected(reason)) => {
            warn!(event = "client.config.reload_rejected", error = %reason);
            true
        }
        Err(ClientReloadError::ClientStopped) => false,
    }
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
    fn parses_json_log_format_after_subcommand() {
        let args = Args::try_parse_from([
            "uk-client",
            "config-check",
            "--config",
            "client.toml",
            "--log-format",
            "json",
        ])
        .unwrap();

        assert_eq!(args.log_format, LogFormat::Json);
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
