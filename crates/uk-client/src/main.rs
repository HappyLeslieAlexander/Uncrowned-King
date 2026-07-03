//! Uncrowned King client binary.

mod config;
mod relay;
mod session;
mod socks5;
mod tls;

use clap::{Parser, Subcommand};

use crate::config::ClientConfig;

type AnyError = Box<dyn std::error::Error + Send + Sync>;

/// UK client command line.
#[derive(Debug, Parser)]
#[command(name = "uk-client", about = "Uncrowned King client")]
struct Args {
    /// Path to client TOML config.
    #[arg(long)]
    config: String,
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
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let config = ClientConfig::load(&args.config)?;
    match args.command {
        Command::ConfigCheck => check_config(&config)?,
        Command::Handshake => run_handshake(config).await?,
        Command::Socks5 { listen } => {
            relay::run_socks5_listener(config, listen).await?;
        }
    }
    Ok(())
}

fn check_config(config: &ClientConfig) -> Result<(), AnyError> {
    config.validate_auth_material()?;
    let _connector = tls::connector(&config.ca_cert_path)?;
    let _server_name = tls::server_name(config.server_name.clone())?;
    println!("uk-client config ok");
    Ok(())
}

async fn run_handshake(config: ClientConfig) -> Result<(), AnyError> {
    let (_stream, _settings) = session::connect_authenticated(&config).await?;
    println!("uk-client handshake ok");
    Ok(())
}
