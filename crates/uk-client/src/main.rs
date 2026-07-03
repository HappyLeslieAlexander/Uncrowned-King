//! UncrownedKing client binary.

mod config;
mod relay;
mod session;
mod socks5;
mod tls;

use clap::{Parser, Subcommand};

use crate::config::ClientConfig;

/// UK client command line.
#[derive(Debug, Parser)]
#[command(name = "uk-client", about = "UncrownedKing client")]
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
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let config = ClientConfig::load(&args.config)?;
    match args.command {
        Command::Handshake => run_handshake(config).await?,
        Command::Socks5 { listen } => {
            relay::run_socks5_listener(config, listen).await?;
        }
    }
    Ok(())
}

async fn run_handshake(
    config: ClientConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (_stream, _settings) = session::connect_authenticated(&config).await?;
    println!("uk-client handshake ok");
    Ok(())
}
