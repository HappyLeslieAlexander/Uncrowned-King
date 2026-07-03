//! Uncrowned King client binary.

use clap::{Parser, Subcommand};
use uk_client::{AnyError, check_config, config::ClientConfig, run_handshake, run_socks5_listener};

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
        Command::ConfigCheck => {
            check_config(&config)?;
            println!("uk-client config ok");
        }
        Command::Handshake => {
            run_handshake(config).await?;
            println!("uk-client handshake ok");
        }
        Command::Socks5 { listen } => {
            run_socks5_listener(config, listen).await?;
        }
    }
    Ok(())
}
