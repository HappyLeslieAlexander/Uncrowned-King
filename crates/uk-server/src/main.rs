//! Uncrowned King server binary.

use clap::{Parser, Subcommand};
use uk_server::{AnyError, check_config, config::ServerConfig, run};

/// UK server command line.
#[derive(Debug, Parser)]
#[command(name = "uk-server", about = "Uncrowned King server")]
struct Args {
    /// Path to server TOML config.
    #[arg(long)]
    config: String,
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
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let config = ServerConfig::load(&args.config)?;
    match args.command.unwrap_or(Command::Serve) {
        Command::Serve => run(config).await?,
        Command::ConfigCheck => {
            check_config(&config)?;
            println!("uk-server config ok");
        }
    }
    Ok(())
}
