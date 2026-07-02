//! UncrownedKing client binary placeholder.

use clap::{Parser, Subcommand};

/// UK client command line.
#[derive(Debug, Parser)]
#[command(name = "uk-client", about = "UncrownedKing client")]
struct Args {
    /// Path to client TOML config.
    #[arg(long)]
    config: Option<String>,
    /// Client subcommand.
    #[command(subcommand)]
    command: Option<Command>,
}

/// Client mode.
#[derive(Debug, Subcommand)]
enum Command {
    /// Start a local SOCKS5 listener. Full implementation lands in the relay milestone.
    Socks5 {
        /// Local listen address.
        #[arg(long, default_value = "127.0.0.1:1080")]
        listen: String,
    },
}

fn main() {
    let args = Args::parse();
    println!("uk-client v0.1 placeholder config={:?}", args.config);
    if let Some(Command::Socks5 { listen }) = args.command {
        println!("socks5 placeholder listen={listen}");
    }
}
