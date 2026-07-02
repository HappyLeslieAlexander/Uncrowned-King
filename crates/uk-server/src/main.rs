//! UncrownedKing server binary placeholder.

use clap::Parser;

/// UK server command line.
#[derive(Debug, Parser)]
#[command(name = "uk-server", about = "UncrownedKing server")]
struct Args {
    /// Path to server TOML config.
    #[arg(long)]
    config: Option<String>,
}

fn main() {
    let args = Args::parse();
    println!("uk-server v0.1 placeholder config={:?}", args.config);
}
