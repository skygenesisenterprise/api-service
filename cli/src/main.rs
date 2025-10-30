mod config;
mod core;
mod controllers;
mod services;

use clap::{Parser, Subcommand};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Parser)]
#[command(name = "sge")]
#[command(about = "Sky Genesis Enterprise CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Network management commands
    Network(controllers::NetworkArgs),
    /// VPN management commands
    Vpn(controllers::VpnArgs),
    /// Mail service commands
    Mail(controllers::MailArgs),
    /// Search service commands
    Search(controllers::SearchArgs),
    /// Telemetry and monitoring commands
    Telemetry(controllers::TelemetryArgs),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .init();

    info!("Starting Sky Genesis Enterprise CLI");

    let cli = Cli::parse();
    let config = config::Config::load()?;
    let state = core::AppState::new(config).await?;

    match cli.command {
        Commands::Network(args) => controllers::handle_network(args, &state).await,
        Commands::Vpn(args) => controllers::handle_vpn(args, &state).await,
        Commands::Mail(args) => controllers::handle_mail(args, &state).await,
        Commands::Search(args) => controllers::handle_search(args, &state).await,
        Commands::Telemetry(args) => controllers::handle_telemetry(args, &state).await,
    }
}
