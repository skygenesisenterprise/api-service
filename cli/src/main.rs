mod config;
mod core;
mod controllers;
mod queries;
mod routes;
mod services;
mod utils;
mod ssh_shell;

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
    /// Authentication commands
    Auth(controllers::AuthArgs),
    /// User management commands
    User(controllers::UserArgs),
    /// API key management commands
    Keys(controllers::KeyArgs),
    /// Security and cryptography commands
    Security(controllers::SecurityArgs),
    /// Organization management commands
    Org(controllers::OrgArgs),
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
    /// Device management commands
    Device(controllers::DeviceArgs),
    /// Interactive SSH shell
    Shell,
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
        Commands::Auth(args) => controllers::handle_auth(args, &state).await,
        Commands::User(args) => controllers::handle_user(args, &state).await,
        Commands::Keys(args) => controllers::handle_keys(args, &state).await,
        Commands::Security(args) => controllers::handle_security(args, &state).await,
        Commands::Org(args) => controllers::handle_org(args, &state).await,
        Commands::Network(args) => controllers::handle_network(args, &state).await,
        Commands::Vpn(args) => controllers::handle_vpn(args, &state).await,
        Commands::Mail(args) => controllers::handle_mail(args, &state).await,
        Commands::Search(args) => controllers::handle_search(args, &state).await,
        Commands::Telemetry(args) => controllers::handle_telemetry(args, &state).await,
        Commands::Device(args) => controllers::handle_device(args, &state).await,
        Commands::Shell => {
            let mut shell = ssh_shell::SshShell::new("admin".to_string());
            shell.run()?;
            Ok(())
        }
    }
}
