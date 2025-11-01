use clap::{Args, Subcommand};
use crate::core::api_client::SshApiClient;
use anyhow::Result;

#[derive(Args)]
pub struct VpnArgs {
    #[command(subcommand)]
    pub command: VpnCommands,
}

#[derive(Subcommand)]
pub enum VpnCommands {
    /// Show VPN status
    Status,
    /// List VPN peers
    Peers,
    /// Connect to VPN peer
    Connect { peer_name: String },
}

pub async fn handle_vpn(args: VpnArgs, state: &crate::core::AppState) -> Result<()> {
    let client = &state.client;

    match args.command {
        VpnCommands::Status => {
            let status = client.get_vpn_status()?;
            println!("VPN Status: {}", status.wireguard.status);
            println!("Public Key: {}", status.wireguard.public_key);
            println!("Peers: {}", status.wireguard.peers);
        }
        VpnCommands::Peers => {
            let peers = client.get_vpn_peers()?;
            for peer in peers {
                println!("{}: {} ({})", peer.name, peer.ip, peer.status);
            }
        }
        VpnCommands::Connect { peer_name } => {
            let result = client.connect_vpn_peer(&peer_name)?;
            println!("Connection result: {}", result.status);
            println!("{}", result.message);
        }
    }

    Ok(())
}