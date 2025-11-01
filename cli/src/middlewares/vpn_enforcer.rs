// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise CLI
//  Module: VPN Enforcement Middleware
// ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide VPN enforcement for CLI operations requiring secure access.
//  NOTICE: This module ensures that certain CLI operations are only performed
//  when connected to the corporate VPN or through approved secure channels.
//  SECURITY: Network-based access control and VPN status validation
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use crate::core::AppState;
use anyhow::{Result, anyhow};
use std::collections::HashSet;
use std::net::IpAddr;
use std::process::Command;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnConfig {
    pub required_commands: HashSet<String>,
    pub allowed_networks: Vec<String>, // CIDR notation
    pub vpn_check_command: Option<String>,
    pub enforce_vpn: bool,
}

impl Default for VpnConfig {
    fn default() -> Self {
        let mut required_commands = HashSet::new();
        required_commands.insert("security.*".to_string());
        required_commands.insert("keys.*".to_string());
        required_commands.insert("user.delete".to_string());
        required_commands.insert("org.delete".to_string());

        Self {
            required_commands,
            allowed_networks: vec![
                "10.0.0.0/8".to_string(),
                "172.16.0.0/12".to_string(),
                "192.168.0.0/16".to_string(),
            ],
            vpn_check_command: Some("ip route show | grep -q 'via'".to_string()),
            enforce_vpn: true,
        }
    }
}

#[derive(Debug)]
pub struct VpnEnforcer {
    config: VpnConfig,
}

impl VpnEnforcer {
    pub fn new(config: VpnConfig) -> Self {
        Self { config }
    }

    pub fn new_default() -> Self {
        Self::new(VpnConfig::default())
    }

    pub async fn enforce_vpn_for_command(&self, command: &str) -> Result<()> {
        if !self.config.enforce_vpn {
            tracing::debug!("VPN enforcement disabled");
            return Ok(());
        }

        // Check if this command requires VPN
        if !self.requires_vpn(command) {
            return Ok(());
        }

        // Check if user is on VPN
        if !self.is_on_vpn().await? {
            return Err(anyhow!(
                "Command '{}' requires VPN connection. Please connect to the corporate VPN first.",
                command
            ));
        }

        tracing::debug!("VPN requirement satisfied for command: {}", command);
        Ok(())
    }

    pub async fn is_on_vpn(&self) -> Result<bool> {
        // Method 1: Check network routes
        if let Some(ref cmd) = self.config.vpn_check_command {
            if self.check_vpn_via_command(cmd).await? {
                return Ok(true);
            }
        }

        // Method 2: Check IP address against allowed networks
        if self.check_vpn_via_ip().await? {
            return Ok(true);
        }

        // Method 3: Check for VPN-specific interfaces
        if self.check_vpn_interfaces().await? {
            return Ok(true);
        }

        Ok(false)
    }

    async fn check_vpn_via_command(&self, command: &str) -> Result<bool> {
        match Command::new("sh")
            .arg("-c")
            .arg(command)
            .status()
            .await
        {
            Ok(status) => Ok(status.success()),
            Err(_) => Ok(false),
        }
    }

    async fn check_vpn_via_ip(&self) -> Result<bool> {
        // Get local IP addresses
        let local_ips = self.get_local_ips()?;

        for ip in local_ips {
            for network in &self.config.allowed_networks {
                if self.ip_in_network(ip, network) {
                    tracing::debug!("IP {} is in allowed network {}", ip, network);
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    async fn check_vpn_interfaces(&self) -> Result<bool> {
        // Check for common VPN interface names
        let vpn_interfaces = ["tun0", "tap0", "wg0", "ppp0", "ipsec0"];

        for interface in &vpn_interfaces {
            if self.interface_exists(interface).await? {
                tracing::debug!("VPN interface {} found", interface);
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn requires_vpn(&self, command: &str) -> bool {
        // Check exact matches
        if self.config.required_commands.contains(command) {
            return true;
        }

        // Check wildcard patterns
        for pattern in &self.config.required_commands {
            if pattern.ends_with(".*") {
                let prefix = &pattern[..pattern.len() - 2];
                if command.starts_with(prefix) {
                    return true;
                }
            }
        }

        false
    }

    fn get_local_ips(&self) -> Result<Vec<IpAddr>> {
        let mut ips = Vec::new();

        // Get IPs from network interfaces
        if let Ok(interfaces) = nix::ifaddrs::getifaddrs() {
            for interface in interfaces {
                if let Some(addr) = interface.address {
                    match addr {
                        nix::sys::socket::SockAddr::Inet(inet_addr) => {
                            ips.push(inet_addr.ip().into());
                        }
                        _ => {}
                    }
                }
            }
        }

        Ok(ips)
    }

    fn ip_in_network(&self, ip: IpAddr, network: &str) -> bool {
        // Simple CIDR check - in production, use a proper IP network library
        match ip {
            IpAddr::V4(ipv4) => {
                if let Some((net_ip, prefix)) = self.parse_cidr_v4(network) {
                    let ip_int = u32::from(ipv4);
                    let net_int = u32::from(net_ip);
                    let mask = !0u32 << (32 - prefix);

                    (ip_int & mask) == (net_int & mask)
                } else {
                    false
                }
            }
            IpAddr::V6(_) => {
                // IPv6 support can be added later
                false
            }
        }
    }

    fn parse_cidr_v4(&self, cidr: &str) -> Option<(std::net::Ipv4Addr, u8)> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() == 2 {
            if let (Ok(ip), Ok(prefix)) = (
                parts[0].parse::<std::net::Ipv4Addr>(),
                parts[1].parse::<u8>(),
            ) {
                Some((ip, prefix))
            } else {
                None
            }
        } else {
            None
        }
    }

    async fn interface_exists(&self, interface_name: &str) -> Result<bool> {
        match Command::new("ip")
            .args(&["link", "show", interface_name])
            .status()
            .await
        {
            Ok(status) => Ok(status.success()),
            Err(_) => Ok(false),
        }
    }

    pub fn get_config(&self) -> &VpnConfig {
        &self.config
    }

    pub async fn get_vpn_status(&self) -> Result<VpnStatus> {
        let is_connected = self.is_on_vpn().await?;
        let local_ips = self.get_local_ips().unwrap_or_default();

        Ok(VpnStatus {
            connected: is_connected,
            local_ips,
            required_for_current_command: false, // This would be set by the caller
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnStatus {
    pub connected: bool,
    pub local_ips: Vec<IpAddr>,
    pub required_for_current_command: bool,
}

// Global VPN enforcer instance
lazy_static::lazy_static! {
    pub static ref VPN_ENFORCER: VpnEnforcer = VpnEnforcer::new_default();
}

// Convenience functions
pub async fn enforce_vpn_for_command(command: &str) -> Result<()> {
    VPN_ENFORCER.enforce_vpn_for_command(command).await
}

pub async fn check_vpn_status() -> Result<VpnStatus> {
    VPN_ENFORCER.get_vpn_status().await
}

pub async fn is_on_vpn() -> Result<bool> {
    VPN_ENFORCER.is_on_vpn().await
}

pub fn command_requires_vpn(command: &str) -> bool {
    VPN_ENFORCER.requires_vpn(command)
}