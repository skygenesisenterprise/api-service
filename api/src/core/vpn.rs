use std::process::Command;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Clone)]
pub struct VpnPeer {
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<String>,
    pub persistent_keepalive: Option<u16>,
}

#[derive(Serialize, Deserialize)]
pub struct VpnConfig {
    pub interface: String,
    pub private_key: String,
    pub listen_port: u16,
    pub address: String,
    pub peers: HashMap<String, VpnPeer>,
}

pub struct VpnManager {
    config: Arc<RwLock<VpnConfig>>,
    interface: String,
}

impl VpnManager {
    pub fn new(interface: &str, config: VpnConfig) -> Self {
        VpnManager {
            config: Arc::new(RwLock::new(config)),
            interface: interface.to_string(),
        }
    }

    pub async fn apply_config(&self) -> Result<(), Box<dyn std::error::Error>> {
        let config = self.config.read().await;

        // Generate WireGuard configuration
        let mut wg_config = format!(
            "[Interface]\nPrivateKey = {}\nListenPort = {}\nAddress = {}\n\n",
            config.private_key, config.listen_port, config.address
        );

        for (name, peer) in &config.peers {
            wg_config.push_str(&format!(
                "[Peer]\nPublicKey = {}\nAllowedIPs = {}\n",
                peer.public_key,
                peer.allowed_ips.join(", ")
            ));

            if let Some(endpoint) = &peer.endpoint {
                wg_config.push_str(&format!("Endpoint = {}\n", endpoint));
            }

            if let Some(keepalive) = peer.persistent_keepalive {
                wg_config.push_str(&format!("PersistentKeepalive = {}\n", keepalive));
            }

            wg_config.push_str("\n");
        }

        // Write config to file
        let config_path = format!("/etc/wireguard/{}.conf", self.interface);
        std::fs::write(&config_path, wg_config)?;

        // Apply configuration using wg-quick
        let output = Command::new("wg-quick")
            .args(&["down", &self.interface])
            .output();

        if let Ok(_) = output {
            // Interface was up, bring it down first
        }

        let output = Command::new("wg-quick")
            .args(&["up", &self.interface])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Failed to apply WireGuard config: {}", stderr).into());
        }

        Ok(())
    }

    pub async fn add_peer(&self, name: String, peer: VpnPeer) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = self.config.write().await;
        config.peers.insert(name, peer);
        self.apply_config().await
    }

    pub async fn remove_peer(&self, name: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = self.config.write().await;
        config.peers.remove(name);
        self.apply_config().await
    }

    pub async fn get_peers(&self) -> HashMap<String, VpnPeer> {
        let config = self.config.read().await;
        config.peers.clone()
    }

    pub async fn get_status(&self) -> Result<String, Box<dyn std::error::Error>> {
        let output = Command::new("wg")
            .args(&["show", &self.interface])
            .output()?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("Failed to get WireGuard status: {}", stderr).into())
        }
    }
}

// Tailscale integration (simplified)
pub struct TailscaleManager {
    auth_key: String,
}

impl TailscaleManager {
    pub fn new(auth_key: String) -> Self {
        TailscaleManager { auth_key }
    }

    pub async fn authenticate(&self) -> Result<(), Box<dyn std::error::Error>> {
        let output = Command::new("tailscale")
            .args(&["login", "--auth-key", &self.auth_key])
            .output()?;

        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("Failed to authenticate with Tailscale: {}", stderr).into())
        }
    }

    pub async fn get_status(&self) -> Result<String, Box<dyn std::error::Error>> {
        let output = Command::new("tailscale")
            .arg("status")
            .output()?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("Failed to get Tailscale status: {}", stderr).into())
        }
    }

    pub async fn get_ip(&self) -> Result<String, Box<dyn std::error::Error>> {
        let output = Command::new("tailscale")
            .arg("ip")
            .output()?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("Failed to get Tailscale IP: {}", stderr).into())
        }
    }
}