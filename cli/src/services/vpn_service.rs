// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise CLI
//  Module: VPN Service
// ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide VPN business logic for CLI operations.
//  NOTICE: This module encapsulates VPN operations using the API client.
//  SECURITY: Secure VPN connection handling
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use crate::core::api_client::SshApiClient;
use anyhow::Result;
use serde_json::Value;

/// VPN service for CLI operations
#[allow(dead_code)]
pub struct VpnService<'a> {
    client: &'a SshApiClient,
}

#[allow(dead_code)]
impl<'a> VpnService<'a> {
    /// Create new VPN service
    pub fn new(client: &'a SshApiClient) -> Self {
        Self { client }
    }

    /// Get VPN status
    pub async fn get_status(&self) -> Result<Value> {
        let params = serde_json::json!({});
        let result = self.client.call_method("vpn.status", params)?;
        Ok(result)
    }

    /// Get VPN peers
    pub async fn get_peers(&self) -> Result<Value> {
        let params = serde_json::json!({});
        let result = self.client.call_method("vpn.peers", params)?;
        Ok(result)
    }

    /// Connect to VPN peer
    pub async fn connect_peer(&self, peer_name: &str) -> Result<Value> {
        let params = serde_json::json!({
            "peer": peer_name
        });
        let result = self.client.call_method("vpn.connect", params)?;
        Ok(result)
    }

    /// Disconnect from VPN peer
    pub async fn disconnect_peer(&self, peer_name: &str) -> Result<Value> {
        let params = serde_json::json!({
            "peer": peer_name
        });
        let result = self.client.call_method("vpn.disconnect", params)?;
        Ok(result)
    }

    /// Get VPN configuration
    pub async fn get_config(&self) -> Result<Value> {
        let params = serde_json::json!({});
        let result = self.client.call_method("vpn.config", params)?;
        Ok(result)
    }

    /// Update VPN configuration
    pub async fn update_config(&self, config: Value) -> Result<Value> {
        let params = serde_json::json!({
            "config": config
        });
        let result = self.client.call_method("vpn.update_config", params)?;
        Ok(result)
    }

    /// Get VPN keys
    pub async fn get_keys(&self) -> Result<Value> {
        let params = serde_json::json!({});
        let result = self.client.call_method("vpn.keys", params)?;
        Ok(result)
    }

    /// Generate new VPN keys
    pub async fn generate_keys(&self) -> Result<Value> {
        let params = serde_json::json!({});
        let result = self.client.call_method("vpn.generate_keys", params)?;
        Ok(result)
    }
}