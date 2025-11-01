// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise CLI
//  Module: Telemetry Service
// ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide telemetry business logic for CLI operations.
//  NOTICE: This module encapsulates telemetry operations using the API client.
//  SECURITY: Secure telemetry data handling
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use crate::core::api_client::SshApiClient;
use anyhow::Result;
use serde_json::Value;

/// Telemetry service for CLI operations
pub struct TelemetryService<'a> {
    client: &'a SshApiClient,
}

impl<'a> TelemetryService<'a> {
    /// Create new telemetry service
    pub fn new(client: &'a SshApiClient) -> Self {
        Self { client }
    }

    /// Get system metrics
    pub async fn get_metrics(&self) -> Result<Value> {
        let params = serde_json::json!({});
        let result = self.client.call_method("telemetry.metrics", params)?;
        Ok(result)
    }

    /// Get monitoring status
    pub async fn get_status(&self) -> Result<Value> {
        let params = serde_json::json!({});
        let result = self.client.call_method("telemetry.status", params)?;
        Ok(result)
    }

    /// Get performance data
    pub async fn get_performance(&self) -> Result<Value> {
        let params = serde_json::json!({});
        let result = self.client.call_method("telemetry.performance", params)?;
        Ok(result)
    }

    /// Get health check results
    pub async fn get_health(&self) -> Result<Value> {
        let params = serde_json::json!({});
        let result = self.client.call_method("telemetry.health", params)?;
        Ok(result)
    }

    /// Get alerts
    pub async fn get_alerts(&self) -> Result<Value> {
        let params = serde_json::json!({});
        let result = self.client.call_method("telemetry.alerts", params)?;
        Ok(result)
    }

    /// Get logs
    pub async fn get_logs(&self, limit: Option<u64>) -> Result<Value> {
        let params = serde_json::json!({
            "limit": limit.unwrap_or(100)
        });
        let result = self.client.call_method("telemetry.logs", params)?;
        Ok(result)
    }

    /// Get configuration
    pub async fn get_config(&self) -> Result<Value> {
        let params = serde_json::json!({});
        let result = self.client.call_method("telemetry.config", params)?;
        Ok(result)
    }
}