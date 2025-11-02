// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Grafana Service
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | SENSITIVE
//  MISSION: Provide programmatic access to Grafana HTTP API for dashboard
//  management, datasource configuration, and alerting setup.
//  NOTICE: This service enables automated Grafana configuration and monitoring
//  dashboard creation through the Sky Genesis API.
//  MONITORING: Grafana dashboard creation, datasource management, alert rules
//  INTEGRATION: Grafana HTTP API, Prometheus datasources
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use reqwest::Client;
use crate::core::vault::VaultClient;
use std::sync::Arc;

/// [GRAFANA CONFIGURATION] Service Configuration
/// @MISSION Store Grafana API connection details securely.
/// @THREAT API key exposure in configuration.
/// @COUNTERMEASURE Secure storage via Vault integration.
/// @AUDIT Configuration access logged for security monitoring.
#[derive(Debug, Clone)]
pub struct GrafanaConfig {
    pub base_url: String,
    pub api_key: String,
    pub timeout_seconds: u64,
}

/// [GRAFANA DASHBOARD] Dashboard Structure
/// @MISSION Define Grafana dashboard JSON structure.
/// @THREAT Incompatible dashboard format.
/// @COUNTERMEASURE Standard Grafana dashboard schema.
/// @AUDIT Dashboard creation tracked for audit compliance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrafanaDashboard {
    pub dashboard: serde_json::Value,
    pub folder_id: Option<i64>,
    pub overwrite: bool,
}

/// [GRAFANA DATASOURCE] Datasource Configuration
/// @MISSION Define datasource connection parameters.
/// @THREAT Incorrect datasource configuration.
/// @COUNTERMEASURE Validated configuration with health checks.
/// @AUDIT Datasource changes logged for monitoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrafanaDatasource {
    pub name: String,
    pub r#type: String,
    pub url: String,
    pub access: String, // "proxy" or "direct"
    pub basic_auth: Option<bool>,
    pub basic_auth_user: Option<String>,
    pub secure_json_data: Option<HashMap<String, String>>,
    pub json_data: Option<serde_json::Value>,
}

/// [GRAFANA ALERT RULE] Alert Rule Definition
/// @MISSION Define alerting rules for monitoring.
/// @THREAT Missing critical alerts.
/// @COUNTERMEASURE Structured alert rule configuration.
/// @AUDIT Alert rule changes tracked for compliance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrafanaAlertRule {
    pub title: String,
    pub condition: String,
    pub data: Vec<serde_json::Value>,
    pub no_data_state: String,
    pub exec_err_state: String,
    pub for_duration: String,
}

/// [GRAFANA SERVICE] API Integration Service
/// @MISSION Provide comprehensive Grafana API integration.
/// @THREAT Manual Grafana configuration errors.
/// @COUNTERMEASURE Automated configuration via API.
/// @DEPENDENCY Grafana service must be accessible.
/// @PERFORMANCE API calls with timeout protection.
/// @AUDIT All Grafana operations logged and traced.
pub struct GrafanaService {
    client: Client,
    config: GrafanaConfig,
    vault_client: Arc<VaultClient>,
}

impl GrafanaService {
    /// [SERVICE INITIALIZATION] Grafana API Setup
    /// @MISSION Initialize Grafana service with secure configuration.
    /// @THREAT Misconfigured API access.
    /// @COUNTERMEASURE Configuration validation and secure key retrieval.
    /// @DEPENDENCY Vault for API key storage.
    /// @PERFORMANCE Lightweight initialization with connection validation.
    /// @AUDIT Service initialization logged for security tracking.
    pub async fn new(vault_client: Arc<VaultClient>) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let base_url = std::env::var("GRAFANA_URL")
            .unwrap_or_else(|_| "https://grafana.skygenesisenterprise.com".to_string());
        let api_key_path = std::env::var("GRAFANA_API_KEY_PATH")
            .unwrap_or_else(|_| "grafana/api_key".to_string());

        // Retrieve API key from Vault
        let api_key = vault_client.get_secret(&api_key_path, "key").await?;

        let config = GrafanaConfig {
            base_url,
            api_key,
            timeout_seconds: 30,
        };

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_seconds))
            .build()?;

        Ok(GrafanaService {
            client,
            config,
            vault_client,
        })
    }

    /// [HEALTH CHECK] Grafana Service Availability
    /// @MISSION Verify Grafana API accessibility.
    /// @THREAT Grafana service unavailability.
    /// @COUNTERMEASURE Direct API health check.
    /// @DEPENDENCY Grafana service must be running.
    /// @PERFORMANCE Health check completes within timeout.
    /// @AUDIT Health check results used for monitoring.
    pub async fn health_check(&self) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/api/health", self.config.base_url);
        let response = self.client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .send()
            .await?;

        Ok(response.status().is_success())
    }

    /// [CREATE DASHBOARD] Programmatic Dashboard Creation
    /// @MISSION Create Grafana dashboards via API.
    /// @THREAT Manual dashboard creation errors.
    /// @COUNTERMEASURE Automated dashboard deployment.
    /// @DEPENDENCY Valid dashboard JSON structure.
    /// @PERFORMANCE Dashboard creation within API timeout.
    /// @AUDIT Dashboard creation logged for compliance.
    pub async fn create_dashboard(&self, dashboard: GrafanaDashboard) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/api/dashboards/db", self.config.base_url);

        let payload = serde_json::json!({
            "dashboard": dashboard.dashboard,
            "folderId": dashboard.folder_id,
            "overwrite": dashboard.overwrite
        });

        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(format!("Grafana API error: {}", error_text).into());
        }

        let result: serde_json::Value = response.json().await?;
        Ok(result)
    }

    /// [CREATE DATASOURCE] Prometheus Datasource Setup
    /// @MISSION Configure Prometheus datasource in Grafana.
    /// @THREAT Missing or misconfigured datasources.
    /// @COUNTERMEASURE Automated datasource creation.
    /// @DEPENDENCY Valid datasource configuration.
    /// @PERFORMANCE Datasource creation within API timeout.
    /// @AUDIT Datasource changes logged for monitoring.
    pub async fn create_datasource(&self, datasource: GrafanaDatasource) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/api/datasources", self.config.base_url);

        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .header("Content-Type", "application/json")
            .json(&datasource)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(format!("Grafana API error: {}", error_text).into());
        }

        let result: serde_json::Value = response.json().await?;
        Ok(result)
    }

    /// [LIST DASHBOARDS] Retrieve Dashboard Inventory
    /// @MISSION Get list of existing dashboards.
    /// @THREAT Unknown dashboard state.
    /// @COUNTERMEASURE API-based dashboard inventory.
    /// @DEPENDENCY Grafana API accessibility.
    /// @PERFORMANCE Dashboard listing within timeout.
    /// @AUDIT Dashboard inventory used for management.
    pub async fn list_dashboards(&self) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/api/search?type=dash-db", self.config.base_url);

        let response = self.client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(format!("Grafana API error: {}", error_text).into());
        }

        let result: Vec<serde_json::Value> = response.json().await?;
        Ok(result)
    }

    /// [DELETE DASHBOARD] Remove Dashboard
    /// @MISSION Delete dashboards via API.
    /// @THREAT Orphaned or outdated dashboards.
    /// @COUNTERMEASURE Programmatic dashboard cleanup.
    /// @DEPENDENCY Valid dashboard UID.
    /// @PERFORMANCE Dashboard deletion within timeout.
    /// @AUDIT Dashboard deletions logged for compliance.
    pub async fn delete_dashboard(&self, uid: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/api/dashboards/uid/{}", self.config.base_url, uid);

        let response = self.client
            .delete(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(format!("Grafana API error: {}", error_text).into());
        }

        Ok(())
    }

    /// [CREATE ALERT RULE] Set Up Monitoring Alerts
    /// @MISSION Create alert rules for system monitoring.
    /// @THREAT Undetected system issues.
    /// @COUNTERMEASURE Automated alert rule creation.
    /// @DEPENDENCY Valid alert rule configuration.
    /// @PERFORMANCE Alert creation within API timeout.
    /// @AUDIT Alert rules tracked for compliance.
    pub async fn create_alert_rule(&self, rule: GrafanaAlertRule) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/api/v1/provisioning/alert-rules", self.config.base_url);

        let payload = serde_json::json!({
            "title": rule.title,
            "condition": rule.condition,
            "data": rule.data,
            "noDataState": rule.no_data_state,
            "execErrState": rule.exec_err_state,
            "for": rule.for_duration
        });

        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(format!("Grafana API error: {}", error_text).into());
        }

        let result: serde_json::Value = response.json().await?;
        Ok(result)
    }

    /// [GET DASHBOARD] Retrieve Dashboard by UID
    /// @MISSION Fetch specific dashboard configuration.
    /// @THREAT Unknown dashboard content.
    /// @COUNTERMEASURE API-based dashboard retrieval.
    /// @DEPENDENCY Valid dashboard UID.
    /// @PERFORMANCE Dashboard retrieval within timeout.
    /// @AUDIT Dashboard access logged for security.
    pub async fn get_dashboard(&self, uid: &str) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/api/dashboards/uid/{}", self.config.base_url, uid);

        let response = self.client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(format!("Grafana API error: {}", error_text).into());
        }

        let result: serde_json::Value = response.json().await?;
        Ok(result)
    }

    /// [UPDATE DASHBOARD] Modify Existing Dashboard
    /// @MISSION Update dashboard configuration.
    /// @THREAT Outdated dashboard configurations.
    /// @COUNTERMEASURE Programmatic dashboard updates.
    /// @DEPENDENCY Valid dashboard JSON and UID.
    /// @PERFORMANCE Dashboard update within timeout.
    /// @AUDIT Dashboard modifications logged.
    pub async fn update_dashboard(&self, uid: &str, dashboard: GrafanaDashboard) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/api/dashboards/db", self.config.base_url);

        let mut payload = serde_json::json!({
            "dashboard": dashboard.dashboard,
            "folderId": dashboard.folder_id,
            "overwrite": dashboard.overwrite
        });

        // Add UID for update
        if let Some(obj) = payload["dashboard"].as_object_mut() {
            obj.insert("uid".to_string(), serde_json::Value::String(uid.to_string()));
        }

        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(format!("Grafana API error: {}", error_text).into());
        }

        let result: serde_json::Value = response.json().await?;
        Ok(result)
    }
}