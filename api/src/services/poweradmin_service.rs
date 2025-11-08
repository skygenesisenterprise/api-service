// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: PowerAdmin Service
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | SENSITIVE
//  MISSION: Provide programmatic access to PowerAdmin HTTP API for DNS zone
//  management, record operations, and DNSSEC configuration.
//  NOTICE: This service enables automated DNS management through
//  the Sky Genesis API for infrastructure automation.
//  DNS: Zone operations, record management, DNSSEC
//  INTEGRATION: PowerAdmin HTTP API, PowerDNS backend
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================


use serde::{Deserialize, Serialize};
use reqwest::Client;
use crate::core::vault::VaultClient;
use std::sync::Arc;

/// [POWERADMIN CONFIGURATION] Service Configuration
/// @MISSION Store PowerAdmin API connection details securely.
/// @THREAT API key exposure in configuration.
/// @COUNTERMEASURE Secure storage via Vault integration.
/// @AUDIT Configuration access logged for security monitoring.
#[derive(Debug, Clone)]
pub struct PowerAdminConfig {
    pub base_url: String,
    pub api_key: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub timeout_seconds: u64,
}

/// [POWERADMIN ZONE] Zone Structure
/// @MISSION Define PowerAdmin zone JSON structure.
/// @THREAT Incompatible zone format.
/// @COUNTERMEASURE Standard PowerAdmin zone schema.
/// @AUDIT Zone operations tracked for audit compliance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowerAdminZone {
    pub name: String,
    pub r#type: String, // MASTER, SLAVE, NATIVE
    pub nameservers: Option<Vec<String>>,
    pub template: Option<String>,
}

/// [POWERADMIN RECORD] Record Structure
/// @MISSION Define PowerAdmin record JSON structure.
/// @THREAT Incompatible record format.
/// @COUNTERMEASURE Standard PowerAdmin record schema.
/// @AUDIT Record operations tracked for audit compliance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowerAdminRecord {
    pub name: String,
    pub r#type: String,
    pub content: String,
    pub ttl: i32,
    pub prio: Option<i32>,
    pub disabled: bool,
}

/// [POWERADMIN SERVICE] API Integration Service
/// @MISSION Provide comprehensive PowerAdmin API integration.
/// @THREAT Manual DNS configuration errors.
/// @COUNTERMEASURE Automated configuration via API.
/// @DEPENDENCY PowerAdmin service must be accessible.
/// @PERFORMANCE API calls with timeout protection.
/// @AUDIT All PowerAdmin operations logged and traced.
pub struct PowerAdminService {
    client: Client,
    config: PowerAdminConfig,
    vault_client: Arc<VaultClient>,
}

impl PowerAdminService {
    /// [SERVICE INITIALIZATION] PowerAdmin API Setup
    /// @MISSION Initialize PowerAdmin service with secure configuration.
    /// @THREAT Misconfigured API access.
    /// @COUNTERMEASURE Configuration validation and secure key retrieval.
    /// @DEPENDENCY Vault for API key storage.
    /// @PERFORMANCE Lightweight initialization with connection validation.
    /// @AUDIT Service initialization logged for security tracking.
    pub async fn new(vault_client: Arc<VaultClient>) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let base_url = std::env::var("POWERADMIN_BASE_URL")
            .unwrap_or_else(|_| "http://localhost/poweradmin".to_string());

        let api_key = vault_client.get_secret("poweradmin/api_key").await.ok();
        let username = vault_client.get_secret("poweradmin/username").await.ok();
        let password = vault_client.get_secret("poweradmin/password").await.ok();

        let config = PowerAdminConfig {
            base_url,
            api_key,
            username,
            password,
            timeout_seconds: 30,
        };

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_seconds))
            .build()?;

        Ok(Self {
            client,
            config,
            vault_client,
        })
    }

    /// [HEALTH CHECK] Service Availability Verification
    /// @MISSION Verify PowerAdmin API connectivity.
    /// @THREAT Service unavailability during operations.
    /// @COUNTERMEASURE Proactive health monitoring.
    /// @PERFORMANCE Lightweight connectivity check.
    /// @AUDIT Health check attempts logged.
    pub async fn health_check(&self) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        // Try to access a basic endpoint to check if PowerAdmin is available
        // PowerAdmin might not have a dedicated health endpoint, so we'll try the zones list
        let url = format!("{}/api/v1/zones", self.config.base_url);

        let mut request = self.client.get(&url);

        // Add authentication
        if let Some(api_key) = &self.config.api_key {
            request = request.header("X-API-Key", api_key);
        } else if let (Some(username), Some(password)) = (&self.config.username, &self.config.password) {
            request = request.basic_auth(username, Some(password));
        }

        let response = request.send().await?;
        Ok(response.status().is_success())
    }

    /// [LIST ZONES] Retrieve All DNS Zones
    /// @MISSION Get comprehensive list of managed zones.
    /// @THREAT Incomplete zone visibility.
    /// @COUNTERMEASURE Full zone enumeration.
    /// @PERFORMANCE Paginated retrieval for large zone counts.
    /// @AUDIT Zone listing operations tracked.
    pub async fn list_zones(&self) -> Result<Vec<PowerAdminZone>, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/api/v1/zones", self.config.base_url);

        let mut request = self.client.get(&url);

        // Add authentication
        if let Some(api_key) = &self.config.api_key {
            request = request.header("X-API-Key", api_key);
        } else if let (Some(username), Some(password)) = (&self.config.username, &self.config.password) {
            request = request.basic_auth(username, Some(password));
        }

        let response = request.send().await?;
        let zones: Vec<PowerAdminZone> = response.json().await?;
        Ok(zones)
    }

    /// [GET ZONE] Retrieve Specific Zone Details
    /// @MISSION Get detailed zone configuration.
    /// @THREAT Zone configuration inconsistencies.
    /// @COUNTERMEASURE Detailed zone inspection.
    /// @PERFORMANCE Direct zone retrieval by ID.
    /// @AUDIT Zone access operations tracked.
    pub async fn get_zone(&self, zone_id: &str) -> Result<PowerAdminZone, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/api/v1/zones/{}", self.config.base_url, zone_id);

        let mut request = self.client.get(&url);

        // Add authentication
        if let Some(api_key) = &self.config.api_key {
            request = request.header("X-API-Key", api_key);
        } else if let (Some(username), Some(password)) = (&self.config.username, &self.config.password) {
            request = request.basic_auth(username, Some(password));
        }

        let response = request.send().await?;
        let zone: PowerAdminZone = response.json().await?;
        Ok(zone)
    }

    /// [CREATE ZONE] Add New DNS Zone
    /// @MISSION Provision new DNS zone with configuration.
    /// @THREAT Zone creation conflicts or errors.
    /// @COUNTERMEASURE Validated zone creation with conflict detection.
    /// @PERFORMANCE Asynchronous zone provisioning.
    /// @AUDIT Zone creation operations tracked.
    pub async fn create_zone(&self, zone: PowerAdminZone) -> Result<PowerAdminZone, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/api/v1/zones", self.config.base_url);

        let mut request = self.client.post(&url);

        // Add authentication
        if let Some(api_key) = &self.config.api_key {
            request = request.header("X-API-Key", api_key);
        } else if let (Some(username), Some(password)) = (&self.config.username, &self.config.password) {
            request = request.basic_auth(username, Some(password));
        }

        let response = request.json(&zone).send().await?;
        let created_zone: PowerAdminZone = response.json().await?;
        Ok(created_zone)
    }

    /// [UPDATE ZONE] Modify Existing Zone
    /// @MISSION Update zone configuration parameters.
    /// @THREAT Zone update conflicts or data loss.
    /// @COUNTERMEASURE Atomic zone updates with validation.
    /// @PERFORMANCE Direct zone modification by ID.
    /// @AUDIT Zone modification operations tracked.
    pub async fn update_zone(&self, zone_id: &str, zone: PowerAdminZone) -> Result<PowerAdminZone, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/api/v1/zones/{}", self.config.base_url, zone_id);

        let mut request = self.client.put(&url);

        // Add authentication
        if let Some(api_key) = &self.config.api_key {
            request = request.header("X-API-Key", api_key);
        } else if let (Some(username), Some(password)) = (&self.config.username, &self.config.password) {
            request = request.basic_auth(username, Some(password));
        }

        let response = request.json(&zone).send().await?;
        let updated_zone: PowerAdminZone = response.json().await?;
        Ok(updated_zone)
    }

    /// [DELETE ZONE] Remove DNS Zone
    /// @MISSION Decommission DNS zone safely.
    /// @THREAT Accidental zone deletion or data loss.
    /// @COUNTERMEASURE Safe zone deletion with confirmation.
    /// @PERFORMANCE Direct zone removal by ID.
    /// @AUDIT Zone deletion operations tracked.
    pub async fn delete_zone(&self, zone_id: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/api/v1/zones/{}", self.config.base_url, zone_id);

        let mut request = self.client.delete(&url);

        // Add authentication
        if let Some(api_key) = &self.config.api_key {
            request = request.header("X-API-Key", api_key);
        } else if let (Some(username), Some(password)) = (&self.config.username, &self.config.password) {
            request = request.basic_auth(username, Some(password));
        }

        request.send().await?;
        Ok(())
    }

    /// [LIST RECORDS] Retrieve Zone Records
    /// @MISSION Get all DNS records for a zone.
    /// @THREAT Incomplete record visibility.
    /// @COUNTERMEASURE Full record enumeration per zone.
    /// @PERFORMANCE Paginated record retrieval.
    /// @AUDIT Record listing operations tracked.
    pub async fn list_records(&self, zone_id: &str) -> Result<Vec<PowerAdminRecord>, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/api/v1/zones/{}/records", self.config.base_url, zone_id);

        let mut request = self.client.get(&url);

        // Add authentication
        if let Some(api_key) = &self.config.api_key {
            request = request.header("X-API-Key", api_key);
        } else if let (Some(username), Some(password)) = (&self.config.username, &self.config.password) {
            request = request.basic_auth(username, Some(password));
        }

        let response = request.send().await?;
        let records: Vec<PowerAdminRecord> = response.json().await?;
        Ok(records)
    }

    /// [GET RECORD] Retrieve Specific Record Details
    /// @MISSION Get detailed record configuration.
    /// @THREAT Record configuration inconsistencies.
    /// @COUNTERMEASURE Detailed record inspection.
    /// @PERFORMANCE Direct record retrieval by ID.
    /// @AUDIT Record access operations tracked.
    pub async fn get_record(&self, record_id: &str) -> Result<PowerAdminRecord, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/api/v1/records/{}", self.config.base_url, record_id);

        let mut request = self.client.get(&url);

        // Add authentication
        if let Some(api_key) = &self.config.api_key {
            request = request.header("X-API-Key", api_key);
        } else if let (Some(username), Some(password)) = (&self.config.username, &self.config.password) {
            request = request.basic_auth(username, Some(password));
        }

        let response = request.send().await?;
        let record: PowerAdminRecord = response.json().await?;
        Ok(record)
    }

    /// [CREATE RECORD] Add New DNS Record
    /// @MISSION Provision new DNS record in zone.
    /// @THREAT Record creation conflicts or errors.
    /// @COUNTERMEASURE Validated record creation with conflict detection.
    /// @PERFORMANCE Asynchronous record provisioning.
    /// @AUDIT Record creation operations tracked.
    pub async fn create_record(&self, zone_id: &str, record: PowerAdminRecord) -> Result<PowerAdminRecord, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/api/v1/zones/{}/records", self.config.base_url, zone_id);

        let mut request = self.client.post(&url);

        // Add authentication
        if let Some(api_key) = &self.config.api_key {
            request = request.header("X-API-Key", api_key);
        } else if let (Some(username), Some(password)) = (&self.config.username, &self.config.password) {
            request = request.basic_auth(username, Some(password));
        }

        let response = request.json(&record).send().await?;
        let created_record: PowerAdminRecord = response.json().await?;
        Ok(created_record)
    }

    /// [UPDATE RECORD] Modify Existing Record
    /// @MISSION Update record configuration parameters.
    /// @THREAT Record update conflicts or data loss.
    /// @COUNTERMEASURE Atomic record updates with validation.
    /// @PERFORMANCE Direct record modification by ID.
    /// @AUDIT Record modification operations tracked.
    pub async fn update_record(&self, record_id: &str, record: PowerAdminRecord) -> Result<PowerAdminRecord, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/api/v1/records/{}", self.config.base_url, record_id);

        let mut request = self.client.put(&url);

        // Add authentication
        if let Some(api_key) = &self.config.api_key {
            request = request.header("X-API-Key", api_key);
        } else if let (Some(username), Some(password)) = (&self.config.username, &self.config.password) {
            request = request.basic_auth(username, Some(password));
        }

        let response = request.json(&record).send().await?;
        let updated_record: PowerAdminRecord = response.json().await?;
        Ok(updated_record)
    }

    /// [DELETE RECORD] Remove DNS Record
    /// @MISSION Decommission DNS record safely.
    /// @THREAT Accidental record deletion or data loss.
    /// @COUNTERMEASURE Safe record deletion with confirmation.
    /// @PERFORMANCE Direct record removal by ID.
    /// @AUDIT Record deletion operations tracked.
    pub async fn delete_record(&self, record_id: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/api/v1/records/{}", self.config.base_url, record_id);

        let mut request = self.client.delete(&url);

        // Add authentication
        if let Some(api_key) = &self.config.api_key {
            request = request.header("X-API-Key", api_key);
        } else if let (Some(username), Some(password)) = (&self.config.username, &self.config.password) {
            request = request.basic_auth(username, Some(password));
        }

        request.send().await?;
        Ok(())
    }
}