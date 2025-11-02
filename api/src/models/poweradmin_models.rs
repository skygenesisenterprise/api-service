// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: PowerAdmin Models
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | SENSITIVE
//  MISSION: Define data structures and models for PowerAdmin DNS integration,
//  providing type-safe representations of zones, records, DNSSEC keys,
//  and DNS operations within the enterprise DNS infrastructure.
//  NOTICE: Models implement serialization, validation, and type safety for
//  all PowerAdmin-related data structures with enterprise security standards.
//  MODEL STANDARDS: Type Safety, Serialization, Validation, Documentation
//  COMPLIANCE: DNS Standards, Data Protection, API Standards
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// [DNS ZONE MODEL] Complete Zone Representation
/// @MISSION Define the structure of a DNS zone.
/// @THREAT Inconsistent zone data structures.
/// @COUNTERMEASURE Standardized zone model with validation.
/// @AUDIT Zone models used for audit logging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsZone {
    pub id: Option<String>,
    pub name: String,
    pub r#type: String, // MASTER, SLAVE, NATIVE
    pub nameservers: Vec<String>,
    pub serial: Option<i64>,
    pub refresh: Option<i32>,
    pub retry: Option<i32>,
    pub expire: Option<i32>,
    pub minimum: Option<i32>,
    pub ttl: Option<i32>,
    pub owner: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub dnssec_enabled: bool,
    pub template_name: Option<String>,
}

/// [DNS RECORD MODEL] Individual DNS Record Representation
/// @MISSION Define the structure of a DNS record.
/// @THREAT Malformed record configurations.
/// @COUNTERMEASURE Structured record model with type safety.
/// @AUDIT Record configurations audited.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub id: Option<String>,
    pub zone_id: String,
    pub name: String,
    pub r#type: String,
    pub content: String,
    pub ttl: i32,
    pub prio: Option<i32>,
    pub disabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub comment: Option<String>,
}

/// [DNSSEC KEY MODEL] DNS Security Extensions Key
/// @MISSION Define DNSSEC key structures.
/// @THREAT Weak or compromised DNSSEC keys.
/// @COUNTERMEASURE Secure key management structures.
/// @AUDIT DNSSEC key operations audited.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnssecKey {
    pub id: String,
    pub zone_id: String,
    pub key_type: String, // KSK, ZSK
    pub algorithm: String,
    pub key_size: i32,
    pub public_key: String,
    pub private_key_path: String, // Vault path for private key
    pub key_tag: i32,
    pub status: String, // ACTIVE, INACTIVE, PUBLISHED
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub activated_at: Option<chrono::DateTime<chrono::Utc>>,
    pub inactivated_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// [DNS OPERATION LOG MODEL] Audit Trail for DNS Operations
/// @MISSION Track all DNS operations for compliance.
/// @THREAT Undetected DNS configuration changes.
/// @COUNTERMEASURE Comprehensive operation logging.
/// @AUDIT DNS operations tracked for compliance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsOperationLog {
    pub id: String,
    pub operation: String, // CREATE, UPDATE, DELETE
    pub resource_type: String, // ZONE, RECORD, KEY
    pub resource_id: String,
    pub resource_name: String,
    pub user_id: String,
    pub organization_id: String,
    pub old_value: Option<serde_json::Value>,
    pub new_value: Option<serde_json::Value>,
    pub ip_address: String,
    pub user_agent: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub success: bool,
    pub error_message: Option<String>,
}

/// [DNS ZONE TEMPLATE MODEL] Reusable Zone Configurations
/// @MISSION Define zone templates for rapid deployment.
/// @THREAT Inconsistent zone setups.
/// @COUNTERMEASURE Template-based zone creation.
/// @AUDIT Template usage tracked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsZoneTemplate {
    pub id: String,
    pub name: String,
    pub description: String,
    pub zone_type: String,
    pub default_ttl: i32,
    pub nameservers: Vec<String>,
    pub soa_config: DnsSoaConfig,
    pub default_records: Vec<DnsRecordTemplate>,
    pub dnssec_config: Option<DnssecConfig>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// [DNS RECORD TEMPLATE MODEL] Reusable Record Patterns
/// @MISSION Define record templates with placeholders.
/// @THREAT Manual record creation errors.
/// @COUNTERMEASURE Template-based record generation.
/// @AUDIT Template usage tracked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecordTemplate {
    pub id: String,
    pub template_id: String,
    pub name_pattern: String,
    pub record_type: String,
    pub content_pattern: String,
    pub ttl: i32,
    pub priority: Option<i32>,
    pub disabled: bool,
    pub description: String,
}

/// [DNS SOA CONFIG MODEL] Start of Authority Configuration
/// @MISSION Define SOA record parameters.
/// @THREAT Incorrect SOA configuration.
/// @COUNTERMEASURE Structured SOA configuration.
/// @AUDIT SOA changes tracked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsSoaConfig {
    pub primary_ns: String,
    pub contact: String,
    pub serial: i64,
    pub refresh: i32,
    pub retry: i32,
    pub expire: i32,
    pub minimum: i32,
}

/// [DNSSEC CONFIG MODEL] DNSSEC Configuration
/// @MISSION Define DNSSEC settings for zones.
/// @THREAT DNS security vulnerabilities.
/// @COUNTERMEASURE Secure DNSSEC configuration.
/// @AUDIT DNSSEC config changes tracked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnssecConfig {
    pub enabled: bool,
    pub algorithm: String,
    pub key_size: i32,
    pub zsk_rollover_period: String,
    pub ksk_rollover_period: String,
    pub nsec3_enabled: bool,
    pub nsec3_iterations: Option<i32>,
    pub nsec3_salt: Option<String>,
}

/// [DNS VALIDATION RULE MODEL] Record Validation Rules
/// @MISSION Define validation rules for record types.
/// @THREAT Invalid DNS records.
/// @COUNTERMEASURE Type-specific validation.
/// @AUDIT Validation rules audited.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsValidationRule {
    pub record_type: String,
    pub content_pattern: String,
    pub name_pattern: Option<String>,
    pub required_fields: Vec<String>,
    pub max_length: Option<i32>,
    pub custom_validation: Option<String>,
}

/// [DNS ZONE TRANSFER MODEL] Zone Transfer Configuration
/// @MISSION Define zone transfer settings.
/// @THREAT Unauthorized zone transfers.
/// @COUNTERMEASURE Secure transfer configuration.
/// @AUDIT Transfer settings audited.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsZoneTransfer {
    pub zone_id: String,
    pub transfer_type: String, // AXFR, IXFR
    pub allowed_servers: Vec<String>,
    pub tsig_key_name: Option<String>,
    pub tsig_key_path: Option<String>, // Vault path
    pub enabled: bool,
}

/// [DNS MONITORING MODEL] Zone and Record Monitoring
/// @MISSION Define monitoring settings for DNS.
/// @THREAT Undetected DNS issues.
/// @COUNTERMEASURE Proactive monitoring.
/// @AUDIT Monitoring configurations tracked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsMonitoring {
    pub zone_id: Option<String>,
    pub record_id: Option<String>,
    pub monitoring_type: String, // HEALTH, RESOLUTION, TRANSFER
    pub check_interval: i32,
    pub alert_threshold: i32,
    pub alert_channels: Vec<String>,
    pub enabled: bool,
    pub last_check: Option<chrono::DateTime<chrono::Utc>>,
    pub last_status: Option<String>,
}

/// [DNS BACKUP MODEL] Zone Backup Configuration
/// @MISSION Define backup settings for DNS zones.
/// @THREAT Data loss from DNS configuration.
/// @COUNTERMEASURE Regular backups.
/// @AUDIT Backup operations tracked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsBackup {
    pub zone_id: String,
    pub backup_type: String, // FULL, INCREMENTAL
    pub schedule: String, // cron expression
    pub retention_days: i32,
    pub storage_path: String,
    pub encryption_enabled: bool,
    pub last_backup: Option<chrono::DateTime<chrono::Utc>>,
    pub next_backup: Option<chrono::DateTime<chrono::Utc>>,
}

/// [DNS API RESPONSE MODEL] Standardized API Responses
/// @MISSION Define consistent API response formats.
/// @THREAT Inconsistent API responses.
/// @COUNTERMEASURE Standardized response models.
/// @AUDIT API responses logged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<DnsApiError>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub request_id: String,
}

/// [DNS API ERROR MODEL] Error Response Structure
/// @MISSION Define error response formats.
/// @THREAT Information leakage through errors.
/// @COUNTERMEASURE Sanitized error responses.
/// @AUDIT Errors logged for monitoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsApiError {
    pub code: String,
    pub message: String,
    pub details: Option<HashMap<String, serde_json::Value>>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// [DNS BULK OPERATION MODEL] Batch DNS Operations
/// @MISSION Define batch operation structures.
/// @THREAT Individual operation overhead.
/// @COUNTERMEASURE Batch processing.
/// @AUDIT Batch operations tracked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsBulkOperation {
    pub operation_type: String, // CREATE, UPDATE, DELETE
    pub resource_type: String, // ZONE, RECORD
    pub operations: Vec<DnsBulkOperationItem>,
    pub continue_on_error: bool,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// [DNS BULK OPERATION ITEM MODEL] Individual Batch Operation
/// @MISSION Define individual batch operation items.
/// @THREAT Batch operation failures.
/// @COUNTERMEASURE Item-level error handling.
/// @AUDIT Individual operations tracked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsBulkOperationItem {
    pub id: String,
    pub data: serde_json::Value,
    pub status: String, // PENDING, PROCESSING, COMPLETED, FAILED
    pub error_message: Option<String>,
    pub processed_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// [DNS STATISTICS MODEL] DNS Operation Statistics
/// @MISSION Track DNS operation metrics.
/// @THREAT Lack of visibility into DNS operations.
/// @COUNTERMEASURE Comprehensive statistics.
/// @AUDIT Statistics used for monitoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsStatistics {
    pub total_zones: i64,
    pub total_records: i64,
    pub zones_created_today: i64,
    pub records_modified_today: i64,
    pub failed_operations_today: i64,
    pub average_response_time: f64,
    pub dnssec_enabled_zones: i64,
    pub monitored_zones: i64,
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

/// [DNS PERMISSION MODEL] Access Control for DNS Resources
/// @MISSION Define permissions for DNS operations.
/// @THREAT Unauthorized DNS access.
/// @COUNTERMEASURE Granular permissions.
/// @AUDIT Permission checks logged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsPermission {
    pub user_id: String,
    pub resource_type: String, // ZONE, RECORD, TEMPLATE
    pub resource_id: Option<String>,
    pub permissions: Vec<String>, // READ, WRITE, DELETE, ADMIN
    pub granted_by: String,
    pub granted_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}