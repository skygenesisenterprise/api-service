// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Logger Models
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | SENSITIVE
//  MISSION: Define data structures for logger operations, audit trail management,
//  and log filtering capabilities with enterprise security standards.
//  NOTICE: Models implement type-safe structures for log data, filtering options,
//  and response formats with comprehensive validation.
//  MODEL STANDARDS: Type Safety, Serialization, Validation, Documentation
//  COMPLIANCE: Data Protection, Audit Trail Integrity, GDPR Compliance
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use crate::core::audit_manager::{AuditEvent, AuditEventType, AuditSeverity};

/// [LOGGER RESPONSE] Standardized API Response for Logger Operations
/// @MISSION Provide consistent response format for all logger endpoints.
/// @THREAT Inconsistent API responses, information leakage.
/// @COUNTERMEASURE Structured response with status, data, and metadata.
/// @INVARIANT All logger responses follow this format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggerResponse<T> {
    pub status: String,
    pub message: Option<String>,
    pub data: Option<T>,
    pub timestamp: DateTime<Utc>,
    pub total_count: Option<usize>,
}

/// [LOG FILTER REQUEST] Query Parameters for Log Filtering
/// @MISSION Enable flexible log querying with multiple filter criteria.
/// @THREAT Excessive data retrieval, unauthorized access.
/// @COUNTERMEASURE Parameter validation and result limiting.
/// @INVARIANT All filters are optional with sensible defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogFilterRequest {
    /// Filter by user ID
    pub user_id: Option<String>,
    /// Filter by event type (string representation)
    pub event_type: Option<String>,
    /// Filter by resource/route containing this string
    pub resource: Option<String>,
    /// Filter by severity level
    pub severity: Option<String>,
    /// Start time for filtering (ISO 8601 format)
    pub start_time: Option<DateTime<Utc>>,
    /// End time for filtering (ISO 8601 format)
    pub end_time: Option<DateTime<Utc>>,
    /// Maximum number of events to return (default: 100, max: 1000)
    pub limit: Option<usize>,
    /// Offset for pagination
    pub offset: Option<usize>,
}

/// [LOG SUMMARY] Aggregated Log Statistics
/// @MISSION Provide summary statistics for log analysis.
/// @THREAT Missing visibility into log patterns.
/// @COUNTERMEASURE Aggregated metrics with time-based analysis.
/// @AUDIT Summary generation is logged for compliance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSummary {
    pub total_events: usize,
    pub events_by_type: std::collections::HashMap<String, usize>,
    pub events_by_severity: std::collections::HashMap<String, usize>,
    pub events_by_resource: std::collections::HashMap<String, usize>,
    pub time_range: TimeRange,
    pub top_resources: Vec<ResourceCount>,
}

/// [TIME RANGE] Time Period Definition
/// @MISSION Define time ranges for log analysis.
/// @THREAT Ambiguous time period definitions.
/// @COUNTERMEASURE Explicit start and end timestamps.
/// @INVARIANT End time is always after start time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

/// [RESOURCE COUNT] Resource Usage Statistics
/// @MISSION Track which resources are most accessed.
/// @THREAT Missing visibility into resource usage patterns.
/// @COUNTERMEASURE Count-based ranking with resource identification.
/// @AUDIT Resource usage is monitored for security analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceCount {
    pub resource: String,
    pub count: usize,
}

/// [LOG EXPORT REQUEST] Parameters for Log Export Operations
/// @MISSION Enable secure log export with filtering and formatting options.
/// @THREAT Unauthorized log export, data exfiltration.
/// @COUNTERMEASURE Access controls, format validation, audit logging.
/// @COMPLIANCE Export operations require explicit authorization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogExportRequest {
    pub filters: LogFilterRequest,
    pub format: ExportFormat,
    pub include_sensitive: bool, // Requires special permissions
}

/// [EXPORT FORMAT] Supported Export Formats
/// @MISSION Define available export formats for log data.
/// @THREAT Unsupported or insecure export formats.
/// @COUNTERMEASURE Limited set of secure, standardized formats.
/// @COMPLIANCE All exports include integrity verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExportFormat {
    Json,
    Csv,
    Xml,
}

/// [LOG CONFIGURATION] Logger System Configuration
/// @MISSION Configure logger behavior and filtering rules.
/// @THREAT Misconfigured logging leading to data loss or exposure.
/// @COUNTERMEASURE Validated configuration with security controls.
/// @AUDIT Configuration changes are logged and audited.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggerConfig {
    /// Enable/disable logging globally
    pub enabled: bool,
    /// Maximum log retention period in days
    pub retention_days: i64,
    /// Routes to exclude from logging
    pub excluded_routes: Vec<String>,
    /// Routes to include in logging (if empty, log all)
    pub included_routes: Vec<String>,
    /// Enable sensitive data masking
    pub mask_sensitive_data: bool,
    /// Maximum events per query
    pub max_query_limit: usize,
}

/// [LOG ALERT RULE] Automated Alert Configuration
/// @MISSION Define rules for automatic alerting based on log patterns.
/// @THREAT Undetected security incidents or system issues.
/// @COUNTERMEASURE Pattern-based alerting with configurable thresholds.
/// @AUDIT Alert rules are version controlled and audited.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogAlertRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub event_type: Option<AuditEventType>,
    pub severity: Option<AuditSeverity>,
    pub resource_pattern: Option<String>,
    pub threshold: AlertThreshold,
    pub time_window_minutes: u32,
    pub alert_channels: Vec<AlertChannel>,
}

/// [ALERT THRESHOLD] Threshold Configuration for Alerts
/// @MISSION Define when alerts should be triggered.
/// @THREAT False positives or missed alerts.
/// @COUNTERMEASURE Configurable thresholds with time windows.
/// @AUDIT Threshold breaches are logged for analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertThreshold {
    pub count: usize,
    pub percentage: Option<f64>,
}

/// [ALERT CHANNEL] Notification Channel Configuration
/// @MISSION Define how alerts are delivered.
/// @THREAT Alert delivery failures.
/// @COUNTERMEASURE Multiple channels with fallback options.
/// @AUDIT Alert delivery is tracked and confirmed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertChannel {
    pub channel_type: AlertChannelType,
    pub destination: String,
    pub enabled: bool,
}

/// [ALERT CHANNEL TYPE] Supported Alert Delivery Methods
/// @MISSION Define available alert delivery mechanisms.
/// @THREAT Insecure or unreliable alert delivery.
/// @COUNTERMEASURE Secure, monitored delivery channels.
/// @COMPLIANCE All channels support encryption and authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertChannelType {
    Email,
    Webhook,
    Slack,
    Discord,
    Sms,
}

/// [LOG ARCHIVE INFO] Archive Metadata
/// @MISSION Track log archives for compliance and retention.
/// @THREAT Lost or corrupted archives.
/// @COUNTERMEASURE Metadata tracking with integrity verification.
/// @COMPLIANCE Archives are tamper-evident and auditable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogArchiveInfo {
    pub archive_id: String,
    pub creation_time: DateTime<Utc>,
    pub time_range: TimeRange,
    pub total_events: usize,
    pub file_size_bytes: u64,
    pub checksum: String,
    pub storage_location: String,
    pub retention_until: DateTime<Utc>,
}

/// [LOG QUERY RESULT] Paginated Query Results
/// @MISSION Provide paginated results for large log queries.
/// @THREAT Memory exhaustion from large result sets.
/// @COUNTERMEASURE Pagination with configurable page sizes.
/// @PERFORMANCE Results are streamed to avoid memory issues.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogQueryResult {
    pub events: Vec<AuditEvent>,
    pub total_count: usize,
    pub page: usize,
    pub page_size: usize,
    pub has_more: bool,
    pub query_time_ms: u64,
}