// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Logger Utilities
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | SENSITIVE
//  MISSION: Provide utility functions for logger operations, including
//  data formatting, validation helpers, and common operations.
//  NOTICE: Utilities implement common patterns and helper functions
//  for logger functionality with enterprise security standards.
//  UTILITY STANDARDS: Pure functions, error handling, performance
//  COMPLIANCE: Data protection, security best practices
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use chrono::{DateTime, Utc, Duration};
use regex::Regex;
use std::collections::HashMap;
use crate::core::audit_manager::{AuditEvent, AuditEventType, AuditSeverity};
use crate::models::logger_model::{LogFilterRequest, TimeRange};

/// [LOG PARSING UTILITIES] Event Data Extraction and Validation
/// @MISSION Provide utilities for parsing and validating log data.
/// @THREAT Malformed log data, parsing errors, security vulnerabilities.
/// @COUNTERMEASURE Robust parsing, validation, sanitization.
/// @INVARIANT All parsing operations are safe and validated.
/// @AUDIT Parsing operations are logged for debugging.

/// Extract resource path from HTTP request path
/// @MISSION Parse and normalize API resource paths.
/// @THREAT Path traversal attacks, malformed paths.
/// @COUNTERMEASURE Path validation, normalization, sanitization.
/// @INVARIANT Paths are validated and safe for processing.
pub fn extract_resource_path(path: &str) -> Result<String, LoggerUtilsError> {
    if path.is_empty() {
        return Err(LoggerUtilsError::ValidationError("Path cannot be empty".to_string()));
    }

    // Remove query parameters
    let path = path.split('?').next().unwrap_or(path);

    // Validate path starts with /
    if !path.starts_with('/') {
        return Err(LoggerUtilsError::ValidationError("Path must start with /".to_string()));
    }

    // Basic path traversal protection
    if path.contains("..") || path.contains("//") {
        return Err(LoggerUtilsError::SecurityError("Invalid path structure".to_string()));
    }

    Ok(path.to_string())
}

/// Parse severity level from string
/// @MISSION Convert string severity to enum with validation.
/// @THREAT Invalid severity values, type confusion.
/// @COUNTERMEASURE Strict validation, default fallbacks.
/// @INVARIANT Invalid severities default to Low.
pub fn parse_severity(severity_str: &str) -> AuditSeverity {
    match severity_str.to_lowercase().as_str() {
        "critical" => AuditSeverity::Critical,
        "high" => AuditSeverity::High,
        "medium" => AuditSeverity::Medium,
        "low" => AuditSeverity::Low,
        _ => AuditSeverity::Low, // Default to Low for invalid values
    }
}

/// Parse event type from string
/// @MISSION Convert string event type to enum with validation.
/// @THREAT Invalid event types, type confusion.
/// @COUNTERMEASURE Strict validation, case-insensitive matching.
/// @INVARIANT Invalid types return error.
pub fn parse_event_type(event_type_str: &str) -> Result<AuditEventType, LoggerUtilsError> {
    match event_type_str.to_lowercase().as_str() {
        "login_success" | "loginsuccess" => Ok(AuditEventType::LoginSuccess),
        "login_failure" | "loginfailure" => Ok(AuditEventType::LoginFailure),
        "logout" => Ok(AuditEventType::Logout),
        "api_request" | "apirequest" => Ok(AuditEventType::ApiRequest),
        "mail_sent" | "mailsent" => Ok(AuditEventType::MailSent),
        "service_started" | "servicestarted" => Ok(AuditEventType::ServiceStarted),
        _ => Err(LoggerUtilsError::ValidationError(format!("Unknown event type: {}", event_type_str))),
    }
}

/// [FILTER UTILITIES] Query Filter Processing
/// @MISSION Provide utilities for processing and optimizing log filters.
/// @THREAT Inefficient queries, excessive data retrieval.
/// @COUNTERMEASURE Filter optimization, validation, sanitization.
/// @INVARIANT Filters are validated and optimized for performance.

/// Validate and sanitize filter request
/// @MISSION Ensure filter parameters are safe and reasonable.
/// @THREAT Malicious filter parameters, performance issues.
/// @COUNTERMEASURE Parameter validation, limits enforcement.
/// @INVARIANT Invalid parameters are rejected or sanitized.
pub fn validate_filter_request(mut filters: LogFilterRequest) -> Result<LogFilterRequest, LoggerUtilsError> {
    // Validate limit
    if let Some(limit) = filters.limit {
        if limit > 10000 {
            return Err(LoggerUtilsError::ValidationError("Limit cannot exceed 10000".to_string()));
        }
        if limit <= 0 {
            filters.limit = Some(100); // Default
        }
    } else {
        filters.limit = Some(100); // Default
    }

    // Validate offset
    if let Some(offset) = filters.offset {
        if offset < 0 {
            filters.offset = Some(0); // Default
        }
    }

    // Validate time range
    if let (Some(start), Some(end)) = (filters.start_time, filters.end_time) {
        if start >= end {
            return Err(LoggerUtilsError::ValidationError("Start time must be before end time".to_string()));
        }
        if end - start > Duration::days(365) {
            return Err(LoggerUtilsError::ValidationError("Time range cannot exceed 365 days".to_string()));
        }
    }

    // Validate resource pattern
    if let Some(ref resource) = filters.resource {
        if resource.len() > 500 {
            return Err(LoggerUtilsError::ValidationError("Resource filter too long".to_string()));
        }
        // Basic SQL injection protection
        if resource.contains("'") || resource.contains(";") {
            return Err(LoggerUtilsError::SecurityError("Invalid characters in resource filter".to_string()));
        }
    }

    Ok(filters)
}

/// Create default time range for queries
/// @MISSION Provide sensible default time ranges.
/// @THREAT Missing time bounds leading to excessive queries.
/// @COUNTERMEASURE Reasonable defaults with configuration.
/// @INVARIANT Defaults provide bounded, reasonable ranges.
pub fn create_default_time_range() -> TimeRange {
    let end = Utc::now();
    let start = end - Duration::days(30); // Last 30 days by default

    TimeRange { start, end }
}

/// [DATA FORMATTING UTILITIES] Output Formatting and Sanitization
/// @MISSION Provide utilities for formatting log data for output.
/// @THREAT Data exposure, formatting errors, security issues.
/// @COUNTERMEASURE Data sanitization, safe formatting, validation.
/// @INVARIANT Output is safe and properly formatted.

/// Sanitize string for CSV output
/// @MISSION Escape special characters in CSV data.
/// @THREAT CSV injection attacks, malformed output.
/// @COUNTERMEASURE Character escaping, validation.
/// @INVARIANT CSV output is safe and valid.
pub fn sanitize_for_csv(input: &str) -> String {
    if input.contains(',') || input.contains('"') || input.contains('\n') {
        format!("\"{}\"", input.replace("\"", "\"\""))
    } else {
        input.to_string()
    }
}

/// Format timestamp for display
/// @MISSION Provide consistent timestamp formatting.
/// @THREAT Inconsistent time display, parsing errors.
/// @COUNTERMEASURE Standardized ISO 8601 formatting.
/// @INVARIANT Timestamps are consistently formatted.
pub fn format_timestamp(timestamp: &DateTime<Utc>) -> String {
    timestamp.to_rfc3339()
}

/// Truncate long strings for display
/// @MISSION Prevent overly long output in logs and displays.
/// @THREAT UI issues, performance problems from long strings.
/// @COUNTERMEASURE Configurable truncation with indicators.
/// @INVARIANT Long strings are safely truncated.
pub fn truncate_string(input: &str, max_length: usize) -> String {
    if input.len() <= max_length {
        input.to_string()
    } else {
        format!("{}... [TRUNCATED]", &input[..max_length.saturating_sub(16)])
    }
}

/// [STATISTICS UTILITIES] Log Analysis and Metrics
/// @MISSION Provide utilities for analyzing log data and generating metrics.
/// @THREAT Incorrect statistics, performance issues.
/// @COUNTERMEASURE Efficient algorithms, validation, caching.
/// @INVARIANT Statistics are accurate and efficiently computed.

/// Calculate events per time period
/// @MISSION Compute event frequency metrics.
/// @THREAT Incorrect time-based calculations.
/// @COUNTERMEASURE Proper time arithmetic, validation.
/// @INVARIANT Calculations handle edge cases correctly.
pub fn calculate_events_per_period(events: &[AuditEvent], period_hours: i64) -> HashMap<String, usize> {
    let mut period_counts = HashMap::new();
    let period_duration = Duration::hours(period_hours);

    for event in events {
        let period_start = event.timestamp.timestamp() / (period_duration.num_seconds()) * period_duration.num_seconds();
        let period_key = format!("period_{}", period_start);

        *period_counts.entry(period_key).or_insert(0) += 1;
    }

    period_counts
}

/// Find most active resources
/// @MISSION Identify frequently accessed resources.
/// @THREAT Missing visibility into resource usage.
/// @COUNTERMEASURE Efficient counting and ranking.
/// @INVARIANT Results are accurately ranked.
pub fn find_most_active_resources(events: &[AuditEvent], limit: usize) -> Vec<(String, usize)> {
    let mut resource_counts = HashMap::new();

    for event in events {
        *resource_counts.entry(event.resource.clone()).or_insert(0) += 1;
    }

    let mut sorted: Vec<(String, usize)> = resource_counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));

    sorted.into_iter().take(limit).collect()
}

/// [VALIDATION UTILITIES] Input Validation and Sanitization
/// @MISSION Provide comprehensive input validation.
/// @THREAT Malformed input, security vulnerabilities.
/// @COUNTERMEASURE Regex validation, length checks, sanitization.
/// @INVARIANT All input is validated and safe.

/// Validate user ID format
/// @MISSION Ensure user IDs follow expected format.
/// @THREAT Malformed user identifiers, injection attacks.
/// @COUNTERMEASURE Format validation, length limits.
/// @INVARIANT User IDs are properly formatted.
pub fn validate_user_id(user_id: &str) -> Result<(), LoggerUtilsError> {
    if user_id.is_empty() {
        return Err(LoggerUtilsError::ValidationError("User ID cannot be empty".to_string()));
    }

    if user_id.len() > 100 {
        return Err(LoggerUtilsError::ValidationError("User ID too long".to_string()));
    }

    // Allow alphanumeric, hyphens, underscores, and dots
    let user_id_regex = Regex::new(r"^[a-zA-Z0-9._-]+$").unwrap();
    if !user_id_regex.is_match(user_id) {
        return Err(LoggerUtilsError::ValidationError("Invalid user ID format".to_string()));
    }

    Ok(())
}

/// Validate resource path format
/// @MISSION Ensure resource paths are safe and valid.
/// @THREAT Path traversal, malformed paths.
/// @COUNTERMEASURE Path validation, character restrictions.
/// @INVARIANT Resource paths are safe for processing.
pub fn validate_resource_path(path: &str) -> Result<(), LoggerUtilsError> {
    if path.is_empty() || !path.starts_with('/') {
        return Err(LoggerUtilsError::ValidationError("Invalid resource path format".to_string()));
    }

    if path.len() > 1000 {
        return Err(LoggerUtilsError::ValidationError("Resource path too long".to_string()));
    }

    // Check for dangerous patterns
    if path.contains("..") || path.contains("//") || path.contains('\0') {
        return Err(LoggerUtilsError::SecurityError("Unsafe path characters detected".to_string()));
    }

    Ok(())
}

/// [ERROR HANDLING] Comprehensive Error Types
/// @MISSION Provide detailed error classification for logger utilities.
/// @THREAT Generic errors, information leakage.
/// @COUNTERMEASURE Specific error types, safe error messages.
/// @INVARIANT Errors provide appropriate detail without security risks.
#[derive(Debug)]
pub enum LoggerUtilsError {
    ValidationError(String),
    SecurityError(String),
    FormatError(String),
    ParseError(String),
}

impl std::fmt::Display for LoggerUtilsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoggerUtilsError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            LoggerUtilsError::SecurityError(msg) => write!(f, "Security error: {}", msg),
            LoggerUtilsError::FormatError(msg) => write!(f, "Format error: {}", msg),
            LoggerUtilsError::ParseError(msg) => write!(f, "Parse error: {}", msg),
        }
    }
}

impl std::error::Error for LoggerUtilsError {}

/// [TEST UTILITIES] Helper Functions for Testing
/// @MISSION Provide utilities for testing logger functionality.
/// @THREAT Inadequate test coverage, test data issues.
/// @COUNTERMEASURE Test data generation, validation helpers.
/// @INVARIANT Test utilities are safe and comprehensive.
#[cfg(test)]
pub mod test_utils {
    use super::*;
    use crate::core::audit_manager::AuditEvent;

    /// Generate test audit events
    /// @MISSION Create realistic test data for testing.
    /// @THREAT Unrealistic test data leading to false results.
    /// @COUNTERMEASURE Varied, realistic test event generation.
    /// @INVARIANT Test data covers various scenarios.
    pub fn generate_test_events(count: usize) -> Vec<AuditEvent> {
        (0..count).map(|i| {
            let severity = match i % 4 {
                0 => AuditSeverity::Low,
                1 => AuditSeverity::Medium,
                2 => AuditSeverity::High,
                _ => AuditSeverity::Critical,
            };

            let event_type = match i % 6 {
                0 => AuditEventType::ApiRequest,
                1 => AuditEventType::LoginSuccess,
                2 => AuditEventType::LoginFailure,
                3 => AuditEventType::MailSent,
                4 => AuditEventType::ServiceStarted,
                _ => AuditEventType::Logout,
            };

            AuditEvent::new(
                event_type,
                severity,
                Some(&crate::models::user::User {
                    id: format!("user_{}", i % 10),
                    tenant_id: "test_tenant".to_string(),
                    username: format!("testuser{}", i % 10),
                    email: format!("user{}@test.com", i % 10),
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                    is_active: true,
                    role: "user".to_string(),
                }),
                format!("/api/v1/resource/{}", i),
                format!("action_{}", i % 5),
                if i % 3 == 0 { "success" } else { "failure" }.to_string(),
                serde_json::json!({
                    "test_id": i,
                    "data": format!("test_data_{}", i),
                    "metadata": {
                        "source": "test",
                        "version": "1.0"
                    }
                }),
            )
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_resource_path() {
        assert_eq!(extract_resource_path("/api/v1/users").unwrap(), "/api/v1/users");
        assert_eq!(extract_resource_path("/api/v1/users?query=test").unwrap(), "/api/v1/users");
        assert!(extract_resource_path("").is_err());
        assert!(extract_resource_path("api/v1/users").is_err());
        assert!(extract_resource_path("/api/../../../etc/passwd").is_err());
    }

    #[test]
    fn test_parse_severity() {
        assert!(matches!(parse_severity("low"), AuditSeverity::Low));
        assert!(matches!(parse_severity("HIGH"), AuditSeverity::High));
        assert!(matches!(parse_severity("invalid"), AuditSeverity::Low)); // Default
    }

    #[test]
    fn test_validate_filter_request() {
        let valid_filters = LogFilterRequest {
            user_id: Some("user123".to_string()),
            event_type: None,
            resource: Some("/api/v1/test".to_string()),
            severity: None,
            start_time: Some(Utc::now() - Duration::hours(1)),
            end_time: Some(Utc::now()),
            limit: Some(50),
            offset: None,
        };

        assert!(validate_filter_request(valid_filters).is_ok());

        let invalid_filters = LogFilterRequest {
            user_id: None,
            event_type: None,
            resource: None,
            severity: None,
            start_time: Some(Utc::now()),
            end_time: Some(Utc::now() - Duration::hours(1)), // Start after end
            limit: Some(50),
            offset: None,
        };

        assert!(validate_filter_request(invalid_filters).is_err());
    }

    #[test]
    fn test_sanitize_for_csv() {
        assert_eq!(sanitize_for_csv("simple"), "simple");
        assert_eq!(sanitize_for_csv("has,comma"), "\"has,comma\"");
        assert_eq!(sanitize_for_csv("has\"quote"), "\"has\"\"quote\"");
    }

    #[test]
    fn test_validate_user_id() {
        assert!(validate_user_id("user123").is_ok());
        assert!(validate_user_id("user.name_123").is_ok());
        assert!(validate_user_id("").is_err());
        assert!(validate_user_id("user@domain.com").is_err()); // Invalid character
    }
}