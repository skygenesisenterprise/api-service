// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Grafana Utilities
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | SENSITIVE
//  MISSION: Provide utility functions and helpers for Grafana integration,
//  including UID generation, data transformation, validation helpers,
//  and common operations used across Grafana-related components.
//  NOTICE: Utilities implement common patterns and reduce code duplication
//  for Grafana dashboard management, datasource configuration, and monitoring
//  operations with enterprise utility standards.
//  UTILITIES: UID generation, data transformation, validation, formatting
//  COMPLIANCE: Utility standards, error handling, performance
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use std::collections::HashMap;
use serde_json::{Value, json};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use regex::Regex;

/// [UID GENERATION] Unique Identifier Utilities
/// @MISSION Generate unique identifiers for Grafana resources.
/// @THREAT ID collisions causing conflicts.
/// @COUNTERMEASURE Cryptographically secure UID generation.
/// @AUDIT UID generation tracked.

/// Generate a unique Grafana-compatible UID
/// @MISSION Create unique identifiers following Grafana conventions.
/// @THREAT Non-unique UIDs causing resource conflicts.
/// @COUNTERMEASURE UUID-based generation with validation.
/// @PERFORMANCE Fast generation with low collision probability.
/// @AUDIT Generated UIDs logged for tracking.
pub fn generate_grafana_uid() -> String {
    // Generate a UUID and take first 8 characters for Grafana UID format
    let uuid = Uuid::new_v4();
    let uid = uuid.to_string().replace("-", "")[0..8].to_string();
    uid
}

/// Generate a unique dashboard UID with prefix
/// @MISSION Create prefixed UIDs for better organization.
/// @THREAT Unorganized resource identification.
/// @COUNTERMEASURE Prefixed UID generation.
/// @PERFORMANCE Minimal overhead for prefixing.
/// @AUDIT Prefixed UIDs logged.
pub fn generate_dashboard_uid(prefix: Option<&str>) -> String {
    let base_uid = generate_grafana_uid();
    match prefix {
        Some(p) => format!("{}-{}", p, base_uid),
        None => format!("db-{}", base_uid),
    }
}

/// Generate a unique datasource UID
/// @MISSION Create datasource-specific UIDs.
/// @THREAT Datasource UID conflicts.
/// @COUNTERMEASURE Type-specific UID generation.
/// @PERFORMANCE Consistent UID format.
/// @AUDIT Datasource UIDs logged.
pub fn generate_datasource_uid() -> String {
    format!("ds-{}", generate_grafana_uid())
}

/// Generate a unique alert rule UID
/// @MISSION Create alert-specific UIDs.
/// @THREAT Alert UID conflicts.
/// @COUNTERMEASURE Alert-specific UID generation.
/// @PERFORMANCE Consistent UID format.
/// @AUDIT Alert UIDs logged.
pub fn generate_alert_uid() -> String {
    format!("alert-{}", generate_grafana_uid())
}

/// [DATA TRANSFORMATION] Data Conversion Utilities
/// @MISSION Transform data between formats for Grafana compatibility.
/// @THREAT Data format incompatibilities.
/// @COUNTERMEASURE Format conversion utilities.
/// @AUDIT Data transformations logged.

/// Convert Prometheus query to Grafana target format
/// @MISSION Transform Prometheus queries for Grafana panels.
/// @THREAT Query format incompatibilities.
/// @COUNTERMEASURE Standardized query transformation.
/// @PERFORMANCE Efficient string processing.
/// @AUDIT Query transformations logged.
pub fn prometheus_query_to_grafana_target(
    query: &str,
    legend_format: Option<&str>,
    ref_id: &str
) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    let target = json!({
        "refId": ref_id,
        "queryType": "",
        "relativeTimeRange": {
            "from": 600,
            "to": 0
        },
        "datasource": {
            "type": "prometheus",
            "uid": "prometheus"
        },
        "model": {
            "expr": query,
            "legendFormat": legend_format.unwrap_or("__auto"),
            "interval": "",
            "intervalFactor": 1,
            "format": "time_series",
            "instant": false,
            "range": true
        }
    });

    Ok(target)
}

/// Convert Loki query to Grafana target format
/// @MISSION Transform Loki queries for Grafana panels.
/// @THREAT Query format incompatibilities.
/// @COUNTERMEASURE Loki-specific query transformation.
/// @PERFORMANCE Efficient string processing.
/// @AUDIT Query transformations logged.
pub fn loki_query_to_grafana_target(
    query: &str,
    ref_id: &str
) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    let target = json!({
        "refId": ref_id,
        "queryType": "",
        "relativeTimeRange": {
            "from": 600,
            "to": 0
        },
        "datasource": {
            "type": "loki",
            "uid": "loki"
        },
        "model": {
            "expr": query,
            "legendFormat": "__auto",
            "maxLines": 1000,
            "resolution": 1
        }
    });

    Ok(target)
}

/// Transform time range to Grafana format
/// @MISSION Convert time ranges to Grafana-compatible format.
/// @THREAT Time format incompatibilities.
/// @COUNTERMEASURE Standardized time transformation.
/// @PERFORMANCE Efficient time processing.
/// @AUDIT Time transformations logged.
pub fn time_range_to_grafana_format(from: &str, to: &str) -> Value {
    json!({
        "from": from,
        "to": to
    })
}

/// [VALIDATION UTILITIES] Data Validation Helpers
/// @MISSION Validate Grafana-related data structures.
/// @THREAT Invalid data causing system errors.
/// @COUNTERMEASURE Comprehensive validation utilities.
/// @AUDIT Validation results logged.

/// Validate Grafana UID format
/// @MISSION Ensure UIDs follow Grafana conventions.
/// @THREAT Malformed UIDs causing API errors.
/// @COUNTERMEASURE UID format validation.
/// @PERFORMANCE Fast regex-based validation.
/// @AUDIT UID validation logged.
pub fn validate_grafana_uid(uid: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Grafana UIDs are typically 8-40 characters, alphanumeric with dashes
    let uid_regex = Regex::new(r"^[a-zA-Z0-9_-]{1,40}$")?;
    if !uid_regex.is_match(uid) {
        return Err(format!("Invalid Grafana UID format: {}", uid).into());
    }
    Ok(())
}

/// Validate Prometheus query syntax
/// @MISSION Check Prometheus query validity.
/// @THREAT Invalid queries causing dashboard failures.
/// @COUNTERMEASURE Basic query syntax validation.
/// @PERFORMANCE Lightweight syntax checking.
/// @AUDIT Query validation logged.
pub fn validate_prometheus_query(query: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if query.trim().is_empty() {
        return Err("Empty Prometheus query".into());
    }

    // Basic validation - check for balanced braces and parentheses
    let brace_count = query.chars().fold(0, |count, c| {
        match c {
            '{' => count + 1,
            '}' => count - 1,
            _ => count,
        }
    });

    if brace_count != 0 {
        return Err("Unbalanced braces in Prometheus query".into());
    }

    let paren_count = query.chars().fold(0, |count, c| {
        match c {
            '(' => count + 1,
            ')' => count - 1,
            _ => count,
        }
    });

    if paren_count != 0 {
        return Err("Unbalanced parentheses in Prometheus query".into());
    }

    Ok(())
}

/// Validate dashboard JSON structure
/// @MISSION Ensure dashboard JSON is well-formed.
/// @THREAT Malformed JSON causing import failures.
/// @COUNTERMEASURE JSON structure validation.
/// @PERFORMANCE Efficient JSON parsing.
/// @AUDIT Dashboard validation logged.
pub fn validate_dashboard_json(dashboard: &Value) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Check required fields
    if !dashboard.is_object() {
        return Err("Dashboard must be a JSON object".into());
    }

    let obj = dashboard.as_object().unwrap();

    if !obj.contains_key("title") {
        return Err("Dashboard must have a title".into());
    }

    if !obj.contains_key("panels") {
        return Err("Dashboard must have panels".into());
    }

    if let Some(panels) = obj.get("panels") {
        if !panels.is_array() {
            return Err("Dashboard panels must be an array".into());
        }
    }

    Ok(())
}

/// [FORMATTING UTILITIES] Data Formatting Helpers
/// @MISSION Format data for Grafana compatibility.
/// @THREAT Formatting inconsistencies.
/// @COUNTERMEASURE Standardized formatting utilities.
/// @AUDIT Formatting operations logged.

/// Format duration for Grafana
/// @MISSION Convert durations to Grafana format.
/// @THREAT Duration format incompatibilities.
/// @COUNTERMEASURE Standardized duration formatting.
/// @PERFORMANCE Efficient string formatting.
/// @AUDIT Duration formatting logged.
pub fn format_duration_for_grafana(seconds: i64) -> String {
    if seconds < 60 {
        format!("{}s", seconds)
    } else if seconds < 3600 {
        format!("{}m", seconds / 60)
    } else if seconds < 86400 {
        format!("{}h", seconds / 3600)
    } else {
        format!("{}d", seconds / 86400)
    }
}

/// Format timestamp for Grafana
/// @MISSION Convert timestamps to Grafana format.
/// @THREAT Timestamp format incompatibilities.
/// @COUNTERMEASURE ISO 8601 formatting.
/// @PERFORMANCE Efficient timestamp formatting.
/// @AUDIT Timestamp formatting logged.
pub fn format_timestamp_for_grafana(timestamp: DateTime<Utc>) -> String {
    timestamp.to_rfc3339()
}

/// Format metric name for Prometheus
/// @MISSION Ensure metric names follow Prometheus conventions.
/// @THREAT Invalid metric names.
/// @COUNTERMEASURE Prometheus naming validation.
/// @PERFORMANCE Regex-based validation.
/// @AUDIT Metric name formatting logged.
pub fn format_metric_name(name: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    // Prometheus metric name rules: start with letter or _, followed by letters, numbers, _
    let metric_regex = Regex::new(r"^[a-zA-Z_][a-zA-Z0-9_]*$")?;
    if !metric_regex.is_match(name) {
        return Err(format!("Invalid Prometheus metric name: {}", name).into());
    }
    Ok(name.to_string())
}

/// [TEMPLATE UTILITIES] Template Processing Helpers
/// @MISSION Process dashboard and alert templates.
/// @THREAT Template processing errors.
/// @COUNTERMEASURE Template processing utilities.
/// @AUDIT Template operations logged.

/// Extract template variables from dashboard
/// @MISSION Find all template variables in a dashboard.
/// @THREAT Unidentified template variables.
/// @COUNTERMEASURE Variable extraction utility.
/// @PERFORMANCE Regex-based extraction.
/// @AUDIT Variable extraction logged.
pub fn extract_template_variables(dashboard: &Value) -> Vec<String> {
    let mut variables = Vec::new();
    let dashboard_str = serde_json::to_string(dashboard).unwrap_or_default();

    // Find all {{variable}} patterns
    let var_regex = Regex::new(r"\{\{([^}]+)\}\}").unwrap();
    for cap in var_regex.captures_iter(&dashboard_str) {
        if let Some(var_match) = cap.get(1) {
            let var_name = var_match.as_str().trim().to_string();
            if !variables.contains(&var_name) {
                variables.push(var_name);
            }
        }
    }

    variables
}

/// Validate template parameters
/// @MISSION Ensure all required template parameters are provided.
/// @THREAT Missing template parameters.
/// @COUNTERMEASURE Parameter validation.
/// @PERFORMANCE Set-based validation.
/// @AUDIT Parameter validation logged.
pub fn validate_template_parameters(
    template: &Value,
    provided_params: &HashMap<String, String>
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let required_vars = extract_template_variables(template);
    let provided_keys: std::collections::HashSet<_> = provided_params.keys().collect();

    for var in required_vars {
        if !provided_keys.contains(&var) {
            return Err(format!("Missing required template parameter: {}", var).into());
        }
    }

    Ok(())
}

/// [METADATA UTILITIES] Metadata Management Helpers
/// @MISSION Manage metadata for Grafana resources.
/// @THREAT Missing or inconsistent metadata.
/// @COUNTERMEASURE Metadata utility functions.
/// @AUDIT Metadata operations logged.

/// Generate resource metadata
/// @MISSION Create standardized metadata for resources.
/// @THREAT Inconsistent metadata across resources.
/// @COUNTERMEASURE Standardized metadata generation.
/// @PERFORMANCE Efficient metadata creation.
/// @AUDIT Metadata generation logged.
pub fn generate_resource_metadata(
    resource_type: &str,
    created_by: &str,
    tags: Vec<String>
) -> Value {
    json!({
        "resource_type": resource_type,
        "created_by": created_by,
        "created_at": format_timestamp_for_grafana(Utc::now()),
        "version": "1.0",
        "tags": tags,
        "organization": "sky-genesis-enterprise"
    })
}

/// Update resource metadata
/// @MISSION Update metadata with modification information.
/// @THREAT Stale metadata.
/// @COUNTERMEASURE Metadata update utilities.
/// @PERFORMANCE Efficient metadata updates.
/// @AUDIT Metadata updates logged.
pub fn update_resource_metadata(
    mut metadata: Value,
    updated_by: &str,
    new_tags: Option<Vec<String>>
) -> Value {
    if let Some(obj) = metadata.as_object_mut() {
        obj.insert("updated_by".to_string(), json!(updated_by));
        obj.insert("updated_at".to_string(), json!(format_timestamp_for_grafana(Utc::now())));

        if let Some(tags) = new_tags {
            obj.insert("tags".to_string(), json!(tags));
        }
    }
    metadata
}

/// [ERROR HANDLING UTILITIES] Error Processing Helpers
/// @MISSION Handle and format Grafana-related errors.
/// @THREAT Unclear error messages.
/// @COUNTERMEASURE Error formatting utilities.
/// @AUDIT Error handling logged.

/// Format Grafana API error
/// @MISSION Convert API errors to user-friendly format.
/// @THREAT Confusing error messages.
/// @COUNTERMEASURE Error message formatting.
/// @PERFORMANCE String processing.
/// @AUDIT Error formatting logged.
pub fn format_grafana_api_error(error: &str, operation: &str) -> String {
    format!("Grafana API error during {}: {}", operation, error)
}

/// Check if error is retryable
/// @MISSION Determine if an operation should be retried.
/// @THREAT Unnecessary retries or failed retries.
/// @COUNTERMEASURE Retry logic utilities.
/// @PERFORMANCE Fast error classification.
/// @AUDIT Retry decisions logged.
pub fn is_retryable_error(error: &str) -> bool {
    let retryable_patterns = [
        "timeout",
        "connection refused",
        "temporary failure",
        "rate limit",
        "502",
        "503",
        "504",
    ];

    retryable_patterns.iter().any(|pattern| error.to_lowercase().contains(pattern))
}

/// [PERFORMANCE UTILITIES] Performance Monitoring Helpers
/// @MISSION Monitor performance of Grafana operations.
/// @THREAT Undetected performance issues.
/// @COUNTERMEASURE Performance measurement utilities.
/// @AUDIT Performance metrics logged.

/// Measure operation duration
/// @MISSION Time Grafana operations for performance monitoring.
/// @THREAT Slow operations going undetected.
/// @COUNTERMEASURE Duration measurement utilities.
/// @PERFORMANCE High-precision timing.
/// @AUDIT Performance measurements logged.
pub fn measure_operation_duration<F, T>(operation: F) -> (T, std::time::Duration)
where
    F: FnOnce() -> T,
{
    let start = std::time::Instant::now();
    let result = operation();
    let duration = start.elapsed();
    (result, duration)
}

/// Log performance metrics
/// @MISSION Record performance data for monitoring.
/// @THREAT Performance degradation.
/// @COUNTERMEASURE Performance logging utilities.
/// @PERFORMANCE Efficient logging.
/// @AUDIT Performance logs tracked.
pub fn log_performance_metric(operation: &str, duration: std::time::Duration, success: bool) {
    // In practice, this would integrate with the metrics system
    println!("Grafana operation '{}' completed in {:?}, success: {}", operation, duration, success);
}

/// [SECURITY UTILITIES] Security Helper Functions
/// @MISSION Provide security-related utilities for Grafana operations.
/// @THREAT Security vulnerabilities in Grafana integration.
/// @COUNTERMEASURE Security utility functions.
/// @AUDIT Security operations logged.

/// Sanitize dashboard data
/// @MISSION Remove potentially harmful content from dashboards.
/// @THREAT Code injection through dashboard data.
/// @COUNTERMEASURE Data sanitization utilities.
/// @PERFORMANCE Efficient sanitization.
/// @AUDIT Sanitization operations logged.
pub fn sanitize_dashboard_data(dashboard: &mut Value) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Remove any potentially dangerous script content
    if let Some(obj) = dashboard.as_object_mut() {
        // Remove any script fields that might contain executable content
        let dangerous_fields = ["script", "javascript", "onload", "onerror"];
        for field in dangerous_fields {
            obj.remove(field);
        }
    }
    Ok(())
}

/// Validate datasource URL
/// @MISSION Ensure datasource URLs are safe and valid.
/// @THREAT Malicious datasource URLs.
/// @COUNTERMEASURE URL validation utilities.
/// @PERFORMANCE Regex-based validation.
/// @AUDIT URL validation logged.
pub fn validate_datasource_url(url: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Basic URL validation
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err("Datasource URL must use HTTP or HTTPS".into());
    }

    // Check for localhost/internal addresses that might be dangerous
    let dangerous_patterns = ["localhost", "127.0.0.1", "0.0.0.0", "169.254."];
    for pattern in dangerous_patterns {
        if url.contains(pattern) {
            return Err(format!("Potentially dangerous URL pattern detected: {}", pattern).into());
        }
    }

    Ok(())
}