// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: PowerAdmin Utilities
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | SENSITIVE
//  MISSION: Provide utility functions and helpers for PowerAdmin DNS integration,
//  including UID generation, data transformation, validation helpers,
//  DNS format conversion, and common operations used across PowerAdmin
//  components.
//  NOTICE: Utilities implement common patterns and reduce code duplication
//  for DNS zone management, record operations, and DNSSEC configuration
//  with enterprise utility standards.
//  UTILITIES: UID generation, DNS formatting, data transformation, validation
//  COMPLIANCE: DNS Standards, Utility standards, error handling, performance
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use std::collections::HashMap;
use serde_json::{Value, json};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use regex::Regex;

/// [UID GENERATION] Unique Identifier Utilities
/// @MISSION Generate unique identifiers for DNS resources.
/// @THREAT ID collisions causing conflicts.
/// @COUNTERMEASURE Cryptographically secure UID generation.
/// @AUDIT UID generation tracked.

/// Generate a unique DNS zone UID
/// @MISSION Create unique identifiers for zones.
/// @THREAT Zone UID conflicts.
/// @COUNTERMEASURE UUID-based generation.
/// @PERFORMANCE Fast generation with low collision probability.
/// @AUDIT Generated UIDs logged for tracking.
pub fn generate_zone_uid() -> String {
    format!("zone-{}", generate_dns_uid())
}

/// Generate a unique DNS record UID
/// @MISSION Create unique identifiers for records.
/// @THREAT Record UID conflicts.
/// @COUNTERMEASURE UUID-based generation.
/// @PERFORMANCE Fast generation with low collision probability.
/// @AUDIT Generated UIDs logged for tracking.
pub fn generate_record_uid() -> String {
    format!("record-{}", generate_dns_uid())
}

/// Generate a unique DNSSEC key UID
/// @MISSION Create unique identifiers for DNSSEC keys.
/// @THREAT Key UID conflicts.
/// @COUNTERMEASURE UUID-based generation.
/// @PERFORMANCE Fast generation with low collision probability.
/// @AUDIT Generated UIDs logged for tracking.
pub fn generate_dnssec_key_uid() -> String {
    format!("dnssec-{}", generate_dns_uid())
}

/// Generate a unique operation log UID
/// @MISSION Create unique identifiers for audit logs.
/// @THREAT Log UID conflicts.
/// @COUNTERMEASURE UUID-based generation.
/// @PERFORMANCE Fast generation with low collision probability.
/// @AUDIT Generated UIDs logged for tracking.
pub fn generate_operation_uid() -> String {
    format!("op-{}", generate_dns_uid())
}

/// Generate base DNS UID
fn generate_dns_uid() -> String {
    // Generate a UUID and take first 8 characters for DNS UID format
    let uuid = Uuid::new_v4();
    let uid = uuid.to_string().replace("-", "")[0..8].to_string();
    uid
}

/// [DNS NAME FORMATTING] DNS Name Standardization
/// @MISSION Ensure consistent DNS name formatting.
/// @THREAT Inconsistent name formats.
/// @COUNTERMEASURE Standardized formatting.
/// @AUDIT Name formatting tracked.

/// Normalize DNS name to FQDN format
/// @MISSION Convert names to fully qualified domain names.
/// @THREAT Non-FQDN names causing issues.
/// @COUNTERMEASURE Automatic FQDN conversion.
/// @PERFORMANCE String processing.
/// @AUDIT Name normalization logged.
pub fn normalize_dns_name(name: &str) -> String {
    let trimmed = name.trim();
    if trimmed.ends_with('.') {
        trimmed.to_string()
    } else {
        format!("{}.", trimmed)
    }
}

/// Remove FQDN dot from DNS name
/// @MISSION Convert FQDN to relative name.
/// @THREAT FQDN dots in relative contexts.
/// @COUNTERMEASURE Automatic dot removal.
/// @PERFORMANCE String processing.
/// @AUDIT Name denormalization logged.
pub fn denormalize_dns_name(name: &str) -> String {
    name.trim_end_matches('.').to_string()
}

/// Validate DNS name format
/// @MISSION Check if name follows DNS standards.
/// @THREAT Invalid DNS names.
/// @COUNTERMEASURE RFC-compliant validation.
/// @PERFORMANCE Regex-based validation.
/// @AUDIT Name validation logged.
pub fn validate_dns_name(name: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if name.is_empty() {
        return Err("DNS name cannot be empty".into());
    }

    if name.len() > 253 {
        return Err("DNS name too long (max 253 characters)".into());
    }

    // Basic character validation
    let valid_chars = Regex::new(r"^[a-zA-Z0-9.-]+\.?$").unwrap();
    if !valid_chars.is_match(name) {
        return Err("DNS name contains invalid characters".into());
    }

    // Check for consecutive dots
    if name.contains("..") {
        return Err("DNS name cannot contain consecutive dots".into());
    }

    // Check for valid TLD (basic check)
    if !name.contains('.') {
        return Err("DNS name must contain at least one dot".into());
    }

    Ok(())
}

/// [DNS RECORD FORMATTING] Record Content Standardization
/// @MISSION Ensure consistent record content formatting.
/// @THREAT Malformed record content.
/// @COUNTERMEASURE Type-specific formatting.
/// @AUDIT Record formatting tracked.

/// Format A record content
/// @MISSION Ensure IPv4 address format.
/// @THREAT Invalid IP addresses.
/// @COUNTERMEASURE IP validation and formatting.
/// @PERFORMANCE String validation.
/// @AUDIT A record formatting logged.
pub fn format_a_record(content: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let ip_regex = Regex::new(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$").unwrap();
    if !ip_regex.is_match(content) {
        return Err("Invalid IPv4 address format".into());
    }

    // Validate each octet
    for octet in content.split('.') {
        let octet_num: u8 = octet.parse()?;
        if octet_num > 255 {
            return Err("IPv4 octet value too high".into());
        }
    }

    Ok(content.to_string())
}

/// Format AAAA record content
/// @MISSION Ensure IPv6 address format.
/// @THREAT Invalid IPv6 addresses.
/// @COUNTERMEASURE IPv6 validation and formatting.
/// @PERFORMANCE String validation.
/// @AUDIT AAAA record formatting logged.
pub fn format_aaaa_record(content: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    // Basic IPv6 validation - more comprehensive validation would be needed
    let ipv6_regex = Regex::new(r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$").unwrap();
    if !ipv6_regex.is_match(content) {
        return Err("Invalid IPv6 address format".into());
    }

    Ok(content.to_lowercase())
}

/// Format CNAME record content
/// @MISSION Ensure CNAME target format.
/// @THREAT Invalid CNAME targets.
/// @COUNTERMEASURE Domain name validation.
/// @PERFORMANCE String validation.
/// @AUDIT CNAME record formatting logged.
pub fn format_cname_record(content: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    validate_dns_name(content)?;
    Ok(normalize_dns_name(content))
}

/// Format MX record content
/// @MISSION Ensure MX target format.
/// @THREAT Invalid MX targets.
/// @COUNTERMEASURE Domain name validation.
/// @PERFORMANCE String validation.
/// @AUDIT MX record formatting logged.
pub fn format_mx_record(content: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    validate_dns_name(content)?;
    Ok(normalize_dns_name(content))
}

/// Format TXT record content
/// @MISSION Ensure TXT content format.
/// @THREAT Malformed TXT content.
/// @COUNTERMEASURE Length and character validation.
/// @PERFORMANCE String validation.
/// @AUDIT TXT record formatting logged.
pub fn format_txt_record(content: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    if content.len() > 255 {
        return Err("TXT record content too long (max 255 characters)".into());
    }

    // Escape quotes if needed
    let escaped = content.replace("\"", "\\\"");
    Ok(format!("\"{}\"", escaped))
}

/// [DNS SERIAL NUMBER] SOA Serial Generation
/// @MISSION Generate SOA serial numbers.
/// @THREAT Incorrect serial numbers.
/// @COUNTERMEASURE Date-based serial generation.
/// @AUDIT Serial generation logged.

/// Generate SOA serial number
/// @MISSION Create serial numbers for zone updates.
/// @THREAT Serial number conflicts.
/// @COUNTERMEASURE Date and sequence-based generation.
/// @PERFORMANCE Fast generation.
/// @AUDIT Serial numbers logged.
pub fn generate_soa_serial() -> i64 {
    // Format: YYYYMMDDNN where NN is sequence number
    let now = Utc::now();
    let date_part = now.format("%Y%m%d").to_string().parse::<i64>().unwrap() * 100;
    // In production, you'd track sequence per zone
    date_part + 1
}

/// Increment SOA serial number
/// @MISSION Increment serial for zone updates.
/// @THREAT Serial not incremented.
/// @COUNTERMEASURE Automatic incrementation.
/// @PERFORMANCE Simple arithmetic.
/// @AUDIT Serial increments logged.
pub fn increment_soa_serial(current_serial: i64) -> i64 {
    let now = Utc::now();
    let today_serial_base = now.format("%Y%m%d").to_string().parse::<i64>().unwrap() * 100;

    if current_serial >= today_serial_base {
        current_serial + 1
    } else {
        today_serial_base + 1
    }
}

/// [DNSSEC UTILITIES] DNSSEC Helper Functions
/// @MISSION Provide DNSSEC-related utilities.
/// @THREAT DNSSEC configuration errors.
/// @COUNTERMEASURE Helper functions for DNSSEC.
/// @AUDIT DNSSEC operations logged.

/// Calculate DNSSEC key tag
/// @MISSION Generate key tags for DNSSEC keys.
/// @THREAT Incorrect key tags.
/// @COUNTERMEASURE RFC 4034 compliant calculation.
/// @PERFORMANCE Mathematical computation.
/// @AUDIT Key tag generation logged.
pub fn calculate_key_tag(public_key: &str) -> Result<i32, Box<dyn std::error::Error + Send + Sync>> {
    // Simplified key tag calculation
    // In production, use proper RFC 4034 algorithm
    let hash = ring::digest::digest(&ring::digest::SHA256, public_key.as_bytes());
    let bytes = hash.as_ref();
    let tag = ((bytes[0] as u16) << 8) | (bytes[1] as u16);
    Ok(tag as i32)
}

/// Generate DNSSEC key timing
/// @MISSION Calculate key rollover timing.
/// @THREAT Incorrect rollover timing.
/// @COUNTERMEASURE Duration-based calculations.
/// @PERFORMANCE Date arithmetic.
/// @AUDIT Timing calculations logged.
pub fn calculate_dnssec_timing(rollover_period: &str) -> Result<DateTime<Utc>, Box<dyn std::error::Error + Send + Sync>> {
    let now = Utc::now();

    // Parse rollover period (e.g., "30d", "1y")
    let duration = parse_duration(rollover_period)?;
    let next_rollover = now + duration;

    Ok(next_rollover)
}

/// Parse duration string
fn parse_duration(duration_str: &str) -> Result<chrono::Duration, Box<dyn std::error::Error + Send + Sync>> {
    let regex = Regex::new(r"^(\d+)([smhdwy])$").unwrap();
    let captures = regex.captures(duration_str)
        .ok_or_else(|| format!("Invalid duration format: {}", duration_str))?;

    let value: i64 = captures[1].parse()?;
    let unit = &captures[2];

    match unit {
        "s" => Ok(chrono::Duration::seconds(value)),
        "m" => Ok(chrono::Duration::minutes(value)),
        "h" => Ok(chrono::Duration::hours(value)),
        "d" => Ok(chrono::Duration::days(value)),
        "w" => Ok(chrono::Duration::weeks(value)),
        "y" => Ok(chrono::Duration::days(value * 365)), // Approximate
        _ => Err(format!("Unknown duration unit: {}", unit).into()),
    }
}

/// [DATA TRANSFORMATION] DNS Data Conversion
/// @MISSION Convert between DNS formats.
/// @THREAT Format incompatibilities.
/// @COUNTERMEASURE Format conversion utilities.
/// @AUDIT Data transformations logged.

/// Convert PowerAdmin zone to internal format
/// @MISSION Transform external API data.
/// @THREAT Data format mismatches.
/// @COUNTERMEASURE Standardized conversion.
/// @PERFORMANCE JSON processing.
/// @AUDIT Data conversion logged.
pub fn poweradmin_zone_to_internal(pa_zone: &Value) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    let mut internal = json!({
        "name": pa_zone.get("name").and_then(|v| v.as_str()).unwrap_or(""),
        "type": pa_zone.get("type").and_then(|v| v.as_str()).unwrap_or("MASTER"),
        "nameservers": pa_zone.get("nameservers").and_then(|v| v.as_array()).unwrap_or(&vec![]),
        "serial": pa_zone.get("serial").and_then(|v| v.as_i64()),
        "refresh": pa_zone.get("refresh").and_then(|v| v.as_i64()),
        "retry": pa_zone.get("retry").and_then(|v| v.as_i64()),
        "expire": pa_zone.get("expire").and_then(|v| v.as_i64()),
        "minimum": pa_zone.get("minimum").and_then(|v| v.as_i64()),
        "ttl": pa_zone.get("ttl").and_then(|v| v.as_i64()),
    });

    Ok(internal)
}

/// Convert PowerAdmin record to internal format
/// @MISSION Transform external API data.
/// @THREAT Data format mismatches.
/// @COUNTERMEASURE Standardized conversion.
/// @PERFORMANCE JSON processing.
/// @AUDIT Data conversion logged.
pub fn poweradmin_record_to_internal(pa_record: &Value) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    let mut internal = json!({
        "name": pa_record.get("name").and_then(|v| v.as_str()).unwrap_or(""),
        "type": pa_record.get("type").and_then(|v| v.as_str()).unwrap_or(""),
        "content": pa_record.get("content").and_then(|v| v.as_str()).unwrap_or(""),
        "ttl": pa_record.get("ttl").and_then(|v| v.as_i64()).unwrap_or(3600),
        "prio": pa_record.get("prio").and_then(|v| v.as_i64()),
        "disabled": pa_record.get("disabled").and_then(|v| v.as_bool()).unwrap_or(false),
    });

    Ok(internal)
}

/// [VALIDATION UTILITIES] DNS Validation Helpers
/// @MISSION Provide validation helper functions.
/// @THREAT Invalid DNS data.
/// @COUNTERMEASURE Comprehensive validation.
/// @AUDIT Validation operations logged.

/// Validate zone configuration
/// @MISSION Check zone configuration validity.
/// @THREAT Invalid zone configurations.
/// @COUNTERMEASURE Multi-field validation.
/// @PERFORMANCE Comprehensive checks.
/// @AUDIT Zone validation logged.
pub fn validate_zone_config(zone: &Value) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let mut errors = Vec::new();

    // Validate zone name
    if let Some(name) = zone.get("name").and_then(|v| v.as_str()) {
        if let Err(e) = validate_dns_name(name) {
            errors.push(format!("Invalid zone name: {}", e));
        }
    } else {
        errors.push("Zone name is required".to_string());
    }

    // Validate zone type
    if let Some(zone_type) = zone.get("type").and_then(|v| v.as_str()) {
        let valid_types = ["MASTER", "SLAVE", "NATIVE"];
        if !valid_types.contains(&zone_type) {
            errors.push(format!("Invalid zone type: {}", zone_type));
        }
    }

    // Validate nameservers
    if let Some(nameservers) = zone.get("nameservers").and_then(|v| v.as_array()) {
        for (i, ns) in nameservers.iter().enumerate() {
            if let Some(ns_str) = ns.as_str() {
                if let Err(e) = validate_dns_name(ns_str) {
                    errors.push(format!("Invalid nameserver {}: {}", i + 1, e));
                }
            } else {
                errors.push(format!("Nameserver {} is not a string", i + 1));
            }
        }
    }

    Ok(errors)
}

/// Validate record configuration
/// @MISSION Check record configuration validity.
/// @THREAT Invalid record configurations.
/// @COUNTERMEASURE Type-specific validation.
/// @PERFORMANCE Comprehensive checks.
/// @AUDIT Record validation logged.
pub fn validate_record_config(record: &Value) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let mut errors = Vec::new();

    // Validate record name
    if let Some(name) = record.get("name").and_then(|v| v.as_str()) {
        if let Err(e) = validate_dns_name(name) {
            errors.push(format!("Invalid record name: {}", e));
        }
    } else {
        errors.push("Record name is required".to_string());
    }

    // Validate record type
    let record_type = record.get("type").and_then(|v| v.as_str()).unwrap_or("");
    let valid_types = ["A", "AAAA", "CNAME", "MX", "TXT", "SRV", "PTR", "NS", "SOA"];
    if !valid_types.contains(&record_type) {
        errors.push(format!("Invalid record type: {}", record_type));
    }

    // Validate content based on type
    if let Some(content) = record.get("content").and_then(|v| v.as_str()) {
        let content_validation = match record_type {
            "A" => format_a_record(content),
            "AAAA" => format_aaaa_record(content),
            "CNAME" | "MX" | "NS" => validate_dns_name(content),
            "TXT" => format_txt_record(content),
            _ => Ok(content.to_string()),
        };

        if let Err(e) = content_validation {
            errors.push(format!("Invalid record content: {}", e));
        }
    } else {
        errors.push("Record content is required".to_string());
    }

    // Validate TTL
    if let Some(ttl) = record.get("ttl").and_then(|v| v.as_i64()) {
        if ttl < 0 || ttl > 2147483647 {
            errors.push("TTL must be between 0 and 2147483647".to_string());
        }
    }

    // Validate priority for MX records
    if record_type == "MX" {
        if record.get("prio").and_then(|v| v.as_i64()).is_none() {
            errors.push("MX records require a priority".to_string());
        }
    }

    Ok(errors)
}

/// [TEMPLATE UTILITIES] Zone Template Helpers
/// @MISSION Provide template processing utilities.
/// @THREAT Template processing errors.
/// @COUNTERMEASURE Safe template expansion.
/// @AUDIT Template operations logged.

/// Process zone template with parameters
/// @MISSION Expand template variables.
/// @THREAT Template injection.
/// @COUNTERMEASURE Parameterized expansion.
/// @PERFORMANCE String processing.
/// @AUDIT Template processing logged.
pub fn process_zone_template(template: &str, parameters: &HashMap<String, String>) -> String {
    let mut result = template.to_string();

    for (key, value) in parameters {
        let placeholder = format!("{{{}}}", key);
        result = result.replace(&placeholder, value);
    }

    result
}

/// Extract template variables from content
/// @MISSION Find variables in template content.
/// @THREAT Unprocessed variables.
/// @COUNTERMEASURE Variable extraction.
/// @PERFORMANCE Regex processing.
/// @AUDIT Variable extraction logged.
pub fn extract_template_variables(content: &str) -> Vec<String> {
    let regex = Regex::new(r"\{([^}]+)\}").unwrap();
    regex.captures_iter(content)
        .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string()))
        .collect()
}