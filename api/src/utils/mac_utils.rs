// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: MAC Identity Utilities
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | SENSITIVE
//  MISSION: Provide utility functions for MAC identity operations,
//  including formatting, conversion, validation helpers, and common operations.
//  NOTICE: Implements secure utility functions with proper error handling,
//  logging, and enterprise security standards for MAC identity management.
//  STANDARDS: Utility Functions, Error Handling, Cryptographic Standards
//  COMPLIANCE: Security Best Practices, MAC Identity Standards
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use std::collections::HashMap;
use uuid::Uuid;
use regex::Regex;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

use crate::models::data_model::{MacIdentity, MacStatus};
use crate::core::audit_manager::{AuditManager, AuditEventType, AuditSeverity};

/// [MAC UTILITIES] Utility functions for MAC identity operations
/// @MISSION Provide helper functions for MAC management.
/// @THREAT Inconsistent data handling or format errors.
/// @COUNTERMEASURE Standardized utility functions with validation.
/// @AUDIT Utility operations logged where appropriate.
/// @DEPENDENCY Audit manager for logging.

/// Format MAC address for display
/// @MISSION Provide human-readable MAC address formatting.
/// @THREAT Display format inconsistencies.
/// @COUNTERMEASURE Standardized formatting functions.
pub fn format_mac_for_display(mac: &str) -> String {
    if mac.starts_with("SGE-") {
        // SGE format: already properly formatted
        mac.to_string()
    } else {
        // Assume IEEE format and convert to colon-separated
        mac.replace("-", ":").to_uppercase()
    }
}

/// Normalize MAC address to standard format
/// @MISSION Convert various MAC formats to canonical representation.
/// @THREAT Inconsistent MAC storage.
/// @COUNTERMEASURE Normalization to standard format.
pub fn normalize_mac_address(mac: &str) -> Result<String, String> {
    lazy_static! {
        static ref IEEE_REGEX: Regex = Regex::new(r"^([0-9A-Fa-f]{2})[:-]?([0-9A-Fa-f]{2})[:-]?([0-9A-Fa-f]{2})[:-]?([0-9A-Fa-f]{2})[:-]?([0-9A-Fa-f]{2})[:-]?([0-9A-Fa-f]{2})$").unwrap();
        static ref SGE_REGEX: Regex = Regex::new(r"^SGE-([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2})$").unwrap();
    }

    if let Some(caps) = SGE_REGEX.captures(mac) {
        // Already SGE format, ensure uppercase
        Ok(format!("SGE-{}:{}:{}:{}:{}:{}",
            &caps[1].to_uppercase(),
            &caps[2].to_uppercase(),
            &caps[3].to_uppercase(),
            &caps[4].to_uppercase(),
            &caps[5].to_uppercase(),
            &caps[6].to_uppercase()
        ))
    } else if let Some(caps) = IEEE_REGEX.captures(mac) {
        // Convert IEEE to SGE format
        Ok(format!("SGE-{}:{}:{}:{}:{}:{}",
            &caps[1].to_uppercase(),
            &caps[2].to_uppercase(),
            &caps[3].to_uppercase(),
            &caps[4].to_uppercase(),
            &caps[5].to_uppercase(),
            &caps[6].to_uppercase()
        ))
    } else {
        Err("Invalid MAC address format".to_string())
    }
}

/// Extract MAC components for analysis
/// @MISSION Break down MAC address into analyzable components.
/// @THREAT Incorrect component extraction.
/// @COUNTERMEASURE Regex-based parsing with validation.
pub fn extract_mac_components(mac: &str) -> Result<MacComponents, String> {
    lazy_static! {
        static ref SGE_REGEX: Regex = Regex::new(r"^SGE-([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2})$").unwrap();
    }

    if let Some(caps) = SGE_REGEX.captures(mac) {
        let components = MacComponents {
            prefix: "SGE".to_string(),
            bytes: vec![
                u8::from_str_radix(&caps[1], 16).map_err(|_| "Invalid hex")?,
                u8::from_str_radix(&caps[2], 16).map_err(|_| "Invalid hex")?,
                u8::from_str_radix(&caps[3], 16).map_err(|_| "Invalid hex")?,
                u8::from_str_radix(&caps[4], 16).map_err(|_| "Invalid hex")?,
                u8::from_str_radix(&caps[5], 16).map_err(|_| "Invalid hex")?,
                u8::from_str_radix(&caps[6], 16).map_err(|_| "Invalid hex")?,
            ],
        };
        Ok(components)
    } else {
        Err("Invalid SGE-MAC format".to_string())
    }
}

/// MAC address components structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacComponents {
    pub prefix: String,
    pub bytes: Vec<u8>,
}

/// Check if MAC address is locally administered
/// @MISSION Identify locally administered MAC addresses.
/// @THREAT Incorrect OUI classification.
/// @COUNTERMEASURE Proper bit checking for U/L bit.
pub fn is_locally_administered(mac: &str) -> Result<bool, String> {
    let components = extract_mac_components(mac)?;
    // Check the U/L bit (second least significant bit of first byte)
    Ok((components.bytes[0] & 0x02) != 0)
}

/// Check if MAC address is unicast
/// @MISSION Identify unicast vs multicast MAC addresses.
/// @THREAT Incorrect unicast/multicast classification.
/// @COUNTERMEASURE Proper bit checking for I/G bit.
pub fn is_unicast(mac: &str) -> Result<bool, String> {
    let components = extract_mac_components(mac)?;
    // Check the I/G bit (least significant bit of first byte)
    Ok((components.bytes[0] & 0x01) == 0)
}

/// Generate MAC address range for organization
/// @MISSION Create sequential MAC addresses for organizational use.
/// @THREAT MAC address collisions.
/// @COUNTERMEASURE Sequential generation with validation.
pub fn generate_mac_range(base_mac: &str, count: usize) -> Result<Vec<String>, String> {
    let components = extract_mac_components(base_mac)?;
    let mut macs = Vec::new();

    let mut current_bytes = components.bytes.clone();

    for _ in 0..count {
        let mac = format!("SGE-{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            current_bytes[0], current_bytes[1], current_bytes[2],
            current_bytes[3], current_bytes[4], current_bytes[5]
        );
        macs.push(mac);

        // Increment the MAC address
        for i in (0..6).rev() {
            if current_bytes[i] < 255 {
                current_bytes[i] += 1;
                break;
            } else {
                current_bytes[i] = 0;
            }
        }
    }

    Ok(macs)
}

/// Validate IP-MAC binding
/// @MISSION Ensure IP and MAC address compatibility.
/// @THREAT Invalid network configurations.
/// @COUNTERMEASURE Basic IP/MAC validation.
pub fn validate_ip_mac_binding(ip: &str, mac: &str) -> Result<bool, String> {
    // Basic validation - in real implementation, this would check network rules
    if ip.is_empty() || mac.is_empty() {
        return Ok(false);
    }

    // Check if IP is valid
    if ip.parse::<std::net::IpAddr>().is_err() {
        return Err("Invalid IP address format".to_string());
    }

    // Check if MAC is valid
    let _ = extract_mac_components(mac)?;

    // For now, just return true if both are valid
    Ok(true)
}

/// Create MAC identity summary for logging
/// @MISSION Generate audit-safe MAC identity summaries.
/// @THREAT Sensitive data exposure in logs.
/// @COUNTERMEASURE Sanitized logging information.
pub fn create_mac_summary(mac: &MacIdentity) -> HashMap<String, String> {
    let mut summary = HashMap::new();
    summary.insert("id".to_string(), mac.id.to_string());
    summary.insert("sge_mac_prefix".to_string(), mac.sge_mac.chars().take(8).collect());
    summary.insert("status".to_string(), format!("{:?}", mac.status));
    summary.insert("organization_id".to_string(), mac.organization_id.to_string());
    summary.insert("has_ip".to_string(), (!mac.ip_address.is_none()).to_string());
    summary.insert("has_standard_mac".to_string(), (!mac.standard_mac.is_none()).to_string());
    summary.insert("created_at".to_string(), mac.created_at.to_string());
    summary
}

/// Calculate MAC address age in days
/// @MISSION Determine how long a MAC identity has existed.
/// @THREAT Time calculation errors.
/// @COUNTERMEASURE Proper timestamp arithmetic.
pub fn calculate_mac_age_days(mac: &MacIdentity) -> Result<i64, String> {
    let now = chrono::Utc::now();
    let duration = now.signed_duration_since(mac.created_at);
    Ok(duration.num_days())
}

/// Check if MAC identity needs renewal
/// @MISSION Identify MAC identities requiring updates.
/// @THREAT Stale MAC identity data.
/// @COUNTERMEASURE Age-based renewal checks.
pub fn needs_renewal(mac: &MacIdentity, max_age_days: i64) -> Result<bool, String> {
    let age = calculate_mac_age_days(mac)?;
    Ok(age > max_age_days)
}

/// Sanitize MAC metadata for storage
/// @MISSION Clean metadata before database storage.
/// @THREAT Malformed or malicious metadata.
/// @COUNTERMEASURE Input sanitization and validation.
pub fn sanitize_mac_metadata(metadata: &HashMap<String, String>) -> HashMap<String, String> {
    metadata.iter()
        .filter_map(|(k, v)| {
            // Basic sanitization - remove potentially harmful keys/values
            if k.len() > 100 || v.len() > 1000 {
                None
            } else if k.contains('<') || k.contains('>') || v.contains('<') || v.contains('>') {
                None
            } else {
                Some((k.clone(), v.clone()))
            }
        })
        .collect()
}

/// Generate MAC operation audit context
/// @MISSION Create structured audit data for MAC operations.
/// @THREAT Incomplete audit trails.
/// @COUNTERMEASURE Comprehensive audit context generation.
pub fn generate_audit_context(
    operation: &str,
    mac: Option<&MacIdentity>,
    user_id: &str,
    organization_id: Uuid,
    additional_data: Option<HashMap<String, String>>,
) -> serde_json::Value {
    let mut context = serde_json::json!({
        "operation": operation,
        "user_id": user_id,
        "organization_id": organization_id,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    if let Some(mac) = mac {
        context["mac_summary"] = serde_json::json!(create_mac_summary(mac));
    }

    if let Some(data) = additional_data {
        context["additional_data"] = serde_json::json!(data);
    }

    context
}

/// Batch validate MAC addresses
/// @MISSION Validate multiple MAC addresses efficiently.
/// @THREAT Performance issues with bulk validation.
/// @COUNTERMEASURE Batch processing with early termination.
pub fn batch_validate_macs(macs: &[String]) -> (Vec<String>, Vec<String>) {
    let mut valid = Vec::new();
    let mut invalid = Vec::new();

    for mac in macs {
        if let Ok(normalized) = normalize_mac_address(mac) {
            valid.push(normalized);
        } else {
            invalid.push(mac.clone());
        }
    }

    (valid, invalid)
}

/// Calculate MAC address diversity metrics
/// @MISSION Analyze MAC address distribution.
/// @THREAT Poor randomization or patterns.
/// @COUNTERMEASURE Statistical analysis of MAC distribution.
pub fn calculate_mac_diversity(macs: &[String]) -> Result<MacDiversityMetrics, String> {
    if macs.is_empty() {
        return Err("Empty MAC list".to_string());
    }

    let mut components = Vec::new();
    for mac in macs {
        components.push(extract_mac_components(mac)?);
    }

    // Calculate entropy for each byte position
    let mut byte_entropies = Vec::new();
    for byte_pos in 0..6 {
        let mut freq = [0u32; 256];
        for comp in &components {
            freq[comp.bytes[byte_pos] as usize] += 1;
        }

        let mut entropy = 0.0;
        let total = components.len() as f64;
        for &count in &freq {
            if count > 0 {
                let p = count as f64 / total;
                entropy -= p * p.log2();
            }
        }
        byte_entropies.push(entropy);
    }

    let avg_entropy = byte_entropies.iter().sum::<f64>() / byte_entropies.len() as f64;

    Ok(MacDiversityMetrics {
        total_macs: macs.len(),
        unique_macs: macs.iter().collect::<std::collections::HashSet<_>>().len(),
        average_entropy: avg_entropy,
        byte_entropies,
    })
}

/// MAC diversity metrics structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacDiversityMetrics {
    pub total_macs: usize,
    pub unique_macs: usize,
    pub average_entropy: f64,
    pub byte_entropies: Vec<f64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_mac_address() {
        assert_eq!(
            normalize_mac_address("00:11:22:33:44:55").unwrap(),
            "SGE-00:11:22:33:44:55"
        );
        assert_eq!(
            normalize_mac_address("SGE-00:11:22:33:44:55").unwrap(),
            "SGE-00:11:22:33:44:55"
        );
        assert!(normalize_mac_address("INVALID").is_err());
    }

    #[test]
    fn test_extract_mac_components() {
        let components = extract_mac_components("SGE-00:11:22:33:44:55").unwrap();
        assert_eq!(components.prefix, "SGE");
        assert_eq!(components.bytes, vec![0, 17, 34, 51, 68, 85]);
    }

    #[test]
    fn test_is_unicast() {
        assert!(is_unicast("SGE-00:11:22:33:44:55").unwrap()); // Even first byte
        assert!(!is_unicast("SGE-01:11:22:33:44:55").unwrap()); // Odd first byte (multicast)
    }

    #[test]
    fn test_batch_validate_macs() {
        let macs = vec![
            "SGE-00:11:22:33:44:55".to_string(),
            "INVALID".to_string(),
            "00:11:22:33:44:55".to_string(),
        ];

        let (valid, invalid) = batch_validate_macs(&macs);
        assert_eq!(valid.len(), 2);
        assert_eq!(invalid.len(), 1);
    }
}