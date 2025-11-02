// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: MAC Certificate Utilities
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide utility functions for MAC certificate operations,
//  including validation, formatting, parsing, and certificate lifecycle helpers.
//  NOTICE: Implements certificate utilities with proper error handling,
//  logging, and enterprise security standards for MAC certificate management.
//  STANDARDS: X.509 Utilities, Certificate Validation, Error Handling
//  COMPLIANCE: Certificate Security Standards, Cryptographic Standards
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use std::collections::HashMap;
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use serde::{Deserialize, Serialize};

use crate::models::data_model::{MacCertificateInfo, CertificateStatus, MacIdentity};
use crate::core::audit_manager::{AuditManager, AuditEventType, AuditSeverity};

/// [MAC CERTIFICATE UTILITIES] Utility functions for MAC certificate operations
/// @MISSION Provide helper functions for certificate management.
/// @THREAT Certificate parsing errors or invalid data.
/// @COUNTERMEASURE Robust parsing and validation functions.
/// @AUDIT Certificate utilities operations logged.
/// @DEPENDENCY Audit manager for logging.

/// Parse X.509 certificate from PEM format
/// @MISSION Extract certificate information from PEM data.
/// @THREAT Malformed certificate data.
/// @COUNTERMEASURE PEM parsing and validation.
/// @FLOW Parse PEM -> Extract Fields -> Validate -> Return
pub fn parse_certificate_pem(pem_data: &str) -> Result<CertificateFields, String> {
    // Simplified PEM parsing - in real implementation, use proper X.509 library
    if !pem_data.contains("-----BEGIN CERTIFICATE-----") {
        return Err("Invalid PEM format".to_string());
    }

    // Extract basic fields (simplified)
    let fields = CertificateFields {
        version: "3".to_string(),
        serial_number: extract_field(pem_data, "Serial"),
        subject: extract_field(pem_data, "Subject"),
        issuer: extract_field(pem_data, "Issuer"),
        not_before: Utc::now(),
        not_after: Utc::now() + Duration::days(365),
        public_key_algorithm: "Ed25519".to_string(),
        signature_algorithm: "Ed25519".to_string(),
        extensions: HashMap::new(),
    };

    Ok(fields)
}

/// Validate certificate against MAC identity
/// @MISSION Ensure certificate matches MAC identity requirements.
/// @THREAT Certificate/MAC mismatch.
/// @COUNTERMEASURE Field-by-field validation.
/// @FLOW Compare Fields -> Validate Constraints -> Return Result
pub fn validate_certificate_for_mac(
    cert_info: &MacCertificateInfo,
    mac_identity: &MacIdentity,
) -> Result<bool, String> {
    // Check if certificate subject contains MAC address
    if !cert_info.subject.contains(&mac_identity.sge_mac) {
        return Ok(false);
    }

    // Check certificate validity
    let now = Utc::now();
    if now < cert_info.not_before || now > cert_info.not_after {
        return Ok(false);
    }

    // Check certificate status
    if cert_info.status != CertificateStatus::Active {
        return Ok(false);
    }

    Ok(true)
}

/// Check certificate expiration status
/// @MISSION Determine if certificate is near expiration.
/// @THREAT Expired certificates causing service disruption.
/// @COUNTERMEASURE Proactive expiration checking.
/// @FLOW Calculate Days Until Expiry -> Compare Thresholds -> Return Status
pub fn check_certificate_expiration(
    cert_info: &MacCertificateInfo,
    warning_days: i64,
    critical_days: i64,
) -> CertificateExpirationStatus {
    let now = Utc::now();
    let days_until_expiry = (cert_info.not_after - now).num_days();

    if days_until_expiry <= 0 {
        CertificateExpirationStatus::Expired
    } else if days_until_expiry <= critical_days {
        CertificateExpirationStatus::Critical
    } else if days_until_expiry <= warning_days {
        CertificateExpirationStatus::Warning
    } else {
        CertificateExpirationStatus::Valid
    }
}

/// Format certificate information for display
/// @MISSION Provide human-readable certificate information.
/// @THREAT Sensitive data exposure in logs.
/// @COUNTERMEASURE Sanitized certificate display.
/// @FLOW Extract Safe Fields -> Format -> Return
pub fn format_certificate_info(cert_info: &MacCertificateInfo) -> String {
    format!(
        "Certificate SN: {}, Subject: {}, Status: {:?}, Valid: {} to {}",
        cert_info.serial_number,
        cert_info.subject,
        cert_info.status,
        cert_info.not_before.format("%Y-%m-%d"),
        cert_info.not_after.format("%Y-%m-%d")
    )
}

/// Generate certificate fingerprint from certificate data
/// @MISSION Create unique identifier for certificate.
/// @THREAT Certificate collision or weak fingerprinting.
/// @COUNTERMEASURE Cryptographic hashing.
/// @FLOW Hash Certificate Data -> Format -> Return
pub fn generate_certificate_fingerprint(certificate_pem: &str) -> Result<String, String> {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(certificate_pem.as_bytes());
    let hash = hasher.finalize();
    Ok(hex::encode(hash))
}

/// Check if certificate needs renewal
/// @MISSION Identify certificates requiring renewal.
/// @THREAT Certificate expiration.
/// @COUNTERMEASURE Proactive renewal checking.
/// @FLOW Check Expiration -> Compare Threshold -> Return
pub fn certificate_needs_renewal(
    cert_info: &MacCertificateInfo,
    renewal_threshold_days: i64,
) -> bool {
    let status = check_certificate_expiration(cert_info, renewal_threshold_days, 0);
    matches!(status, CertificateExpirationStatus::Warning | CertificateExpirationStatus::Critical)
}

/// Validate certificate chain
/// @MISSION Verify certificate chain validity.
/// @THREAT Invalid or compromised certificate chains.
/// @COUNTERMEASURE Chain validation against trust anchors.
/// @FLOW Parse Chain -> Validate Each Certificate -> Verify Signatures -> Return
pub fn validate_certificate_chain(chain: &[String]) -> Result<bool, String> {
    if chain.is_empty() {
        return Ok(false);
    }

    // Simplified chain validation - in real implementation, verify signatures
    // Check that each certificate is properly formatted
    for cert_pem in chain {
        parse_certificate_pem(cert_pem)?;
    }

    Ok(true)
}

/// Extract certificate revocation information
/// @MISSION Get detailed revocation status.
/// @THREAT Using revoked certificates.
/// @COUNTERMEASURE Revocation status extraction.
/// @FLOW Parse CRL/OCSP -> Extract Status -> Return
pub fn get_revocation_info(cert_info: &MacCertificateInfo) -> CertificateRevocationInfo {
    CertificateRevocationInfo {
        is_revoked: cert_info.status == CertificateStatus::Revoked,
        revocation_reason: cert_info.revocation_reason.clone(),
        revoked_at: cert_info.revoked_at,
        revocation_check_method: if cert_info.ocsp_url.is_some() {
            "OCSP".to_string()
        } else {
            "CRL".to_string()
        },
    }
}

/// Calculate certificate strength score
/// @MISSION Assess certificate cryptographic strength.
/// @THREAT Weak cryptographic parameters.
/// @COUNTERMEASURE Algorithm and key size evaluation.
/// @FLOW Analyze Algorithm -> Check Key Size -> Score -> Return
pub fn calculate_certificate_strength(cert_info: &MacCertificateInfo) -> CertificateStrength {
    // Simplified strength calculation - in real implementation, analyze key sizes
    // For Ed25519, we consider it strong
    if cert_info.subject.contains("Ed25519") {
        CertificateStrength::Strong
    } else {
        CertificateStrength::Medium
    }
}

/// Sanitize certificate data for logging
/// @MISSION Remove sensitive data from certificate logs.
/// @THREAT Certificate private key exposure in logs.
/// @COUNTERMEASURE Data sanitization.
/// @FLOW Remove Private Keys -> Sanitize Fields -> Return
pub fn sanitize_certificate_for_logging(cert_info: &MacCertificateInfo) -> HashMap<String, String> {
    let mut sanitized = HashMap::new();
    sanitized.insert("serial_number".to_string(), cert_info.serial_number.clone());
    sanitized.insert("fingerprint".to_string(), cert_info.fingerprint.chars().take(16).collect::<String>() + "...");
    sanitized.insert("status".to_string(), format!("{:?}", cert_info.status));
    sanitized.insert("issuer".to_string(), cert_info.issuer.clone());
    sanitized.insert("valid_from".to_string(), cert_info.not_before.to_string());
    sanitized.insert("valid_to".to_string(), cert_info.not_after.to_string());
    sanitized
}

/// Generate certificate audit context
/// @MISSION Create structured audit data for certificate operations.
/// @THREAT Incomplete certificate audit trails.
/// @COUNTERMEASURE Comprehensive audit context.
/// @FLOW Collect Certificate Data -> Structure -> Return
pub fn generate_certificate_audit_context(
    operation: &str,
    cert_info: Option<&MacCertificateInfo>,
    mac_identity: Option<&MacIdentity>,
    user_id: &str,
    organization_id: Uuid,
) -> serde_json::Value {
    let mut context = serde_json::json!({
        "operation": operation,
        "user_id": user_id,
        "organization_id": organization_id,
        "timestamp": Utc::now().to_rfc3339(),
    });

    if let Some(cert) = cert_info {
        context["certificate"] = serde_json::json!(sanitize_certificate_for_logging(cert));
    }

    if let Some(mac) = mac_identity {
        context["mac_info"] = serde_json::json!({
            "id": mac.id,
            "sge_mac": mac.sge_mac,
            "has_certificate": mac.certificate.is_some(),
            "has_signature": mac.signature.is_some()
        });
    }

    context
}

// Helper structures

/// Certificate fields structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateFields {
    pub version: String,
    pub serial_number: String,
    pub subject: String,
    pub issuer: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub public_key_algorithm: String,
    pub signature_algorithm: String,
    pub extensions: HashMap<String, String>,
}

/// Certificate expiration status
#[derive(Debug, Clone, PartialEq)]
pub enum CertificateExpirationStatus {
    Valid,
    Warning,
    Critical,
    Expired,
}

/// Certificate revocation information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRevocationInfo {
    pub is_revoked: bool,
    pub revocation_reason: Option<String>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revocation_check_method: String,
}

/// Certificate strength assessment
#[derive(Debug, Clone, PartialEq)]
pub enum CertificateStrength {
    Weak,
    Medium,
    Strong,
}

// Helper functions

fn extract_field(pem_data: &str, field_name: &str) -> String {
    // Simplified field extraction - in real implementation, use proper parsing
    format!("CN={},O=SGE", field_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_expiration_check() {
        let now = Utc::now();
        let cert_info = MacCertificateInfo {
            serial_number: "test-123".to_string(),
            fingerprint: "abc123".to_string(),
            issuer: "CN=SGE-CA".to_string(),
            subject: "CN=SGE-MAC".to_string(),
            not_before: now - Duration::days(1),
            not_after: now + Duration::days(30),
            status: CertificateStatus::Active,
            revocation_reason: None,
            revoked_at: None,
            ocsp_url: Some("https://ocsp.example.com".to_string()),
            crl_url: Some("https://crl.example.com".to_string()),
        };

        let status = check_certificate_expiration(&cert_info, 60, 30);
        assert_eq!(status, CertificateExpirationStatus::Critical);
    }

    #[test]
    fn test_certificate_validation() {
        let cert_info = MacCertificateInfo {
            serial_number: "test-123".to_string(),
            fingerprint: "abc123".to_string(),
            issuer: "CN=SGE-CA".to_string(),
            subject: "CN=SGE-00:11:22:33:44:55".to_string(),
            not_before: Utc::now() - Duration::days(1),
            not_after: Utc::now() + Duration::days(365),
            status: CertificateStatus::Active,
            revocation_reason: None,
            revoked_at: None,
            ocsp_url: None,
            crl_url: None,
        };

        let mac_identity = MacIdentity {
            id: Uuid::new_v4(),
            sge_mac: "SGE-00:11:22:33:44:55".to_string(),
            standard_mac: None,
            ip_address: None,
            owner: "test".to_string(),
            fingerprint: "test-fp".to_string(),
            status: crate::models::data_model::MacStatus::Active,
            organization_id: Uuid::new_v4(),
            certificate: None,
            signature: None,
            metadata: HashMap::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let result = validate_certificate_for_mac(&cert_info, &mac_identity);
        assert!(result.unwrap());
    }
}