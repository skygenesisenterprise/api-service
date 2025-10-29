// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Key Management Models
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Define data models for API key and certificate management
//  with enterprise security standards and compliance requirements.
//  NOTICE: Models implement secure key lifecycle management with
//  cryptographic standards, tenant isolation, and audit capabilities.
//  MODEL STANDARDS: Type Safety, Serialization, Validation
//  COMPLIANCE: FIPS 140-2, GDPR Data Protection, SOX Compliance
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// [KEY TYPE ENUM] API Key Usage Categories
/// @MISSION Classify API keys by their intended use case.
/// @THREAT Misuse of keys for unauthorized operations.
/// @COUNTERMEASURE Type-based permission restrictions.
/// @INVARIANT Key types determine access levels.
/// @AUDIT Key type usage is tracked.
/// @DEPENDENCY Used by ApiKey and key management services.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum KeyType {
    Client,
    Server,
    Database,
}

/// [CERTIFICATE TYPE ENUM] Cryptographic Certificate Algorithms
/// @MISSION Specify certificate cryptographic algorithms.
/// @THREAT Weak cryptographic algorithms, algorithm attacks.
/// @COUNTERMEASURE FIPS-approved algorithms only.
/// @INVARIANT Certificates use approved crypto.
/// @AUDIT Certificate types are logged.
/// @DEPENDENCY Used by CertificateInfo and key services.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum CertificateType {
    RSA,
    ECDSA,
}

/// [API KEY STATUS ENUM] Environment-Based Key Classification
/// @MISSION Separate sandbox and production environments.
/// @THREAT Production data access from sandbox keys.
/// @COUNTERMEASURE Environment isolation, status validation.
/// @INVARIANT Status determines key capabilities.
/// @AUDIT Status changes are logged.
/// @DEPENDENCY Used by ApiKey and access control.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ApiKeyStatus {
    #[serde(rename = "sandbox")]
    Sandbox,
    #[serde(rename = "production")]
    Production,
}

/// [CERTIFICATE INFO STRUCT] X.509 Certificate Metadata
/// @MISSION Store certificate information and cryptographic data.
/// @THREAT Private key exposure, certificate tampering.
/// @COUNTERMEASURE Secure key storage, fingerprint validation.
/// @INVARIANT Certificates are cryptographically verified.
/// @AUDIT Certificate operations are logged.
/// @DEPENDENCY Used by ApiKey for enhanced security.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CertificateInfo {
    pub public_key: String, // PEM encoded public key
    pub private_key_path: String, // Path in vault for private key
    pub certificate_type: CertificateType,
    pub fingerprint: String, // SHA256 fingerprint for verification
}

/// [API KEY STRUCT] Complete API Key Management Model
/// @MISSION Define comprehensive API key data structure.
/// @THREAT Key exposure, unauthorized key creation.
/// @COUNTERMEASURE Secure generation, vault storage, access control.
/// @INVARIANT Keys have proper metadata and restrictions.
/// @AUDIT Key lifecycle events are tracked.
/// @DEPENDENCY Core model for key management services.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApiKey {
    pub id: String,
    pub key: Option<String>, // The actual API key value, only returned on creation
    pub key_type: KeyType,
    pub tenant: String, // For isolation
    pub status: ApiKeyStatus, // Environment status: sandbox or production
    pub ttl: u64, // Time to live in seconds
    pub created_at: DateTime<Utc>,
    pub permissions: Vec<String>,
    pub vault_path: String,
    pub certificate: Option<CertificateInfo>, // Optional certificate for enhanced security
}