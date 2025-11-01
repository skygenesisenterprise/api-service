// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: OpenPGP Models
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Define data models for OpenPGP cryptographic operations
//  with enterprise security standards and compliance requirements.
//  NOTICE: Models implement secure PGP key and message management with
//  cryptographic standards, tenant isolation, and audit capabilities.
//  MODEL STANDARDS: Type Safety, Serialization, Validation
//  COMPLIANCE: RFC 4880, GDPR Data Protection, Cryptographic Standards
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// [OPENPGP KEY TYPE ENUM] PGP Key Usage Categories
/// @MISSION Classify PGP keys by their intended use case.
/// @THREAT Misuse of keys for unauthorized operations.
/// @COUNTERMEASURE Type-based permission restrictions.
/// @INVARIANT Key types determine access levels.
/// @AUDIT Key type usage is tracked.
/// @DEPENDENCY Used by OpenPGPKey and key management services.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum OpenPGPKeyType {
    #[serde(rename = "signing")]
    Signing,
    #[serde(rename = "encryption")]
    Encryption,
    #[serde(rename = "authentication")]
    Authentication,
    #[serde(rename = "general")]
    General,
}

/// [OPENPGP KEY STATUS ENUM] Key Lifecycle States
/// @MISSION Track PGP key lifecycle states.
/// @THREAT Use of revoked or expired keys.
/// @COUNTERMEASURE Status validation and revocation checking.
/// @INVARIANT Status determines key usability.
/// @AUDIT Status changes are logged.
/// @DEPENDENCY Used by OpenPGPKey and access control.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum OpenPGPKeyStatus {
    #[serde(rename = "active")]
    Active,
    #[serde(rename = "revoked")]
    Revoked,
    #[serde(rename = "expired")]
    Expired,
}

/// [OPENPGP KEY STRUCT] Complete PGP Key Management Model
/// @MISSION Define comprehensive PGP key data structure.
/// @THREAT Key exposure, unauthorized key creation.
/// @COUNTERMEASURE Secure generation, vault storage, access control.
/// @INVARIANT Keys have proper metadata and restrictions.
/// @AUDIT Key lifecycle events are tracked.
/// @DEPENDENCY Core model for PGP key management services.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OpenPGPKey {
    pub id: String,
    pub fingerprint: String,
    pub key_type: OpenPGPKeyType,
    pub tenant: String, // For isolation
    pub status: OpenPGPKeyStatus,
    pub userid: String,
    pub public_key: String, // Base64 encoded public key
    pub private_key_path: Option<String>, // Path in vault for private key (if stored)
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub algorithm: String, // e.g., "RSA", "Ed25519"
    pub key_size: Option<u32>, // For RSA keys
}

/// [OPENPGP SIGNATURE STRUCT] PGP Signature Information
/// @MISSION Store signature metadata and verification data.
/// @THREAT Signature forgery, invalid signatures.
/// @COUNTERMEASURE Cryptographic verification, timestamp validation.
/// @INVARIANT Signatures are cryptographically verified.
/// @AUDIT Signature operations are logged.
/// @DEPENDENCY Used by signature verification operations.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OpenPGPSignature {
    pub id: String,
    pub message_hash: String, // Hash of the signed message
    pub signature_data: String, // Base64 encoded signature
    pub key_fingerprint: String,
    pub signed_at: DateTime<Utc>,
    pub verified: bool,
    pub algorithm: String,
}

/// [OPENPGP MESSAGE STRUCT] Encrypted/Signed Message Container
/// @MISSION Structure encrypted or signed message data.
/// @THREAT Message tampering, unauthorized decryption.
/// @COUNTERMEASURE Integrity verification, access control.
/// @INVARIANT Messages maintain cryptographic integrity.
/// @AUDIT Message operations are logged.
/// @DEPENDENCY Used by encryption/decryption operations.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OpenPGPMessage {
    pub id: String,
    pub content: String, // Base64 encoded message content
    pub message_type: OpenPGPMessageType,
    pub sender_fingerprint: Option<String>,
    pub recipient_fingerprints: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub encrypted: bool,
    pub signed: bool,
}

/// [OPENPGP MESSAGE TYPE ENUM] Message Content Classification
/// @MISSION Classify message types for processing.
/// @THREAT Incorrect message processing.
/// @COUNTERMEASURE Type-based validation and handling.
/// @INVARIANT Messages are processed according to type.
/// @AUDIT Message type usage is tracked.
/// @DEPENDENCY Used by OpenPGPMessage processing.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum OpenPGPMessageType {
    #[serde(rename = "text")]
    Text,
    #[serde(rename = "binary")]
    Binary,
    #[serde(rename = "certificate")]
    Certificate,
}

/// [OPENPGP REQUEST STRUCTS] API Request/Response Models
/// @MISSION Define request/response structures for API operations.
/// @THREAT Invalid input data, malformed requests.
/// @COUNTERMEASURE Input validation, type safety.
/// @INVARIANT Requests are validated before processing.
/// @AUDIT Request processing is logged.
/// @DEPENDENCY Used by OpenPGP controllers.

#[derive(Debug, Deserialize)]
pub struct GenerateKeyRequest {
    pub userid: String,
    pub key_type: Option<OpenPGPKeyType>,
}

#[derive(Debug, Serialize)]
pub struct GenerateKeyResponse {
    pub success: bool,
    pub key: Option<OpenPGPKey>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SignMessageRequest {
    pub message: String,
    pub private_key: String,
    pub key_fingerprint: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SignMessageResponse {
    pub success: bool,
    pub signature: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VerifySignatureRequest {
    pub message: String,
    pub signature: String,
    pub public_key: String,
}

#[derive(Debug, Serialize)]
pub struct VerifySignatureResponse {
    pub success: bool,
    pub valid: Option<bool>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EncryptMessageRequest {
    pub message: String,
    pub public_key: String,
    pub message_type: Option<OpenPGPMessageType>,
}

#[derive(Debug, Serialize)]
pub struct EncryptMessageResponse {
    pub success: bool,
    pub encrypted_message: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DecryptMessageRequest {
    pub encrypted_message: String,
    pub private_key: String,
}

#[derive(Debug, Serialize)]
pub struct DecryptMessageResponse {
    pub success: bool,
    pub decrypted_message: Option<String>,
    pub error: Option<String>,
}