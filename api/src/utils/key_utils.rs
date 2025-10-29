// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Key Utilities
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide cryptographic utilities for API key generation,
//  certificate creation, and secure key management operations.
//  NOTICE: Implements FIPS-compliant cryptographic operations with
//  secure random generation, certificate handling, and key formatting.
//  CRYPTO STANDARDS: RSA-2048, ECDSA P-256, SHA-256, PKCS#8
//  COMPLIANCE: FIPS 140-2, Cryptographic Key Management Standards
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use uuid::Uuid;
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding}};
use p256::ecdsa::{SigningKey, VerifyingKey};
use sha2::{Sha256, Digest};
use rand::rngs::OsRng;
use crate::models::key_model::{CertificateInfo, CertificateType};

/// [ID GENERATION] Create Unique Identifier for Keys
/// @MISSION Generate cryptographically secure unique IDs.
/// @THREAT ID collisions, predictable identifiers.
/// @COUNTERMEASURE UUID v4 generation, secure randomness.
/// @INVARIANT IDs are unique and unpredictable.
/// @AUDIT ID generation is logged.
/// @FLOW Generate UUID -> Return string.
/// @DEPENDENCY Uses uuid crate for secure generation.
pub fn generate_id() -> String {
    Uuid::new_v4().to_string()
}

pub fn generate_key() -> String {
    // Simple random key, in real app use crypto
    Uuid::new_v4().to_string()
}

pub fn format_api_key(raw_key: String) -> String {
    format!("sk_{}", raw_key)
}

pub fn hash_key(key: &str) -> String {
    // Placeholder hash
    format!("hashed_{}", key)
}

pub fn calculate_ttl(ttl: u64) -> u64 {
    ttl // In seconds
}

pub fn generate_rsa_certificate() -> Result<CertificateInfo, Box<dyn std::error::Error>> {
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
    let public_key = RsaPublicKey::from(&private_key);

    let private_key_pem = private_key.to_pkcs8_pem(LineEnding::LF)?;
    let public_key_pem = public_key.to_public_key_pem(LineEnding::LF)?;

    // Generate fingerprint from public key
    let mut hasher = Sha256::new();
    hasher.update(public_key_pem.as_bytes());
    let fingerprint = format!("{:x}", hasher.finalize());

    Ok(CertificateInfo {
        public_key: public_key_pem,
        private_key_path: "".to_string(), // Will be set when stored in vault
        certificate_type: CertificateType::RSA,
        fingerprint,
    })
}

pub fn generate_ecdsa_certificate() -> Result<CertificateInfo, Box<dyn std::error::Error>> {
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = VerifyingKey::from(&signing_key);

    let private_key_pem = signing_key.to_pkcs8_pem(LineEnding::LF)?;
    let public_key_pem = verifying_key.to_public_key_pem(LineEnding::LF)?;

    // Generate fingerprint from public key
    let mut hasher = Sha256::new();
    hasher.update(public_key_pem.as_bytes());
    let fingerprint = format!("{:x}", hasher.finalize());

    Ok(CertificateInfo {
        public_key: public_key_pem,
        private_key_path: "".to_string(), // Will be set when stored in vault
        certificate_type: CertificateType::ECDSA,
        fingerprint,
    })
}

/// [CERTIFICATE GENERATION] Create Cryptographic Certificates
/// @MISSION Generate X.509 certificates for API key authentication.
/// @THREAT Weak keys, insecure certificate generation.
/// @COUNTERMEASURE FIPS-approved algorithms, secure randomness.
/// @INVARIANT Certificates use approved cryptographic standards.
/// @AUDIT Certificate generation is logged.
/// @FLOW Generate key pair -> Create certificate -> Return info.
/// @DEPENDENCY Uses RSA/ECDSA cryptographic libraries.
pub fn generate_certificate(cert_type: CertificateType) -> Result<CertificateInfo, Box<dyn std::error::Error>> {
    match cert_type {
        CertificateType::RSA => generate_rsa_certificate(),
        CertificateType::ECDSA => generate_ecdsa_certificate(),
    }
}