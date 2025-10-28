use uuid::Uuid;
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding}};
use p256::ecdsa::{SigningKey, VerifyingKey};
use sha2::{Sha256, Digest};
use rand::rngs::OsRng;
use crate::models::key_model::{CertificateInfo, CertificateType};

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

pub fn generate_certificate(cert_type: CertificateType) -> Result<CertificateInfo, Box<dyn std::error::Error>> {
    match cert_type {
        CertificateType::RSA => generate_rsa_certificate(),
        CertificateType::ECDSA => generate_ecdsa_certificate(),
    }
}