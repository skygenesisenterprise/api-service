use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum KeyType {
    Client,
    Server,
    Database,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum CertificateType {
    RSA,
    ECDSA,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CertificateInfo {
    pub public_key: String, // PEM encoded public key
    pub private_key_path: String, // Path in vault for private key
    pub certificate_type: CertificateType,
    pub fingerprint: String, // SHA256 fingerprint for verification
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApiKey {
    pub id: String,
    pub key: Option<String>, // The actual API key value, only returned on creation
    pub key_type: KeyType,
    pub tenant: String, // For isolation
    pub ttl: u64, // Time to live in seconds
    pub created_at: DateTime<Utc>,
    pub permissions: Vec<String>,
    pub vault_path: String,
    pub certificate: Option<CertificateInfo>, // Optional certificate for enhanced security
}