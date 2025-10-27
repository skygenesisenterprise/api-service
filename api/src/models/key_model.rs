use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum KeyType {
    Client,
    Server,
    Database,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApiKey {
    pub id: String,
    pub key_type: KeyType,
    pub tenant: String, // For isolation
    pub ttl: u64, // Time to live in seconds
    pub created_at: DateTime<Utc>,
    pub permissions: Vec<String>,
    pub vault_path: String,
}