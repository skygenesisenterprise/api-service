// Models Rust mod

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
    pub vault_path: String, // Path in Vault where secrets are stored
    pub created_at: DateTime<Utc>,
    pub permissions: Vec<String>, // e.g., ["read", "write"]
}