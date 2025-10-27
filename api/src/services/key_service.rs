use crate::core::vault::VaultClient;
use crate::models::key_model::{ApiKey, KeyType};
use crate::queries::key_queries;
use crate::utils::key_utils;
use std::sync::Arc;

pub struct KeyService {
    vault: Arc<VaultClient>,
}

impl KeyService {
    pub fn new(vault: Arc<VaultClient>) -> Self {
        KeyService { vault }
    }

    pub async fn create_key(&self, key_type: KeyType, tenant: String, ttl: u64) -> Result<ApiKey, Box<dyn std::error::Error>> {
        let id = key_utils::generate_id();
        let key_value = self.vault.rotate_key(&format!("{:?}", key_type).to_lowercase()).await?;
        let api_key = ApiKey {
            id: id.clone(),
            key_type,
            tenant,
            ttl,
            created_at: chrono::Utc::now(),
            permissions: vec!["read".to_string()],
            vault_path: format!("secret/{:?}", key_type).to_lowercase(),
        };
        // Log to DB
        key_queries::log_key_creation(&id).await?;
        Ok(api_key)
    }

    pub async fn revoke_key(&self, id: &str) -> Result<(), Box<dyn std::error::Error>> {
        // Revoke in Vault if possible, or mark as revoked
        key_queries::revoke_key(id).await?;
        Ok(())
    }

    pub async fn get_key(&self, id: &str) -> Result<ApiKey, Box<dyn std::error::Error>> {
        key_queries::get_key(id).await
    }

    pub async fn list_keys(&self, tenant: &str) -> Result<Vec<ApiKey>, Box<dyn std::error::Error>> {
        key_queries::list_keys_by_tenant(tenant).await
    }
}