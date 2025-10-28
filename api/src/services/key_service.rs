use crate::core::vault::VaultClient;
use crate::models::key_model::{ApiKey, KeyType, CertificateInfo, CertificateType, ApiKeyStatus};
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

    pub async fn create_key(&self, key_type: KeyType, tenant: String, ttl: u64, status: ApiKeyStatus) -> Result<ApiKey, Box<dyn std::error::Error>> {
        self.create_key_with_certificate(key_type, tenant, ttl, false, status).await
    }

    pub async fn create_key_with_certificate(&self, key_type: KeyType, tenant: String, ttl: u64, with_certificate: bool, status: ApiKeyStatus) -> Result<ApiKey, Box<dyn std::error::Error>> {
        let cert_type = if with_certificate {
            Some(match key_type {
                KeyType::Client => CertificateType::RSA,
                KeyType::Server => CertificateType::ECDSA,
                KeyType::Database => CertificateType::RSA,
            })
        } else {
            None
        };
        self.create_key_with_certificate_specific(key_type, tenant, ttl, cert_type.unwrap_or(CertificateType::RSA), status).await
    }

    pub async fn create_key_with_certificate_specific(&self, key_type: KeyType, tenant: String, ttl: u64, cert_type: CertificateType, status: ApiKeyStatus) -> Result<ApiKey, Box<dyn std::error::Error>> {
        let id = key_utils::generate_id();
        let key_value = self.vault.rotate_key(&format!("{:?}", key_type).to_lowercase()).await?;

        let mut cert = key_utils::generate_certificate(cert_type)?;
        // Store private key in vault
        let private_key_path = format!("secret/certificates/{}/private", id);
        self.vault.set_secret(&private_key_path, serde_json::json!({
            "private_key": cert.public_key.clone() // Note: In real implementation, store actual private key
        })).await?;
        cert.private_key_path = private_key_path;

        let api_key = ApiKey {
            id: id.clone(),
            key: Some(key_value.clone()),
            key_type,
            tenant,
            status,
            ttl,
            created_at: chrono::Utc::now(),
            permissions: vec!["read".to_string()],
            vault_path: format!("secret/{:?}", key_type).to_lowercase(),
            certificate: Some(cert),
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

    // Convenience methods for creating sandbox and production keys
    pub async fn create_sandbox_key(&self, key_type: KeyType, tenant: String, ttl: u64) -> Result<ApiKey, Box<dyn std::error::Error>> {
        self.create_key(key_type, tenant, ttl, ApiKeyStatus::Sandbox).await
    }

    pub async fn create_production_key(&self, key_type: KeyType, tenant: String, ttl: u64) -> Result<ApiKey, Box<dyn std::error::Error>> {
        self.create_key(key_type, tenant, ttl, ApiKeyStatus::Production).await
    }

    pub async fn create_sandbox_key_with_certificate(&self, key_type: KeyType, tenant: String, ttl: u64, with_certificate: bool) -> Result<ApiKey, Box<dyn std::error::Error>> {
        self.create_key_with_certificate(key_type, tenant, ttl, with_certificate, ApiKeyStatus::Sandbox).await
    }

    pub async fn create_production_key_with_certificate(&self, key_type: KeyType, tenant: String, ttl: u64, with_certificate: bool) -> Result<ApiKey, Box<dyn std::error::Error>> {
        self.create_key_with_certificate(key_type, tenant, ttl, with_certificate, ApiKeyStatus::Production).await
    }

    // Validation methods for status-based access control
    pub fn validate_key_status(&self, api_key: &ApiKey, required_status: &ApiKeyStatus) -> Result<(), Box<dyn std::error::Error>> {
        match (&api_key.status, required_status) {
            (ApiKeyStatus::Sandbox, ApiKeyStatus::Sandbox) => Ok(()),
            (ApiKeyStatus::Production, ApiKeyStatus::Production) => Ok(()),
            (ApiKeyStatus::Production, ApiKeyStatus::Sandbox) => Ok(()), // Production keys can access sandbox
            (ApiKeyStatus::Sandbox, ApiKeyStatus::Production) => {
                Err("Sandbox API key cannot access production resources".into())
            }
        }
    }

    pub fn is_production_key(&self, api_key: &ApiKey) -> bool {
        matches!(api_key.status, ApiKeyStatus::Production)
    }

    pub fn is_sandbox_key(&self, api_key: &ApiKey) -> bool {
        matches!(api_key.status, ApiKeyStatus::Sandbox)
    }
}