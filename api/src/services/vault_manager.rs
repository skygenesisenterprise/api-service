use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};


#[derive(Debug, Serialize, Deserialize)]
struct VaultSecret {
    data: Value,
    lease_id: Option<String>,
    lease_duration: Option<u64>,
    renewable: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct KeyData {
    pub value: Value,
    pub expires_at: Instant,
    pub lease_id: Option<String>,
}

pub struct VaultManager {
    client: Client,
    base_url: String,
    token: String,
    cache: Arc<Mutex<HashMap<String, KeyData>>>,
}

impl VaultManager {
    pub fn new(vault_addr: String, token: String) -> Self {
        let client = Client::new();
        let cache = Arc::new(Mutex::new(HashMap::new()));
        VaultManager {
            client,
            base_url: vault_addr,
            token,
            cache,
        }
    }

    async fn fetch_secret(&self, path: &str) -> Result<VaultSecret, Box<dyn std::error::Error>> {
        let url = format!("{}/v1/{}", self.base_url, path);
        let response = self.client
            .get(&url)
            .header("X-Vault-Token", &self.token)
            .send()
            .await?
            .json::<VaultSecret>()
            .await?;
        Ok(response)
    }

    async fn renew_lease(&self, lease_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let url = format!("{}/v1/sys/leases/renew", self.base_url);
        let payload = serde_json::json!({ "lease_id": lease_id });
        self.client
            .post(&url)
            .header("X-Vault-Token", &self.token)
            .json(&payload)
            .send()
            .await?;
        Ok(())
    }

    async fn get_or_fetch_key(&self, key_type: &str) -> Result<Value, Box<dyn std::error::Error>> {
        let cache_key = key_type.to_string();
        {
            let cache = self.cache.lock().unwrap();
            if let Some(cached) = cache.get(&cache_key) {
                if Instant::now() < cached.expires_at {
                    return Ok(cached.value.clone());
                } else if let Some(lease_id) = &cached.lease_id {
                    // Try to renew
                    if let Ok(_) = self.renew_lease(lease_id).await {
                        // Update expiration
                        let mut cache = self.cache.lock().unwrap();
                        if let Some(mut entry) = cache.get_mut(&cache_key) {
                            entry.expires_at = Instant::now() + Duration::from_secs(3600); // Assume 1 hour renewal
                        }
                        return Ok(cached.value.clone());
                    }
                }
            }
        }

        // Fetch from Vault
        let path = format!("secret/{}", key_type);
        let secret = self.fetch_secret(&path).await?;
        let key_data = KeyData {
            value: secret.data,
            expires_at: Instant::now() + Duration::from_secs(secret.lease_duration.unwrap_or(3600)),
            lease_id: secret.lease_id,
        };

        let mut cache = self.cache.lock().unwrap();
        cache.insert(cache_key, key_data.clone());

        Ok(key_data.value)
    }

    pub async fn get_client_key(&self) -> Result<Value, Box<dyn std::error::Error>> {
        self.get_or_fetch_key("client").await
    }

    pub async fn get_server_key(&self) -> Result<Value, Box<dyn std::error::Error>> {
        self.get_or_fetch_key("server").await
    }

    pub async fn get_database_key(&self) -> Result<Value, Box<dyn std::error::Error>> {
        self.get_or_fetch_key("database").await
    }

    // For Zero Trust validation
    pub async fn validate_access(&self, key_type: &str, provided_key: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let secret = self.get_or_fetch_key(key_type).await?;
        // Assume the secret contains the valid key
        if let Some(valid_key) = secret.get("key").and_then(|v| v.as_str()) {
            Ok(valid_key == provided_key)
        } else {
            Ok(false)
        }
    }
}