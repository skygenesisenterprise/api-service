use reqwest::Client;
use serde_json::Value;
use std::env;

pub struct VaultService {
    client: Client,
    base_url: String,
    token: String,
}

impl VaultService {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let base_url = env::var("VAULT_ADDR").unwrap_or("https://vault.skygenesisenterprise.com".to_string());
        let token = env::var("VAULT_TOKEN")?; // Assume token auth

        let client = Client::new();
        Ok(VaultService { client, base_url, token })
    }

    pub async fn get_secret(&self, path: &str) -> Result<Value, Box<dyn std::error::Error>> {
        let url = format!("{}/v1/{}", self.base_url, path);
        let response = self.client
            .get(&url)
            .header("X-Vault-Token", &self.token)
            .send()
            .await?
            .json::<Value>()
            .await?;
        Ok(response["data"]["data"].clone())
    }

    pub async fn set_secret(&self, path: &str, data: Value) -> Result<(), Box<dyn std::error::Error>> {
        let url = format!("{}/v1/{}", self.base_url, path);
        let payload = serde_json::json!({ "data": data });
        self.client
            .post(&url)
            .header("X-Vault-Token", &self.token)
            .json(&payload)
            .send()
            .await?;
        Ok(())
    }

    pub async fn link_key_to_secret(&self, key_id: &str, secret_path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mapping_path = format!("keys/{}", key_id);
        let data = serde_json::json!({ "secret_path": secret_path });
        self.set_secret(&mapping_path, data).await
    }

    pub async fn get_secret_for_key(&self, key_id: &str) -> Result<Value, Box<dyn std::error::Error>> {
        let mapping_path = format!("keys/{}", key_id);
        let mapping = self.get_secret(&mapping_path).await?;
        let secret_path = mapping["secret_path"].as_str().ok_or("Invalid mapping")?;
        self.get_secret(secret_path).await
    }
}