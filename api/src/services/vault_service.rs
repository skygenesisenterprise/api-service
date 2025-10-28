use reqwest::Client;
use serde_json::Value;
use std::env;
use std::collections::HashMap;

// Function to load default values from .env.example
fn load_defaults_from_env_example() -> HashMap<String, String> {
    let mut defaults = HashMap::new();

    // Read .env.example file
    if let Ok(content) = std::fs::read_to_string(".env.example") {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                defaults.insert(key.to_string(), value.to_string());
            }
        }
    }

    defaults
}

pub struct VaultService {
    client: Client,
    base_url: String,
    token: String,
}

impl VaultService {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let defaults = load_defaults_from_env_example();

        let base_url = env::var("VAULT_ADDR")
            .or_else(|_| env::var("VAULT_BASE_URL"))
            .unwrap_or_else(|_| defaults.get("VAULT_ADDR").unwrap_or(&"https://vault.skygenesisenterprise.com".to_string()).clone());
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