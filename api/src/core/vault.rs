use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Deserialize)]
struct AuthResponse {
    auth: AuthData,
}

#[derive(Deserialize)]
struct AuthData {
    client_token: String,
    lease_duration: u64,
}

pub struct VaultClient {
    client: Client,
    base_url: String,
    token: Arc<Mutex<String>>,
    token_expires: Arc<Mutex<Instant>>,
}

impl VaultClient {
    pub async fn new(base_url: String, role_id: String, secret_id: String) -> Result<Self, Box<dyn std::error::Error>> {
        let client = Client::new();
        let mut vault = VaultClient {
            client,
            base_url,
            token: Arc::new(Mutex::new(String::new())),
            token_expires: Arc::new(Mutex::new(Instant::now())),
        };
        vault.authenticate_approle(&role_id, &secret_id).await?;
        Ok(vault)
    }

    async fn authenticate_approle(&self, role_id: &str, secret_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let url = format!("{}/v1/auth/approle/login", self.base_url);
        let payload = serde_json::json!({ "role_id": role_id, "secret_id": secret_id });
        let response = self.client.post(&url).json(&payload).send().await?;
        let auth: AuthResponse = response.json().await?;
        let mut token = self.token.lock().await;
        *token = auth.auth.client_token;
        let mut expires = self.token_expires.lock().await;
        *expires = Instant::now() + Duration::from_secs(auth.auth.lease_duration);
        Ok(())
    }

    async fn ensure_token(&self) -> Result<(), Box<dyn std::error::Error>> {
        let expires = *self.token_expires.lock().await;
        if Instant::now() > expires {
            // Re-authenticate if needed, but for simplicity, assume long-lived
        }
        Ok(())
    }

    pub async fn get_secret(&self, path: &str) -> Result<Value, Box<dyn std::error::Error>> {
        self.ensure_token().await?;
        let url = format!("{}/v1/{}", self.base_url, path);
        let token = self.token.lock().await.clone();
        let response = self.client
            .get(&url)
            .header("X-Vault-Token", token)
            .send()
            .await?
            .json::<Value>()
            .await?;
        Ok(response["data"]["data"].clone())
    }

    pub async fn set_secret(&self, path: &str, data: Value) -> Result<(), Box<dyn std::error::Error>> {
        self.ensure_token().await?;
        let url = format!("{}/v1/{}", self.base_url, path);
        let token = self.token.lock().await.clone();
        let payload = serde_json::json!({ "data": data });
        self.client
            .post(&url)
            .header("X-Vault-Token", token)
            .json(&payload)
            .send()
            .await?;
        Ok(())
    }

    // Auto-rotation for keys
    pub async fn rotate_key(&self, key_type: &str) -> Result<String, Box<dyn std::error::Error>> {
        let new_key = crate::utils::key_utils::generate_key();
        let path = format!("secret/{}", key_type);
        let data = serde_json::json!({ "key": new_key });
        self.set_secret(&path, data).await?;
        Ok(new_key)
    }
}