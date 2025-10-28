use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use crate::core::vault::VaultClient;
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

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: String,
    expires_in: u64,
}

#[derive(Serialize)]
struct LoginRequest {
    grant_type: String,
    client_id: String,
    client_secret: String,
    username: String,
    password: String,
}

#[derive(Serialize)]
struct RegisterRequest {
    username: String,
    email: String,
    first_name: Option<String>,
    last_name: Option<String>,
    enabled: bool,
    credentials: Vec<Credential>,
}

#[derive(Serialize)]
struct Credential {
    #[serde(rename = "type")]
    cred_type: String,
    value: String,
    temporary: bool,
}

pub struct KeycloakClient {
    client: Client,
    base_url: String,
    realm: String,
    client_id: String,
    client_secret: String,
}

impl KeycloakClient {
    pub async fn new(vault: Arc<VaultClient>) -> Result<Self, Box<dyn std::error::Error>> {
        // Load defaults from .env.example
        let defaults = super::load_defaults_from_env_example();

        let base_url = std::env::var("KEYCLOAK_URL")
            .or_else(|_| std::env::var("KEYCLOAK_BASE_URL"))
            .unwrap_or_else(|_| defaults.get("KEYCLOAK_URL").unwrap_or(&"https://keycloak.skygenesisenterprise.com".to_string()).clone());
        let realm = std::env::var("KEYCLOAK_REALM").unwrap_or("skygenesisenterpirse".to_string());
        let client_id = std::env::var("KEYCLOAK_CLIENT_ID").unwrap_or("api-client".to_string());
        let client_secret = vault.get_secret("keycloak/client_secret").await?["data"].as_str().unwrap().to_string();

        Ok(KeycloakClient {
            client: Client::new(),
            base_url,
            realm,
            client_id,
            client_secret,
        })
    }

    pub async fn login(&self, email: &str, password: &str) -> Result<TokenResponse, Box<dyn std::error::Error>> {
        let url = format!("{}/realms/{}/protocol/openid-connect/token", self.base_url, self.realm);
        let req = LoginRequest {
            grant_type: "password".to_string(),
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
            username: email.to_string(),
            password: password.to_string(),
        };
        let response = self.client.post(&url).form(&req).send().await?;
        let token: TokenResponse = response.json().await?;
        Ok(token)
    }

    pub async fn register(&self, user: &crate::models::user::User, password: &str) -> Result<(), Box<dyn std::error::Error>> {
        let url = format!("{}/admin/realms/{}/users", self.base_url, self.realm);
        let admin_token = self.get_admin_token().await?;
        let req = RegisterRequest {
            username: user.email.clone(),
            email: user.email.clone(),
            first_name: user.first_name.clone(),
            last_name: user.last_name.clone(),
            enabled: user.enabled,
            credentials: vec![Credential {
                cred_type: "password".to_string(),
                value: password.to_string(),
                temporary: false,
            }],
        };
        self.client.post(&url)
            .header("Authorization", format!("Bearer {}", admin_token))
            .json(&req)
            .send().await?;
        Ok(())
    }

    pub async fn recover_password(&self, email: &str) -> Result<(), Box<dyn std::error::Error>> {
        // Implement forgot password
        Ok(())
    }

    pub async fn get_user_info(&self, access_token: &str) -> Result<Value, Box<dyn std::error::Error>> {
        let url = format!("{}/realms/{}/protocol/openid-connect/userinfo", self.base_url, self.realm);
        let response = self.client.get(&url)
            .header("Authorization", format!("Bearer {}", access_token))
            .send().await?;
        let info: Value = response.json().await?;
        Ok(info)
    }

    async fn get_admin_token(&self) -> Result<String, Box<dyn std::error::Error>> {
        // Assume admin login
        let token = self.login("admin", "admin_password").await?;
        Ok(token.access_token)
    }
}