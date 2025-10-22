use reqwest;
use serde::{Deserialize, Serialize};
use std::error::Error;

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthResponse {
    pub message: String,
    pub data: serde_json::Value,
}

pub struct AuthService;

impl AuthService {
    pub async fn authenticate(username: &str, password: &str) -> Result<serde_json::Value, Box<dyn Error>> {
        let client = reqwest::Client::new();
        let request_body = AuthRequest {
            username: username.to_string(),
            password: password.to_string(),
        };

        let response = client
            .post("https://sso.skygenesisenterprise.com/auth")
            .json(&request_body)
            .send()
            .await?;

        if response.status().is_success() {
            let auth_response: AuthResponse = response.json().await?;
            Ok(auth_response.data)
        } else {
            Err("Authentication failed".into())
        }
    }
}