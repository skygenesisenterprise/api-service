use actix_web::{web, HttpResponse, Result, http::StatusCode};
use serde::{Deserialize, Serialize};
use reqwest::Client;
use std::env;

#[derive(Deserialize)]
pub struct CallbackRequest {
    pub code: String,
    pub state: Option<String>,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub expires_in: Option<u32>,
}

pub async fn login() -> Result<HttpResponse> {
    let sso_url = env::var("SSO_URL").unwrap_or_else(|_| "https://sso.skygenesisenterprise.com".to_string());
    let realm = env::var("SSO_REALM").unwrap_or_else(|_| "master".to_string());
    let client_id = env::var("SSO_CLIENT_ID").unwrap_or_else(|_| "api-service".to_string());
    let redirect_uri = env::var("SSO_REDIRECT_URI").unwrap_or_else(|_| "http://localhost:8080/api/auth/callback".to_string());

    let auth_url = format!(
        "{}/realms/{}/protocol/openid-connect/auth?client_id={}&redirect_uri={}&response_type=code&scope=openid",
        sso_url, realm, client_id, redirect_uri
    );

    Ok(HttpResponse::Found()
        .append_header(("Location", auth_url))
        .finish())
}

pub async fn callback(query: web::Query<CallbackRequest>) -> Result<HttpResponse> {
    let sso_url = env::var("SSO_URL").unwrap_or_else(|_| "https://sso.skygenesisenterprise.com".to_string());
    let realm = env::var("SSO_REALM").unwrap_or_else(|_| "master".to_string());
    let client_id = env::var("SSO_CLIENT_ID").unwrap_or_else(|_| "api-service".to_string());
    let client_secret = env::var("SSO_CLIENT_SECRET").unwrap_or_else(|_| "".to_string());
    let redirect_uri = env::var("SSO_REDIRECT_URI").unwrap_or_else(|_| "http://localhost:8080/api/auth/callback".to_string());

    let token_url = format!("{}/realms/{}/protocol/openid-connect/token", sso_url, realm);

    let client = Client::new();
    let params = [
        ("grant_type", "authorization_code"),
        ("code", &query.code),
        ("client_id", &client_id),
        ("client_secret", &client_secret),
        ("redirect_uri", &redirect_uri),
    ];

    let response = match client.post(&token_url)
        .form(&params)
        .send()
        .await {
        Ok(resp) => resp,
        Err(_) => return Ok(HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to exchange code"}))),
    };

    if response.status() != StatusCode::OK {
        return Ok(HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid code"})));
    }

    let token_data: serde_json::Value = match response.json().await {
        Ok(data) => data,
        Err(_) => return Ok(HttpResponse::InternalServerError().json(serde_json::json!({"error": "Invalid token response"}))),
    };

    let token_response = TokenResponse {
        access_token: token_data["access_token"].as_str().unwrap_or("").to_string(),
        refresh_token: token_data["refresh_token"].as_str().map(|s| s.to_string()),
        id_token: token_data["id_token"].as_str().map(|s| s.to_string()),
        expires_in: token_data["expires_in"].as_u64().map(|n| n as u32),
    };

    Ok(HttpResponse::Ok().json(token_response))
}

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .route("/login", web::get().to(login))
            .route("/callback", web::get().to(callback))
    );
}