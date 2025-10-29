use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use crate::core::vault::VaultClient;
use std::collections::HashMap;
use openidconnect::{core::*, reqwest::async_http_client, IssuerUrl, ClientId, ClientSecret, RedirectUrl, Nonce, CsrfToken, PkceCodeChallenge, AuthorizationCode, AccessToken, IdToken, OAuth2TokenResponse, TokenResponse};
use openidconnect::core::{CoreClient, CoreProviderMetadata};
use jsonwebtoken::{decode_header, DecodingKey, Validation, Algorithm, decode};
use base64::{Engine as _, engine::general_purpose};

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

#[derive(Deserialize)]
pub struct OidcConfig {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub userinfo_endpoint: String,
}

#[derive(Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

#[derive(Deserialize)]
pub struct Jwk {
    pub kid: String,
    pub kty: String,
    pub n: Option<String>,
    pub e: Option<String>,
    #[serde(rename = "use")]
    pub use_: Option<String>,
}

pub struct KeycloakClient {
    client: Client,
    base_url: String,
    realm: String,
    client_id: String,
    client_secret: String,
    oidc_config: Option<OidcConfig>,
    jwks: Option<Jwks>,
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

    pub async fn discover_oidc_config(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let url = format!("{}/realms/{}/.well-known/openid-connect-configuration", self.base_url, self.realm);
        let response = self.client.get(&url).send().await?;
        let config: OidcConfig = response.json().await?;
        self.oidc_config = Some(config);
        Ok(())
    }

    pub async fn fetch_jwks(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(config) = &self.oidc_config {
            let response = self.client.get(&config.jwks_uri).send().await?;
            let jwks: Jwks = response.json().await?;
            self.jwks = Some(jwks);
        } else {
            self.discover_oidc_config().await?;
            self.fetch_jwks().await?;
        }
        Ok(())
    }

    pub fn validate_jwt(&self, token: &str) -> Result<Value, Box<dyn std::error::Error>> {
        let header = decode_header(token)?;
        let kid = header.kid.ok_or("No kid in JWT header")?;

        if let Some(jwks) = &self.jwks {
            for key in &jwks.keys {
                if key.kid == kid && key.kty == "RSA" {
                    if let (Some(n), Some(e)) = (&key.n, &key.e) {
                        let n_bytes = general_purpose::URL_SAFE_NO_PAD.decode(n)?;
                        let e_bytes = general_purpose::URL_SAFE_NO_PAD.decode(e)?;
                        let decoding_key = DecodingKey::from_rsa_components(&n_bytes, &e_bytes)?;
                        let validation = Validation::new(Algorithm::RS256);
                        let token_data = jsonwebtoken::decode::<Value>(token, &decoding_key, &validation)?;
                        return Ok(token_data.claims);
                    }
                }
            }
        }
        Err("Unable to validate JWT".into())
    }

    pub async fn get_authorization_url(&self, redirect_uri: &str, state: &str) -> Result<String, Box<dyn std::error::Error>> {
        if self.oidc_config.is_none() {
            return Err("OIDC config not discovered".into());
        }

        let issuer_url = IssuerUrl::new(format!("{}/realms/{}", self.base_url, self.realm))?;
        let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, async_http_client).await?;
        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(self.client_id.clone()),
            Some(ClientSecret::new(self.client_secret.clone())),
        ).set_redirect_uri(RedirectUrl::new(redirect_uri.to_string())?);

        let (auth_url, _csrf_token, _nonce) = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_extra_param("state", state)
            .url();

        Ok(auth_url.to_string())
    }

    pub async fn exchange_code_for_token(&self, code: &str, redirect_uri: &str) -> Result<TokenResponse, Box<dyn std::error::Error>> {
        if self.oidc_config.is_none() {
            return Err("OIDC config not discovered".into());
        }

        let issuer_url = IssuerUrl::new(format!("{}/realms/{}", self.base_url, self.realm))?;
        let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, async_http_client).await?;
        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(self.client_id.clone()),
            Some(ClientSecret::new(self.client_secret.clone())),
        ).set_redirect_uri(RedirectUrl::new(redirect_uri.to_string())?);

        let token_response = client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .request_async(async_http_client)
            .await?;

        Ok(TokenResponse {
            access_token: token_response.access_token().secret().clone(),
            refresh_token: token_response.refresh_token().map(|t| t.secret().clone()).unwrap_or_default(),
            expires_in: token_response.expires_in().map(|d| d.as_secs()).unwrap_or(3600),
        })
    }
}