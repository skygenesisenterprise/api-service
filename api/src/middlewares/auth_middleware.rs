use warp::{Filter, Rejection};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use crate::core::keycloak::KeycloakClient;
use rustls::Certificate;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub scopes: Vec<String>,
    pub preferred_username: Option<String>,
    pub email: Option<String>,
}

pub fn jwt_auth(keycloak: Arc<KeycloakClient>) -> impl Filter<Extract = (Claims,), Error = Rejection> + Clone {
    warp::header::<String>("authorization")
        .and_then(move |auth: String| {
            let kc = Arc::clone(&keycloak);
            async move {
                if !auth.starts_with("Bearer ") {
                    return Err(warp::reject::custom(AuthError::InvalidToken));
                }
                let token = auth.trim_start_matches("Bearer ");

                // Try OIDC validation first
                match kc.validate_jwt(token) {
                    Ok(claims) => {
                        // Convert serde_json::Value to Claims
                        let sub = claims["sub"].as_str().unwrap_or("").to_string();
                        let exp = claims["exp"].as_u64().unwrap_or(0) as usize;
                        let scopes = claims["scope"].as_str()
                            .unwrap_or("")
                            .split_whitespace()
                            .map(|s| s.to_string())
                            .collect();
                        let preferred_username = claims["preferred_username"].as_str().map(|s| s.to_string());
                        let email = claims["email"].as_str().map(|s| s.to_string());

                        Ok(Claims {
                            sub,
                            exp,
                            scopes,
                            preferred_username,
                            email,
                        })
                    },
                    Err(_) => {
                        // Fallback to legacy JWT validation
                        let secret = std::env::var("JWT_SECRET").unwrap_or("secret".to_string());
                        let decoding_key = DecodingKey::from_secret(secret.as_ref());
                        let validation = Validation::new(Algorithm::HS256);
                        match decode::<Claims>(token, &decoding_key, &validation) {
                            Ok(token_data) => Ok(token_data.claims),
                            Err(_) => Err(warp::reject::custom(AuthError::InvalidToken)),
                        }
                    }
                }
            }
        })
}

pub fn mtls_auth() -> impl Filter<Extract = (String,), Error = Rejection> + Clone {
    warp::tls::client_cert()
        .and_then(|cert: Option<Certificate>| async move {
            match cert {
                Some(client_cert) => {
                    // Extract client certificate information
                    // In a real implementation, you would validate the certificate
                    // against a trusted CA and extract client identity

                    // For now, return a placeholder client identity
                    let client_identity = "client_cert_subject".to_string(); // Extract from cert
                    Ok(client_identity)
                },
                None => Err(warp::reject::custom(AuthError::MissingClientCert)),
            }
        })
}

pub fn api_key_auth() -> impl Filter<Extract = (String,), Error = Rejection> + Clone {
    warp::header::<String>("x-api-key")
        .or(warp::header::<String>("authorization"))
        .unify()
        .and_then(|auth_header: String| async move {
            if auth_header.starts_with("Bearer ") {
                let api_key = auth_header.trim_start_matches("Bearer ");
                // Validate API key against your key store
                // For now, just check if it's not empty
                if !api_key.is_empty() {
                    Ok(api_key.to_string())
                } else {
                    Err(warp::reject::custom(AuthError::InvalidApiKey))
                }
            } else {
                // Direct API key in header
                if !auth_header.is_empty() {
                    Ok(auth_header)
                } else {
                    Err(warp::reject::custom(AuthError::InvalidApiKey))
                }
            }
        })
}

pub fn combined_auth(keycloak: Arc<KeycloakClient>) -> impl Filter<Extract = (Claims,), Error = Rejection> + Clone {
    // Try JWT auth first, then API key auth
    jwt_auth(keycloak.clone())
        .or(api_key_auth().map(|_| Claims {
            sub: "api_key_user".to_string(),
            exp: 0,
            scopes: vec!["api".to_string()],
            preferred_username: None,
            email: None,
        }))
        .unify()
}

#[derive(Debug)]
pub enum AuthError {
    InvalidToken,
    MissingClientCert,
    InvalidApiKey,
}

impl warp::reject::Reject for AuthError {}