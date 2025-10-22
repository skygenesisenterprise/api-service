use actix_web::{HttpMessage, HttpResponse, dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform}, http::header::HeaderMap, Error, body::BoxBody};
use futures_util::future::LocalBoxFuture;
use std::{future::{ready, Ready}, rc::Rc};
use serde::{Deserialize, Serialize};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use reqwest::Client;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use tokio::sync::RwLock;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthenticatedUser {
    pub sub: String,
    pub email: String,
    pub name: Option<String>,
    pub roles: Vec<String>,
    pub organization_id: Option<String>,
}

#[derive(Deserialize)]
struct Claims {
    sub: String,
    email: String,
    name: Option<String>,
    realm_access: Option<RealmAccess>,
    organization_id: Option<String>,
}

#[derive(Deserialize)]
struct RealmAccess {
    roles: Vec<String>,
}

static JWKS_CACHE: Lazy<RwLock<HashMap<String, DecodingKey>>> = Lazy::new(|| RwLock::new(HashMap::new()));
static HTTP_CLIENT: Lazy<Client> = Lazy::new(|| Client::new());

async fn get_decoding_key(kid: &str) -> Result<DecodingKey, HttpResponse> {
    let cache = JWKS_CACHE.read().await;
    if let Some(key) = cache.get(kid) {
        return Ok(key.clone());
    }
    drop(cache);

    let jwks_url = std::env::var("SSO_JWKS_URL").unwrap_or_else(|_| "https://sso.skygenesisenterprise.com/realms/master/protocol/openid-connect/certs".to_string());
    let response = HTTP_CLIENT.get(&jwks_url).send().await.map_err(|_| {
        HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to fetch JWKS"}))
    })?;
    let jwks: serde_json::Value = response.json().await.map_err(|_| {
        HttpResponse::InternalServerError().json(serde_json::json!({"error": "Invalid JWKS response"}))
    })?;
    let keys = jwks["keys"].as_array().ok_or_else(|| {
        HttpResponse::InternalServerError().json(serde_json::json!({"error": "No keys in JWKS"}))
    })?;

    let mut cache = JWKS_CACHE.write().await;
    for key in keys {
        if let Some(kid_val) = key["kid"].as_str() {
            if let Some(n) = key["n"].as_str() {
                if let Some(e) = key["e"].as_str() {
                    let decoding_key = DecodingKey::from_rsa_components(n, e).map_err(|_| {
                        HttpResponse::InternalServerError().json(serde_json::json!({"error": "Invalid RSA key"}))
                    })?;
                    cache.insert(kid_val.to_string(), decoding_key);
                }
            }
        }
    }
    cache.get(kid).cloned().ok_or_else(|| {
        HttpResponse::Unauthorized().json(serde_json::json!({"error": "Key not found"}))
    })
}

pub async fn authenticate_jwt(headers: &HeaderMap) -> Result<AuthenticatedUser, HttpResponse> {
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|auth| auth.strip_prefix("Bearer "))
        .ok_or_else(|| {
            HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Authentication required",
                "message": "Please provide a Bearer token in Authorization header"
            }))
        })?;

    let header = decode_header(token).map_err(|_| {
        HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid token"}))
    })?;

    let kid = header.kid.ok_or_else(|| {
        HttpResponse::Unauthorized().json(serde_json::json!({"error": "No key ID in token"}))
    })?;

    let decoding_key = get_decoding_key(&kid).await?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[std::env::var("SSO_ISSUER").unwrap_or_else(|_| "https://sso.skygenesisenterprise.com/realms/master".to_string())]);
    validation.set_audience(&[std::env::var("SSO_CLIENT_ID").unwrap_or_else(|_| "api-service".to_string())]);

    let token_data = decode::<Claims>(token, &decoding_key, &validation).map_err(|_| {
        HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid token"}))
    })?;

    let claims = token_data.claims;
    let roles = claims.realm_access.map(|ra| ra.roles).unwrap_or_default();

    Ok(AuthenticatedUser {
        sub: claims.sub,
        email: claims.email,
        name: claims.name,
        roles,
        organization_id: claims.organization_id,
    })
}



pub fn require_role(user: &AuthenticatedUser, role: &str) -> Result<(), HttpResponse> {
    if !user.roles.contains(&role.to_string()) {
        return Err(HttpResponse::Forbidden()
            .json(serde_json::json!({
                "error": "Insufficient permissions",
                "message": format!("Required role: {}", role)
            })));
    }
    Ok(())
}

pub struct AuthenticateJwt;

impl AuthenticateJwt {
    pub fn new() -> Self {
        Self
    }
}

impl<S> Transform<S, ServiceRequest> for AuthenticateJwt
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthenticateJwtMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthenticateJwtMiddleware {
            service: Rc::new(service),
        }))
    }
}

pub struct AuthenticateJwtMiddleware<S> {
    service: Rc<S>,
}

impl<S> Service<ServiceRequest> for AuthenticateJwtMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);

        Box::pin(async move {
            // Skip authentication for certain paths if needed
            let path = req.path();
            if path.starts_with("/api/validate") || path.starts_with("/health") {
                return service.call(req).await;
            }

            match authenticate_jwt(req.headers()).await {
                Ok(user) => {
                    // Store the authenticated user in request extensions
                    req.extensions_mut().insert(user);
                    service.call(req).await
                }
                Err(response) => {
                    Ok(req.into_response(response))
                }
            }
        })
    }
}