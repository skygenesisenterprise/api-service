use actix_web::{HttpMessage, HttpResponse, dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform}, http::header::HeaderMap, Error, body::BoxBody};
use futures_util::future::LocalBoxFuture;
use std::{future::{ready, Ready}, rc::Rc};
use crate::models::api_key::ApiKey;
use crate::services::api_key::ApiKeyService;
use crate::utils::db::DbPool;

pub async fn authenticate_api_key(
    headers: &HeaderMap,
    query_string: &str,
    pool: &DbPool,
) -> Result<ApiKey, HttpResponse> {
    let api_key = headers
        .get("x-api-key")
        .and_then(|h| h.to_str().ok())
        .or_else(|| {
            headers
                .get("authorization")
                .and_then(|h| h.to_str().ok())
                .and_then(|auth| auth.strip_prefix("Bearer "))
        })
        .or_else(|| query_string.split('&').find_map(|pair| {
            let mut parts = pair.split('=');
            match (parts.next(), parts.next()) {
                (Some("api_key"), Some(key)) => Some(key),
                _ => None,
            }
        }));

    let api_key = match api_key {
        Some(key) => key,
        None => {
            return Err(HttpResponse::Unauthorized()
                .json(serde_json::json!({
                    "error": "API key required",
                    "message": "Please provide an API key in X-API-Key header, Authorization header, or api_key query parameter"
                })));
        }
    };

    let mut conn = match pool.get() {
        Ok(conn) => conn,
        Err(_) => {
            return Err(HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Database connection error"})));
        }
    };

    match ApiKeyService::validate_api_key(&mut conn, api_key) {
        Ok(key) => Ok(key),
        Err(e) => {
            let error_msg = if e.to_string().contains("quota") {
                "Quota exceeded"
            } else {
                "Invalid API key"
            };
            let status = if e.to_string().contains("quota") { 429 } else { 401 };
            Err(HttpResponse::build(actix_web::http::StatusCode::from_u16(status).unwrap())
                .json(serde_json::json!({
                    "error": error_msg,
                    "message": e.to_string()
                })))
        }
    }
}

pub fn require_permission(api_key: &ApiKey, permission: &str) -> Result<(), HttpResponse> {
    if !ApiKeyService::has_permission(api_key, permission) {
        return Err(HttpResponse::Forbidden()
            .json(serde_json::json!({
                "error": "Insufficient permissions",
                "message": format!("Required permission: {}", permission)
            })));
    }
    Ok(())
}

pub struct AuthenticateApiKey {
    pool: DbPool,
}

impl AuthenticateApiKey {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

impl<S> Transform<S, ServiceRequest> for AuthenticateApiKey
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthenticateApiKeyMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthenticateApiKeyMiddleware {
            service: Rc::new(service),
            pool: self.pool.clone(),
        }))
    }
}

pub struct AuthenticateApiKeyMiddleware<S> {
    service: Rc<S>,
    pool: DbPool,
}

impl<S> Service<ServiceRequest> for AuthenticateApiKeyMiddleware<S>
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
        let pool = self.pool.clone();

        Box::pin(async move {
            // Skip authentication for certain paths if needed
            let path = req.path();
            if path.starts_with("/api/validate") {
                return service.call(req).await;
            }

            match authenticate_api_key(req.headers(), req.query_string(), &pool).await {
                Ok(api_key) => {
                    // Store the API key in request extensions
                    req.extensions_mut().insert(api_key);
                    service.call(req).await
                }
                Err(response) => {
                    Ok(req.into_response(response))
                }
            }
        })
    }
}