use actix_web::HttpResponse;

use crate::models::api_key::ApiKey;
use crate::services::api_key::ApiKeyService;
use crate::utils::db::DbPool;

pub async fn authenticate_api_key(
    req: &actix_web::HttpRequest,
    pool: &DbPool,
) -> Result<ApiKey, HttpResponse> {
    let api_key = req
        .headers()
        .get("x-api-key")
        .and_then(|h| h.to_str().ok())
        .or_else(|| {
            req.headers()
                .get("authorization")
                .and_then(|h| h.to_str().ok())
                .and_then(|auth| auth.strip_prefix("Bearer "))
        })
        .or_else(|| req.query_string().split('&').find_map(|pair| {
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