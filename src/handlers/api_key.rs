use actix_web::{web, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::models::api_key::{ApiKey, ApiKeyInfo};
use crate::services::api_key::ApiKeyService;
use crate::utils::db::DbPool;

#[derive(Deserialize)]
pub struct CreateApiKeyRequest {
    pub label: Option<String>,
    pub permissions: Option<Vec<String>>,
}

pub async fn create_api_key(
    pool: web::Data<DbPool>,
    organization_id: web::Path<Uuid>,
    api_key_data: web::ReqData<ApiKey>,
    req: web::Json<CreateApiKeyRequest>,
) -> Result<HttpResponse> {
    // Verify the API key belongs to the organization or has admin permissions
    if (&*api_key_data).organization_id != *organization_id && !(&*api_key_data).permissions.contains(&"*".to_string()) {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Insufficient permissions to create API keys for this organization"
        })));
    }

    let mut conn = pool.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
    })?;

    match ApiKeyService::create_api_key(
        &mut conn,
        *organization_id,
        req.label.as_deref(),
        req.permissions.clone().unwrap_or_else(|| vec!["read".to_string()]),
    ) {
        Ok(api_key) => Ok(HttpResponse::Created().json(serde_json::json!({
            "message": "API key created successfully",
            "data": api_key
        }))),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to create API key: {}", e)
        }))),
    }
}

pub async fn get_api_keys(
    pool: web::Data<DbPool>,
    organization_id: web::Path<Uuid>,
    api_key_data: web::ReqData<ApiKey>,
) -> Result<HttpResponse> {
    // Verify the API key belongs to the organization
    if (&*api_key_data).organization_id != *organization_id && !(&*api_key_data).permissions.contains(&"*".to_string()) {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Insufficient permissions to view API keys for this organization"
        })));
    }

    let mut conn = pool.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
    })?;

    match ApiKeyService::get_api_keys_for_organization(&mut conn, *organization_id) {
        Ok(api_keys) => {
            // Don't return the actual key values in the response for security
            let sanitized_keys: Vec<serde_json::Value> = api_keys
                .into_iter()
                .map(|key| {
                    serde_json::json!({
                        "id": key.id,
                        "label": key.label,
                        "permissions": key.permissions,
                        "quota_limit": key.quota_limit,
                        "usage_count": key.usage_count,
                        "status": key.status,
                        "created_at": key.created_at
                    })
                })
                .collect();

            Ok(HttpResponse::Ok().json(serde_json::json!({ "data": sanitized_keys })))
        }
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to get API keys: {}", e)
        }))),
    }
}

pub async fn revoke_api_key(
    pool: web::Data<DbPool>,
    path: web::Path<(Uuid, Uuid)>,
    api_key_data: web::ReqData<ApiKey>,
) -> Result<HttpResponse> {
    let (organization_id, key_id) = path.into_inner();

    // Verify the API key belongs to the organization or has admin permissions
    if (&*api_key_data).organization_id != organization_id && !(&*api_key_data).permissions.contains(&"*".to_string()) {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Insufficient permissions to revoke API keys for this organization"
        })));
    }

    let mut conn = pool.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
    })?;

    match ApiKeyService::revoke_api_key(&mut conn, key_id, organization_id) {
        Ok(true) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "API key revoked successfully"
        }))),
        Ok(false) => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "API key not found"
        }))),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to revoke API key: {}", e)
        }))),
    }
}

pub async fn validate_api_key(api_key_data: web::ReqData<ApiKey>) -> Result<HttpResponse> {
    let info = ApiKeyService::get_api_key_info(&*api_key_data);
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "API key is valid",
        "data": info
    })))
}

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/organizations/{organization_id}/api-keys")
            .route("", web::post().to(create_api_key))
            .route("", web::get().to(get_api_keys))
            .route("/{key_id}", web::delete().to(revoke_api_key))
    )
    .service(
        web::scope("/validate")
            .route("", web::get().to(validate_api_key))
    );
}