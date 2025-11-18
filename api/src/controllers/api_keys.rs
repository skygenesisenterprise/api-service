// ============================================================================
// Sky Genesis Enterprise API - API Key Controllers
// ============================================================================

use crate::models::api_keys::{
    ApiKeyResponse, ApiKeySecretResponse, CreateClientKeyRequest,
    CreateServerKeyRequest, CreateDatabaseKeyRequest, UpdateApiKeyRequest,
    KeyType, ApiKeyStats
};
use crate::services::api_keys::ApiKeyService;
use warp::{Reply, Rejection};
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;
use anyhow::Result;

// ============================================================================
// API Key Controllers
// ============================================================================

pub struct ApiKeyController {
    service: Arc<ApiKeyService>,
}

impl ApiKeyController {
    pub fn new(service: Arc<ApiKeyService>) -> Self {
        Self { service }
    }

    // ============================================================================
    // Create API Keys
    // ============================================================================

    pub async fn create_client_key(
        service: Arc<ApiKeyService>,
        organization_id: Uuid,
        request: CreateClientKeyRequest,
    ) -> Result<impl Reply, Rejection> {
        match service.create_client_key(organization_id, request).await {
            Ok((response, secret_response)) => {
                Ok(warp::reply::json(&json!({
                    "success": true,
                    "data": {
                        "api_key": response,
                        "secrets": secret_response
                    },
                    "message": "Client API key created successfully"
                })))
            }
            Err(e) => {
                Ok(warp::reply::json(&json!({
                    "success": false,
                    "error": format!("Failed to create client key: {}", e),
                    "code": "CREATE_CLIENT_KEY_ERROR"
                })))
            }
        }
    }

    pub async fn create_server_key(
        service: Arc<ApiKeyService>,
        organization_id: Uuid,
        request: CreateServerKeyRequest,
    ) -> Result<impl Reply, Rejection> {
        match service.create_server_key(organization_id, request).await {
            Ok((response, secret_response)) => {
                Ok(warp::reply::json(&json!({
                    "success": true,
                    "data": {
                        "api_key": response,
                        "secrets": secret_response
                    },
                    "message": "Server API key created successfully"
                })))
            }
            Err(e) => {
                Ok(warp::reply::json(&json!({
                    "success": false,
                    "error": format!("Failed to create server key: {}", e),
                    "code": "CREATE_SERVER_KEY_ERROR"
                })))
            }
        }
    }

    pub async fn create_database_key(
        service: Arc<ApiKeyService>,
        organization_id: Uuid,
        request: CreateDatabaseKeyRequest,
    ) -> Result<impl Reply, Rejection> {
        match service.create_database_key(organization_id, request).await {
            Ok((response, secret_response)) => {
                Ok(warp::reply::json(&json!({
                    "success": true,
                    "data": {
                        "api_key": response,
                        "secrets": secret_response
                    },
                    "message": "Database API key created successfully"
                })))
            }
            Err(e) => {
                Ok(warp::reply::json(&json!({
                    "success": false,
                    "error": format!("Failed to create database key: {}", e),
                    "code": "CREATE_DATABASE_KEY_ERROR"
                })))
            }
        }
    }

    // ============================================================================
    // Read API Keys
    // ============================================================================

    pub async fn get_key(
        service: Arc<ApiKeyService>,
        key_id: Uuid,
        organization_id: Uuid,
    ) -> Result<impl Reply, Rejection> {
        match service.get_key_by_id(key_id, organization_id).await {
            Ok(Some(api_key)) => {
                let response = ApiKeyResponse {
                    id: api_key.id,
                    key_value: api_key.key_value,
                    key_type: api_key.key_type,
                    label: api_key.label,
                    permissions: api_key.permissions,
                    quota_limit: api_key.quota_limit,
                    usage_count: api_key.usage_count,
                    status: api_key.status,
                    created_at: api_key.created_at,
                    expires_at: api_key.expires_at,
                    server_endpoint: api_key.server_endpoint,
                    server_region: api_key.server_region,
                    db_type: api_key.db_type,
                    db_host: api_key.db_host,
                    client_origin: api_key.client_origin,
                    client_scopes: api_key.client_scopes,
                };

                Ok(warp::reply::json(&json!({
                    "success": true,
                    "data": response
                })))
            }
            Ok(None) => {
                Ok(warp::reply::json(&json!({
                    "success": false,
                    "error": "API key not found",
                    "code": "KEY_NOT_FOUND"
                })))
            }
            Err(e) => {
                Ok(warp::reply::json(&json!({
                    "success": false,
                    "error": format!("Failed to retrieve API key: {}", e),
                    "code": "GET_KEY_ERROR"
                })))
            }
        }
    }

    pub async fn list_keys(
        service: Arc<ApiKeyService>,
        organization_id: Uuid,
        key_type: Option<KeyType>,
    ) -> Result<impl Reply, Rejection> {
        match service.list_keys(organization_id, key_type).await {
            Ok(api_keys) => {
                let responses: Vec<ApiKeyResponse> = api_keys.into_iter().map(|api_key| {
                    ApiKeyResponse {
                        id: api_key.id,
                        key_value: api_key.key_value,
                        key_type: api_key.key_type,
                        label: api_key.label,
                        permissions: api_key.permissions,
                        quota_limit: api_key.quota_limit,
                        usage_count: api_key.usage_count,
                        status: api_key.status,
                        created_at: api_key.created_at,
                        expires_at: api_key.expires_at,
                        server_endpoint: api_key.server_endpoint,
                        server_region: api_key.server_region,
                        db_type: api_key.db_type,
                        db_host: api_key.db_host,
                        client_origin: api_key.client_origin,
                        client_scopes: api_key.client_scopes,
                    }
                }).collect();

                Ok(warp::reply::json(&json!({
                    "success": true,
                    "data": {
                        "api_keys": responses,
                        "total": responses.len()
                    }
                })))
            }
            Err(e) => {
                Ok(warp::reply::json(&json!({
                    "success": false,
                    "error": format!("Failed to list API keys: {}", e),
                    "code": "LIST_KEYS_ERROR"
                })))
            }
        }
    }

    // ============================================================================
    // Update API Keys
    // ============================================================================

    pub async fn update_key(
        service: Arc<ApiKeyService>,
        key_id: Uuid,
        organization_id: Uuid,
        request: UpdateApiKeyRequest,
    ) -> Result<impl Reply, Rejection> {
        match service.update_key(key_id, organization_id, request).await {
            Ok(Some(api_key)) => {
                let response = ApiKeyResponse {
                    id: api_key.id,
                    key_value: api_key.key_value,
                    key_type: api_key.key_type,
                    label: api_key.label,
                    permissions: api_key.permissions,
                    quota_limit: api_key.quota_limit,
                    usage_count: api_key.usage_count,
                    status: api_key.status,
                    created_at: api_key.created_at,
                    expires_at: api_key.expires_at,
                    server_endpoint: api_key.server_endpoint,
                    server_region: api_key.server_region,
                    db_type: api_key.db_type,
                    db_host: api_key.db_host,
                    client_origin: api_key.client_origin,
                    client_scopes: api_key.client_scopes,
                };

                Ok(warp::reply::json(&json!({
                    "success": true,
                    "data": response,
                    "message": "API key updated successfully"
                })))
            }
            Ok(None) => {
                Ok(warp::reply::json(&json!({
                    "success": false,
                    "error": "API key not found",
                    "code": "KEY_NOT_FOUND"
                })))
            }
            Err(e) => {
                Ok(warp::reply::json(&json!({
                    "success": false,
                    "error": format!("Failed to update API key: {}", e),
                    "code": "UPDATE_KEY_ERROR"
                })))
            }
        }
    }

    // ============================================================================
    // Delete/Revoke API Keys
    // ============================================================================

    pub async fn revoke_key(
        service: Arc<ApiKeyService>,
        key_id: Uuid,
        organization_id: Uuid,
    ) -> Result<impl Reply, Rejection> {
        match service.revoke_key(key_id, organization_id).await {
            Ok(true) => {
                Ok(warp::reply::json(&json!({
                    "success": true,
                    "message": "API key revoked successfully"
                })))
            }
            Ok(false) => {
                Ok(warp::reply::json(&json!({
                    "success": false,
                    "error": "API key not found",
                    "code": "KEY_NOT_FOUND"
                })))
            }
            Err(e) => {
                Ok(warp::reply::json(&json!({
                    "success": false,
                    "error": format!("Failed to revoke API key: {}", e),
                    "code": "REVOKE_KEY_ERROR"
                })))
            }
        }
    }

    pub async fn delete_key(
        service: Arc<ApiKeyService>,
        key_id: Uuid,
        organization_id: Uuid,
    ) -> Result<impl Reply, Rejection> {
        match service.delete_key(key_id, organization_id).await {
            Ok(true) => {
                Ok(warp::reply::json(&json!({
                    "success": true,
                    "message": "API key deleted successfully"
                })))
            }
            Ok(false) => {
                Ok(warp::reply::json(&json!({
                    "success": false,
                    "error": "API key not found",
                    "code": "KEY_NOT_FOUND"
                })))
            }
            Err(e) => {
                Ok(warp::reply::json(&json!({
                    "success": false,
                    "error": format!("Failed to delete API key: {}", e),
                    "code": "DELETE_KEY_ERROR"
                })))
            }
        }
    }

    // ============================================================================
    // Statistics
    // ============================================================================

    pub async fn get_stats(
        service: Arc<ApiKeyService>,
        organization_id: Uuid,
    ) -> Result<impl Reply, Rejection> {
        match service.get_stats(organization_id).await {
            Ok(stats) => {
                Ok(warp::reply::json(&json!({
                    "success": true,
                    "data": stats
                })))
            }
            Err(e) => {
                Ok(warp::reply::json(&json!({
                    "success": false,
                    "error": format!("Failed to retrieve API key statistics: {}", e),
                    "code": "GET_STATS_ERROR"
                })))
            }
        }
    }

    // ============================================================================
    // Utility Controllers
    // ============================================================================

    pub async fn validate_key(
        service: Arc<ApiKeyService>,
        key_value: String,
    ) -> Result<impl Reply, Rejection> {
        match service.get_key_by_value(&key_value).await {
            Ok(Some(api_key)) => {
                Ok(warp::reply::json(&json!({
                    "success": true,
                    "data": {
                        "valid": true,
                        "key_id": api_key.id,
                        "key_type": api_key.key_type,
                        "status": api_key.status,
                        "permissions": api_key.permissions
                    }
                })))
            }
            Ok(None) => {
                Ok(warp::reply::json(&json!({
                    "success": true,
                    "data": {
                        "valid": false,
                        "reason": "Key not found"
                    }
                })))
            }
            Err(e) => {
                Ok(warp::reply::json(&json!({
                    "success": false,
                    "error": format!("Failed to validate API key: {}", e),
                    "code": "VALIDATE_KEY_ERROR"
                })))
            }
        }
    }
}

// ============================================================================
// Response Helpers
// ============================================================================

pub fn success_response<T: serde::Serialize>(data: T, message: Option<&str>) -> impl Reply {
    let mut response = json!({
        "success": true,
        "data": data
    });
    
    if let Some(msg) = message {
        response["message"] = json!(msg);
    }
    
    warp::reply::json(&response)
}

pub fn error_response(error: &str, code: &str) -> impl Reply {
    warp::reply::json(&json!({
        "success": false,
        "error": error,
        "code": code
    }))
}

pub fn not_found_response(resource: &str) -> impl Reply {
    error_response(&format!("{} not found", resource), "NOT_FOUND")
}

pub fn validation_error_response(field: &str, message: &str) -> impl Reply {
    warp::reply::json(&json!({
        "success": false,
        "error": "Validation failed",
        "code": "VALIDATION_ERROR",
        "details": {
            "field": field,
            "message": message
        }
    }))
}