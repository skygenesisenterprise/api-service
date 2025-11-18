// ============================================================================
// Sky Genesis Enterprise API - API Key Routes
// ============================================================================

use warp::{Filter, Reply, Rejection};
use serde_json;
use std::sync::Arc;
use uuid::Uuid;
use crate::controllers::api_keys::ApiKeyController;
use crate::services::api_keys::ApiKeyService;
use crate::models::api_keys::{
    CreateClientKeyRequest, CreateServerKeyRequest, CreateDatabaseKeyRequest,
    UpdateApiKeyRequest, KeyType
};

// ============================================================================
// Route Helpers
// ============================================================================

fn with_service(service: Arc<ApiKeyService>) -> impl Filter<Extract = (Arc<ApiKeyService>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || service.clone())
}

fn with_controller(service: Arc<ApiKeyService>) -> impl Filter<Extract = (Arc<ApiKeyService>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || service.clone())
}

// ============================================================================
// API Key Routes
// ============================================================================

pub fn api_key_routes(
    service: Arc<ApiKeyService>
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let api_keys = warp::path("api")
        .and(warp::path("v1"))
        .and(warp::path("keys"))
        .and(with_service(service.clone()));

    // Create API key routes
    let create_client = api_keys
        .and(warp::path("client"))
        .and(warp::path::end())
        .and(warp::post())
        .and(with_controller(service.clone()))
        .and(warp::path::param::<Uuid>()) // organization_id
        .and(warp::body::json::<CreateClientKeyRequest>())
        .and_then(|service: Arc<ApiKeyService>, org_id: Uuid, request: CreateClientKeyRequest| async move {
            ApiKeyController::create_client_key(service, org_id, request).await
        });

    let create_server = api_keys
        .and(warp::path("server"))
        .and(warp::path::end())
        .and(warp::post())
        .and(with_controller(service.clone()))
        .and(warp::path::param::<Uuid>()) // organization_id
        .and(warp::body::json::<CreateServerKeyRequest>())
        .and_then(|service: Arc<ApiKeyService>, org_id: Uuid, request: CreateServerKeyRequest| async move {
            ApiKeyController::create_server_key(service, org_id, request).await
        });

    let create_database = api_keys
        .and(warp::path("database"))
        .and(warp::path::end())
        .and(warp::post())
        .and(with_controller(service.clone()))
        .and(warp::path::param::<Uuid>()) // organization_id
        .and(warp::body::json::<CreateDatabaseKeyRequest>())
        .and_then(|service: Arc<ApiKeyService>, org_id: Uuid, request: CreateDatabaseKeyRequest| async move {
            ApiKeyController::create_database_key(service, org_id, request).await
        });

    // Read API key routes
    let get_key = api_keys
        .and(warp::path::param::<Uuid>()) // key_id
        .and(warp::path::end())
        .and(warp::get())
        .and(with_controller(service.clone()))
        .and(warp::path::param::<Uuid>()) // organization_id
        .and_then(|service: Arc<ApiKeyService>, key_id: Uuid, org_id: Uuid| async move {
            ApiKeyController::get_key(service, key_id, org_id).await
        });

    let list_keys = api_keys
        .and(warp::path::end())
        .and(warp::get())
        .and(with_controller(service.clone()))
        .and(warp::path::param::<Uuid>()) // organization_id
        .and(warp::query::<Option<String>>()) // key_type filter
        .and_then(|service: Arc<ApiKeyService>, org_id: Uuid, key_type_filter: Option<String>| async move {
            let key_type = key_type_filter.and_then(|kt| match kt.as_str() {
                "client" => Some(KeyType::Client),
                "server" => Some(KeyType::Server),
                "database" => Some(KeyType::Database),
                _ => None,
            });
            ApiKeyController::list_keys(service, org_id, key_type).await
        });

    // Update API key routes
    let update_key = api_keys
        .and(warp::path::param::<Uuid>()) // key_id
        .and(warp::path::end())
        .and(warp::put())
        .and(with_controller(service.clone()))
        .and(warp::path::param::<Uuid>()) // organization_id
        .and(warp::body::json::<UpdateApiKeyRequest>())
        .and_then(|service: Arc<ApiKeyService>, key_id: Uuid, org_id: Uuid, request: UpdateApiKeyRequest| async move {
            ApiKeyController::update_key(service, key_id, org_id, request).await
        });

    // Delete/Revoke API key routes
    let revoke_key = api_keys
        .and(warp::path::param::<Uuid>()) // key_id
        .and(warp::path("revoke"))
        .and(warp::path::end())
        .and(warp::post())
        .and(with_controller(service.clone()))
        .and(warp::path::param::<Uuid>()) // organization_id
        .and_then(|service: Arc<ApiKeyService>, key_id: Uuid, org_id: Uuid| async move {
            ApiKeyController::revoke_key(service, key_id, org_id).await
        });

    let delete_key = api_keys
        .and(warp::path::param::<Uuid>()) // key_id
        .and(warp::path::end())
        .and(warp::delete())
        .and(with_controller(service.clone()))
        .and(warp::path::param::<Uuid>()) // organization_id
        .and_then(|service: Arc<ApiKeyService>, key_id: Uuid, org_id: Uuid| async move {
            ApiKeyController::delete_key(service, key_id, org_id).await
        });

    // Statistics routes
    let get_stats = api_keys
        .and(warp::path("stats"))
        .and(warp::path::end())
        .and(warp::get())
        .and(with_controller(service.clone()))
        .and(warp::path::param::<Uuid>()) // organization_id
        .and_then(|service: Arc<ApiKeyService>, org_id: Uuid| async move {
            ApiKeyController::get_stats(service, org_id).await
        });

    // Utility routes
    let validate_key = api_keys
        .and(warp::path("validate"))
        .and(warp::path::end())
        .and(warp::post())
        .and(with_controller(service.clone()))
        .and(warp::body::json::<serde_json::Value>())
        .and_then(|service: Arc<ApiKeyService>, body: serde_json::Value| async move {
            if let Some(key_value) = body.get("key_value").and_then(|v| v.as_str()) {
                ApiKeyController::validate_key(service, key_value.to_string()).await
            } else {
                Ok(warp::reply::json(&serde_json::json!({
                    "success": false,
                    "error": "key_value field is required",
                    "code": "MISSING_KEY_VALUE"
                })))
            }
        });

    // Combine all routes
    create_client
        .or(create_server)
        .or(create_database)
        .or(get_key)
        .or(list_keys)
        .or(update_key)
        .or(revoke_key)
        .or(delete_key)
        .or(get_stats)
        .or(validate_key)
}

// ============================================================================
// Public API Key Routes (for validation and public access)
// ============================================================================

pub fn public_api_key_routes(
    service: Arc<ApiKeyService>
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let public_keys = warp::path("api")
        .and(warp::path("v1"))
        .and(warp::path("public"))
        .and(warp::path("keys"))
        .and(with_service(service.clone()));

    let validate_public = public_keys
        .and(warp::path("validate"))
        .and(warp::path::end())
        .and(warp::post())
        .and(with_controller(service.clone()))
        .and(warp::body::json::<serde_json::Value>())
        .and_then(|service: Arc<ApiKeyService>, body: serde_json::Value| async move {
            if let Some(key_value) = body.get("key_value").and_then(|v| v.as_str()) {
                ApiKeyController::validate_key(service, key_value.to_string()).await
            } else {
                Ok(warp::reply::json(&serde_json::json!({
                    "success": false,
                    "error": "key_value field is required",
                    "code": "MISSING_KEY_VALUE"
                })))
            }
        });

    validate_public
}

// ============================================================================
// Admin API Key Routes (for administrative operations)
// ============================================================================

pub fn admin_api_key_routes(
    service: Arc<ApiKeyService>
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let admin_keys = warp::path("api")
        .and(warp::path("v1"))
        .and(warp::path("admin"))
        .and(warp::path("keys"))
        .and(with_service(service.clone()));

    // Admin can list all keys across organizations
    let list_all_keys = admin_keys
        .and(warp::path("all"))
        .and(warp::path::end())
        .and(warp::get())
        .and(with_controller(service.clone()))
        .and(warp::query::<Option<String>>()) // key_type filter
        .and_then(|service: Arc<ApiKeyService>, key_type_filter: Option<String>| async move {
            // This would need admin service implementation
            // For now, return empty list
            Ok(warp::reply::json(&serde_json::json!({
                "success": true,
                "data": {
                    "api_keys": [],
                    "total": 0
                },
                "message": "Admin route - not yet implemented"
            })))
        });

    // Admin can get global stats
    let get_global_stats = admin_keys
        .and(warp::path("stats"))
        .and(warp::path("global"))
        .and(warp::path::end())
        .and(warp::get())
        .and(with_controller(service.clone()))
        .and_then(|service: Arc<ApiKeyService>| async move {
            // This would need admin service implementation
            // For now, return empty stats
            Ok(warp::reply::json(&serde_json::json!({
                "success": true,
                "data": {
                    "total_keys": 0,
                    "active_keys": 0,
                    "client_keys": 0,
                    "server_keys": 0,
                    "database_keys": 0,
                    "total_usage_today": 0,
                    "top_used_keys": []
                },
                "message": "Admin global stats - not yet implemented"
            })))
        });

    list_all_keys.or(get_global_stats)
}