// ============================================================================
// Sky Genesis Enterprise API - Routes Module
// ============================================================================

use warp::Filter;
use serde_json;
use std::sync::Arc;
use crate::services::api_keys::ApiKeyService;

mod api_keys;

pub fn routes() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    // Basic routes
    let hello = warp::path!("hello")
        .and(warp::get())
        .map(|| "Hello, World!");
    
    let health = warp::path("api")
        .and(warp::path("v1"))
        .and(warp::path("health"))
        .and(warp::get())
        .map(|| {
            warp::reply::json(&serde_json::json!({
                "status": "healthy",
                "service": "sky-genesis-enterprise-api",
                "version": "1.0.0",
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "uptime_seconds": 0,
                "message": "API is running successfully!"
            }))
        });
    
    let docs = warp::path("docs")
        .and(warp::get())
        .map(|| {
            warp::reply::html(r#"
<!DOCTYPE html>
<html>
<head>
    <title>Sky Genesis Enterprise API</title>
</head>
<body>
    <h1>Sky Genesis Enterprise API</h1>
    <p>API is running!</p>
    <ul>
        <li><a href="/hello">Hello World</a></li>
        <li><a href="/api/v1/health">Health Check</a></li>
        <li><a href="/api/v1/keys">API Keys Management</a></li>
    </ul>
</body>
</html>
            "#)
        });

    // API Key routes (placeholder - would need database connection)
    let api_keys_routes = warp::path("api")
        .and(warp::path("v1"))
        .and(warp::path("keys"))
        .and(warp::path::end())
        .and(warp::get())
        .map(|| {
            warp::reply::json(&serde_json::json!({
                "success": true,
                "message": "API Keys endpoint - database connection needed",
                "endpoints": [
                    "POST /api/v1/keys/client/{org_id}",
                    "POST /api/v1/keys/server/{org_id}",
                    "POST /api/v1/keys/database/{org_id}",
                    "GET /api/v1/keys/{org_id}",
                    "GET /api/v1/keys/{key_id}/{org_id}",
                    "PUT /api/v1/keys/{key_id}/{org_id}",
                    "POST /api/v1/keys/{key_id}/revoke/{org_id}",
                    "DELETE /api/v1/keys/{key_id}/{org_id}"
                ]
            }))
        });

    hello.or(health).or(docs).or(api_keys_routes)
        .with(warp::cors().allow_any_origin().allow_methods(vec!["GET", "POST", "PUT", "DELETE"]))
        .with(warp::log("api"))
}