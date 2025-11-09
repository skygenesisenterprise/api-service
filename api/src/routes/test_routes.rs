//! # Test Routes Module
//! 
//! Simple route for debugging HTTP request handling

use warp::Filter;
use serde_json;

/// Test endpoint for debugging
pub fn test_routes() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    // Simple test endpoint
    let test = warp::path("api")
        .and(warp::path("v1"))
        .and(warp::path("test"))
        .and(warp::get())
        .map(|| {
            println!("📋 Test endpoint called!");
            warp::reply::json(&serde_json::json!({
                "message": "Test route working!",
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "method": "GET"
            }))
        });

    // POST test endpoint
    let test_post = warp::path("api")
        .and(warp::path("v1"))
        .and(warp::path("test"))
        .and(warp::post())
        .and(warp::body::json())
        .map(|body: serde_json::Value| {
            println!("📋 POST test endpoint called with: {:?}", body);
            warp::reply::json(&serde_json::json!({
                "message": "POST test successful!",
                "received": body,
                "timestamp": chrono::Utc::now().to_rfc3339()
            }))
        });

    test.or(test_post)
}