// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Main Entry Point - Ultra Minimal Working Version
// ============================================================================

use warp::Filter;
use dotenv::dotenv;

/// [MAIN FUNCTION] API Service Entry Point - Ultra Minimal
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load environment variables
    dotenv().ok();
    
    println!("🚀 Starting Sky Genesis Enterprise API Service...");
    println!("📍 Server will be available at: http://127.0.0.1:8080");
    println!("📊 Health check: http://127.0.0.1:8080/api/v1/health");
    println!("📚 API Documentation: http://127.0.0.1:8080/docs");
    
    // Health check route
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
    
    // Root route
    let root = warp::path::end()
        .and(warp::get())
        .map(|| {
            warp::reply::json(&serde_json::json!({
                "message": "Welcome to Sky Genesis Enterprise API",
                "version": "1.0.0",
                "endpoints": {
                    "health": "/api/v1/health",
                    "docs": "/docs"
                }
            }))
        });
    
    // API documentation route
    let docs = warp::path("docs")
        .and(warp::get())
        .map(|| {
            warp::reply::with_header(
                warp::reply::html("<html><body><h1>Sky Genesis Enterprise API</h1><p>API is running!</p></body></html>"),
                "content-type",
                "text/html"
            )
        });
    
    // Combine all routes
    let routes = health
        .or(root)
        .or(docs)
        .with(warp::cors().allow_any_origin().allow_methods(vec!["GET", "POST", "PUT", "DELETE"]))
        .with(warp::log("api"));
    
    // Get port from environment or use default
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()
        .unwrap_or(8080);
    
    let host = std::env::var("HOST")
        .unwrap_or_else(|_| "127.0.0.1".to_string());
    
    println!("🌐 Starting server on http://{}:{}", host, port);
    
    // Start server
    warp::serve(routes)
        .run((host.parse::<std::net::IpAddr>().unwrap_or([127, 0, 0, 1].into()), port))
        .await;
    
    Ok(())
}