// ============================================================================
// Sky Genesis Enterprise API - Main Application
// ============================================================================

use std::net::SocketAddr;
use std::env;

// Import modules
mod routes;
mod models;
mod services;
mod controllers;
mod middlewares;
mod queries;
mod utils;
mod core;
mod tests;

// ============================================================================
// MAIN APPLICATION ENTRY POINT
// ============================================================================

#[tokio::main]
async fn main() {
    // Initialize logging
    env_logger::init();

    // Load configuration
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://localhost/api_service".to_string());
    
    let encryption_key = env::var("API_KEY_ENCRYPTION_KEY")
        .unwrap_or_else(|_| "change-this-in-production".to_string());

    let port: u16 = env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse()
        .expect("Invalid PORT value");

    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    
    println!("🚀 Sky Genesis Enterprise API starting on http://{}", addr);
    println!("🔐 API Key Management System Enabled");
    println!("📋 Available endpoints:");
    println!("   GET  /hello - Simple hello world");
    println!("   GET  /api/v1/health - Health check");
    println!("   GET  /docs - API documentation");
    println!("   GET  /api/v1/keys - API Keys management");
    println!("");
    println!("🔑 API Key Types:");
    println!("   • Client Keys (sk_client_*) - For frontend applications");
    println!("   • Server Keys (sk_server_*) - For backend services");
    println!("   • Database Keys (sk_db_*) - For database connections");
    println!("");
    println!("📊 Database: {}", database_url);
    println!("🔒 Encryption: {}", if encryption_key != "change-this-in-production" { "Configured" } else { "Using default (CHANGE IN PRODUCTION)" });
    
    // Initialize API Key Core (would connect to database in real implementation)
    println!("🔧 Initializing API Key Management System...");
    
    // Define routes
    let routes = routes::routes();
    
    // Start server
    println!("🌐 Server starting...");
    warp::serve(routes)
        .run(addr)
        .await;
}

