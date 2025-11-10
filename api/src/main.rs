// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Minimal Working Main
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide minimal working API server to establish baseline
//  NOTICE: Ultra-minimal implementation with only essential dependencies.
//  COMPLIANCE: REST API standards, HTTP/1.1, JSON responses
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use std::net::SocketAddr;
mod routes;

// ============================================================================
//  MAIN APPLICATION ENTRY POINT
// ============================================================================

#[tokio::main]
async fn main() {
    // Simple configuration
    let addr: SocketAddr = ([127, 0, 0, 1], 8080).into();
    
    println!("🚀 Sky Genesis Enterprise API starting on http://{}", addr);
    println!("📋 Available endpoints:");
    println!("   GET  /hello - Simple hello world");
    println!("   GET  /api/v1/health - Health check");
    println!("   GET  /docs - API documentation");
    
    // Define routes
    let routes = routes::routes();
    
    // Start server
    warp::serve(routes)
        .run(addr)
        .await;
}

