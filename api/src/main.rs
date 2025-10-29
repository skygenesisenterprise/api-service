use warp::{Filter, Reply};
use std::convert::Infallible;
use std::sync::Arc;
use dotenv::dotenv;
use std::collections::HashMap;

mod models;
mod services;
mod middlewares;
mod routes;
mod controllers;
mod core;
mod queries;
mod utils;
mod websocket;
mod tests;
mod openapi;

// Function to load default values from .env.example
fn load_defaults_from_env_example() -> HashMap<String, String> {
    let mut defaults = HashMap::new();

    // Read .env.example file
    if let Ok(content) = std::fs::read_to_string(".env.example") {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                defaults.insert(key.to_string(), value.to_string());
            }
        }
    }

    defaults
}

#[tokio::main]
async fn main() {
    dotenv().ok();

    let defaults = load_defaults_from_env_example();

    let vault_addr = std::env::var("VAULT_ADDR")
        .or_else(|_| std::env::var("VAULT_BASE_URL"))
        .unwrap_or_else(|_| defaults.get("VAULT_ADDR").unwrap_or(&"https://vault.skygenesisenterprise.com".to_string()).clone());
    let role_id = std::env::var("VAULT_ROLE_ID").expect("VAULT_ROLE_ID must be set");
    let secret_id = std::env::var("VAULT_SECRET_ID").expect("VAULT_SECRET_ID must be set");
    let vault_client = Arc::new(crate::core::vault::VaultClient::new(vault_addr, role_id, secret_id).await.unwrap());

    let keycloak_client = Arc::new(crate::core::keycloak::KeycloakClient::new(vault_client.clone()).await.unwrap());

    // Initialize session service
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| {
        let defaults = load_defaults_from_env_example();
        defaults.get("REDIS_URL").unwrap_or(&"redis://localhost:6379".to_string()).clone()
    });
    let session_service = Arc::new(crate::services::session_service::SessionService::new(&redis_url).unwrap());

    // Initialize application service
    let application_service = Arc::new(crate::services::application_service::ApplicationService::new(vault_client.clone()));

    // Initialize two-factor authentication service
    let two_factor_service = Arc::new(crate::services::two_factor_service::TwoFactorService::new(vault_client.clone()));

    let auth_service = Arc::new(crate::services::auth_service::AuthService::new(
        keycloak_client,
        vault_client.clone(),
        session_service.clone(),
        application_service.clone(),
        two_factor_service.clone(),
    ));

    let key_service = Arc::new(crate::services::key_service::KeyService::new(vault_client));

    let vault_token = std::env::var("VAULT_TOKEN").unwrap_or_default();
    let vault_manager = Arc::new(crate::services::vault_manager::VaultManager::new("dummy".to_string(), vault_token));

    // Initialize WebSocket server
    let ws_server = Arc::new(crate::websocket::WebSocketServer::new());

    // Initialize SNMP components
    let snmp_manager = Arc::new(crate::core::snmp_manager::SnmpManager::new(vault_client.clone()));
    let audit_manager = Arc::new(crate::core::audit_manager::AuditManager::new(vault_client.clone()));
    let snmp_agent = Arc::new(crate::core::snmp_agent::SnmpAgent::new(vault_client.clone(), audit_manager.clone()));
    let trap_listener = Arc::new(crate::core::snmp_trap_listener::SnmpTrapListener::new(
        vault_client.clone(),
        audit_manager.clone(),
    ));

    // Start SNMP agent
    let snmp_agent_clone = Arc::clone(&snmp_agent);
    tokio::spawn(async move {
        if let Err(e) = snmp_agent_clone.start("127.0.0.1:161").await {
            eprintln!("Failed to start SNMP agent: {}", e);
        }
    });

    // Start trap listener
    let trap_listener_clone = Arc::clone(&trap_listener);
    tokio::spawn(async move {
        let mut listener = Arc::try_unwrap(trap_listener_clone).unwrap();
        if let Err(e) = listener.start().await {
            eprintln!("Failed to start SNMP trap listener: {}", e);
            return;
        }
        if let Err(e) = listener.listen().await {
            eprintln!("SNMP trap listener error: {}", e);
        }
    });

    let routes = routes::routes(
        vault_manager,
        key_service,
        auth_service,
        session_service,
        application_service,
        two_factor_service,
        ws_server,
        snmp_manager,
        snmp_agent,
        trap_listener,
        audit_manager,
    );

    // Get port from environment variable or default to 8080
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()
        .expect("PORT must be a valid port number");

    println!("Server started at http://localhost:{}", port);

    warp::serve(routes)
        .run(([127, 0, 0, 1], port))
        .await;
}
