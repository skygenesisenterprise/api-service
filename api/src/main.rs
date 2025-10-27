use warp::{Filter, Reply};
use std::convert::Infallible;
use std::sync::Arc;
use dotenv::dotenv;

mod models;
mod services;
mod middlewares;
mod routes;
mod controllers;
mod core;
mod queries;
mod utils;
mod tests;

#[tokio::main]
async fn main() {
    dotenv().ok();

    let vault_addr = std::env::var("VAULT_ADDR").unwrap_or("https://vault.skygenesisenterprise.com".to_string());
    let role_id = std::env::var("VAULT_ROLE_ID").expect("VAULT_ROLE_ID must be set");
    let secret_id = std::env::var("VAULT_SECRET_ID").expect("VAULT_SECRET_ID must be set");
    let vault_client = Arc::new(crate::core::vault::VaultClient::new(vault_addr, role_id, secret_id).await.unwrap());

    let keycloak_client = Arc::new(crate::core::keycloak::KeycloakClient::new(vault_client.clone()).await.unwrap());
    let auth_service = Arc::new(crate::services::auth_service::AuthService::new(keycloak_client, vault_client.clone()));

    let key_service = Arc::new(crate::services::key_service::KeyService::new(vault_client));

    let vault_token = std::env::var("VAULT_TOKEN").unwrap_or_default();
    let vault_manager = Arc::new(crate::services::vault_manager::VaultManager::new("dummy".to_string(), vault_token));

    let routes = routes::routes(vault_manager, key_service, auth_service);

    println!("Server started at http://localhost:3000");

    warp::serve(routes)
        .run(([127, 0, 0, 1], 3000))
        .await;
}
