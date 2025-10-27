use warp::{Filter, Reply};
use std::convert::Infallible;
use std::sync::Arc;
use dotenv::dotenv;

mod models;
mod services;
mod middlewares;
mod routes;
mod controllers;

#[tokio::main]
async fn main() {
    dotenv().ok();

    let vault_addr = std::env::var("VAULT_ADDR").unwrap_or("https://vault.skygenesisenterprise.com".to_string());
    let vault_token = std::env::var("VAULT_TOKEN").expect("VAULT_TOKEN must be set");
    let vault_manager = Arc::new(crate::services::vault_manager::VaultManager::new(vault_addr, vault_token));

    let routes = routes::routes(vault_manager);

    println!("Server started at http://localhost:3000");

    warp::serve(routes)
        .run(([127, 0, 0, 1], 3000))
        .await;
}
