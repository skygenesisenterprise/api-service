// Routes Rust mod

pub mod key_routes;
pub mod auth_routes;

use warp::Filter;
use std::sync::Arc;
use crate::services::vault_manager::VaultManager;
use crate::services::key_service::KeyService;
use crate::services::auth_service::AuthService;

pub fn routes(vault_manager: Arc<VaultManager>, key_service: Arc<KeyService>, auth_service: Arc<AuthService>) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let hello = warp::path!("hello")
        .map(|| "Hello, World!");

    let key_routes = crate::routes::key_routes::key_routes(key_service);
    let auth_routes = crate::routes::auth_routes::auth_routes(auth_service);

    hello.or(key_routes).or(auth_routes)
}