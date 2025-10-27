// Routes Rust mod

pub mod key_routes;

use warp::Filter;
use std::sync::Arc;
use crate::services::vault_manager::VaultManager;
use crate::services::key_service::KeyService;

pub fn routes(vault_manager: Arc<VaultManager>, key_service: Arc<KeyService>) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let hello = warp::path!("hello")
        .map(|| "Hello, World!");

    let key_routes = crate::routes::key_routes::key_routes(key_service);

    hello.or(key_routes)
}