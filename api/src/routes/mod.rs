// Routes Rust mod

use warp::Filter;
use std::sync::Arc;
use crate::middlewares::auth::authenticate;
use crate::services::vault_manager::VaultManager;
use crate::controllers;

pub fn routes(vault_manager: Arc<VaultManager>) -> impl Filter<Extract = impl Reply, Error = warp::Rejection> + Clone {
    let hello = warp::path!("hello")
        .map(|| "Hello, World!");

    let protected = warp::path!("protected")
        .and(warp::any().map(move || vault_manager.clone()))
        .and(authenticate())
        .and_then(|vm: Arc<VaultManager>, (key, key_type)| async move {
            crate::middlewares::auth::validate_key(vm, key, key_type).await
        })
        .map(|api_key: crate::models::ApiKey| {
            format!("Protected resource for key type: {:?}", api_key.key_type)
        });

    hello.or(protected)
}