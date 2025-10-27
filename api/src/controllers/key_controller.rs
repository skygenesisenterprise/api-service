use warp::Reply;
use crate::models::key_model::{ApiKey, KeyType};
use crate::services::key_service::KeyService;
use std::sync::Arc;

pub async fn create_key(
    key_service: Arc<KeyService>,
    key_type: String,
    tenant: String,
    ttl: u64,
) -> Result<impl Reply, warp::Rejection> {
    let kt = match key_type.as_str() {
        "client" => KeyType::Client,
        "server" => KeyType::Server,
        "database" => KeyType::Database,
        _ => return Err(warp::reject::custom(crate::middlewares::auth::AuthError::InvalidKeyType)),
    };
    let api_key = key_service.create_key(kt, tenant, ttl).await
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::VaultError))?;
    Ok(warp::reply::json(&api_key))
}

pub async fn revoke_key(
    key_service: Arc<KeyService>,
    id: String,
) -> Result<impl Reply, warp::Rejection> {
    key_service.revoke_key(&id).await
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::VaultError))?;
    Ok(warp::reply::json(&serde_json::json!({"message": "Key revoked"})))
}

pub async fn get_key(
    key_service: Arc<KeyService>,
    id: String,
) -> Result<impl Reply, warp::Rejection> {
    let api_key = key_service.get_key(&id).await
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::VaultError))?;
    Ok(warp::reply::json(&api_key))
}

pub async fn list_keys(
    key_service: Arc<KeyService>,
    tenant: String,
) -> Result<impl Reply, warp::Rejection> {
    let keys = key_service.list_keys(&tenant).await
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::VaultError))?;
    Ok(warp::reply::json(&keys))
}