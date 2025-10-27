use warp::{Filter, Rejection, Reply};
use crate::models::{ApiKey, KeyType};
use crate::services::vault_manager::VaultManager;
use std::sync::Arc;

pub fn authenticate() -> impl Filter<Extract = ((Arc<VaultManager>, String, String),), Error = Rejection> + Clone {
    warp::header::<String>("x-api-key")
        .or(warp::header::<String>("authorization"))
        .unify()
        .and(warp::header::<String>("x-key-type"))
        .map(|key, key_type| (key, key_type))
}

pub async fn validate_key(vault_manager: Arc<VaultManager>, key: String, key_type_str: String) -> Result<ApiKey, Rejection> {
    let key_type = match key_type_str.as_str() {
        "client" => KeyType::Client,
        "server" => KeyType::Server,
        "database" => KeyType::Database,
        _ => return Err(warp::reject::custom(AuthError::InvalidKeyType)),
    };

    let is_valid = vault_manager.validate_access(&key_type_str, &key).await
        .map_err(|_| warp::reject::custom(AuthError::VaultError))?;

    if !is_valid {
        return Err(warp::reject::custom(AuthError::InvalidKey));
    }

    let api_key = ApiKey {
        id: key,
        key_type,
        vault_path: format!("secret/{}", key_type_str),
        created_at: chrono::Utc::now(),
        permissions: vec!["read".to_string()], // Can be fetched from Vault
    };

    Ok(api_key)
}

#[derive(Debug)]
pub enum AuthError {
    InvalidKey,
    InvalidKeyType,
    VaultError,
}

impl AuthError {
    pub fn invalid_key() -> Self {
        AuthError::InvalidKey
    }

    pub fn invalid_key_type() -> Self {
        AuthError::InvalidKeyType
    }

    pub fn vault_error() -> Self {
        AuthError::VaultError
    }
}

impl warp::reject::Reject for AuthError {}