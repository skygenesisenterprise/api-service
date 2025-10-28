use warp::Reply;
use crate::models::key_model::{ApiKey, KeyType, CertificateType, ApiKeyStatus};
use crate::services::key_service::KeyService;
use std::sync::Arc;

pub async fn create_key(
    key_service: Arc<KeyService>,
    key_type: String,
    tenant: String,
    ttl: u64,
    status: String,
) -> Result<impl Reply, warp::Rejection> {
    let kt = match key_type.as_str() {
        "client" => KeyType::Client,
        "server" => KeyType::Server,
        "database" => KeyType::Database,
        _ => return Err(warp::reject::custom(crate::middlewares::auth::AuthError::InvalidKeyType)),
    };

    let status = match status.as_str() {
        "sandbox" => ApiKeyStatus::Sandbox,
        "production" => ApiKeyStatus::Production,
        _ => return Err(warp::reject::custom(crate::middlewares::auth::AuthError::InvalidKeyType)),
    };

    let api_key = key_service.create_key(kt, tenant, ttl, status).await
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

pub async fn create_key_with_certificate(
    key_service: Arc<KeyService>,
    key_type: String,
    tenant: String,
    ttl: u64,
    cert_type: String,
    status: String,
) -> Result<impl Reply, warp::Rejection> {
    let kt = match key_type.as_str() {
        "client" => KeyType::Client,
        "server" => KeyType::Server,
        "database" => KeyType::Database,
        _ => return Err(warp::reject::custom(crate::middlewares::auth::AuthError::InvalidKeyType)),
    };

    let ct = match cert_type.as_str() {
        "rsa" => CertificateType::RSA,
        "ecdsa" => CertificateType::ECDSA,
        _ => return Err(warp::reject::custom(crate::middlewares::auth::AuthError::InvalidKeyType)),
    };

    let status = match status.as_str() {
        "sandbox" => ApiKeyStatus::Sandbox,
        "production" => ApiKeyStatus::Production,
        _ => return Err(warp::reject::custom(crate::middlewares::auth::AuthError::InvalidKeyType)),
    };

    let api_key = key_service.create_key_with_certificate_specific(kt, tenant, ttl, ct, status).await
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::VaultError))?;
    Ok(warp::reply::json(&api_key))
}

pub async fn get_public_key(
    key_service: Arc<KeyService>,
    id: String,
) -> Result<impl Reply, warp::Rejection> {
    let api_key = key_service.get_key(&id).await
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::VaultError))?;

    if let Some(certificate) = api_key.certificate {
        Ok(warp::reply::json(&serde_json::json!({
            "public_key": certificate.public_key,
            "certificate_type": certificate.certificate_type,
            "fingerprint": certificate.fingerprint
        })))
    } else {
        Err(warp::reject::custom(crate::middlewares::auth::AuthError::InvalidKeyType))
    }
}

pub async fn revoke_certificate(
    key_service: Arc<KeyService>,
    id: String,
) -> Result<impl Reply, warp::Rejection> {
    // For certificate revocation, we mark the key as revoked
    // In a real implementation, you might want to maintain a CRL (Certificate Revocation List)
    key_service.revoke_key(&id).await
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::VaultError))?;
    Ok(warp::reply::json(&serde_json::json!({"message": "Certificate revoked"})))
}

// Convenience functions for creating sandbox and production keys
pub async fn create_sandbox_key(
    key_service: Arc<KeyService>,
    key_type: String,
    tenant: String,
    ttl: u64,
) -> Result<impl Reply, warp::Rejection> {
    create_key(key_service, key_type, tenant, ttl, "sandbox".to_string()).await
}

pub async fn create_production_key(
    key_service: Arc<KeyService>,
    key_type: String,
    tenant: String,
    ttl: u64,
) -> Result<impl Reply, warp::Rejection> {
    create_key(key_service, key_type, tenant, ttl, "production".to_string()).await
}

pub async fn create_sandbox_key_with_certificate(
    key_service: Arc<KeyService>,
    key_type: String,
    tenant: String,
    ttl: u64,
    cert_type: String,
) -> Result<impl Reply, warp::Rejection> {
    create_key_with_certificate(key_service, key_type, tenant, ttl, cert_type, "sandbox".to_string()).await
}

pub async fn create_production_key_with_certificate(
    key_service: Arc<KeyService>,
    key_type: String,
    tenant: String,
    ttl: u64,
    cert_type: String,
) -> Result<impl Reply, warp::Rejection> {
    create_key_with_certificate(key_service, key_type, tenant, ttl, cert_type, "production".to_string()).await
}