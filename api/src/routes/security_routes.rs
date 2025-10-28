//! # Security Routes
//!
//! API endpoints for cryptographic operations and security management.
//! These endpoints provide access to modern cryptographic primitives.

use warp::Filter;
use std::sync::Arc;
use crate::services::security_service::{SecurityService, SECURITY_SERVICE};
use crate::middlewares::auth_middleware::jwt_auth;

/// Security routes configuration
pub fn security_routes() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let security_service = Arc::new(SecurityService::new());

    // Base path for all security routes
    let security_base = warp::path("api")
        .and(warp::path("v1"))
        .and(warp::path("security"));

    // Public routes (no authentication required)
    let status = security_base
        .and(warp::path("status"))
        .and(warp::get())
        .and_then(security_status);

    // Authenticated routes (JWT required)
    let authenticated_base = security_base.and(jwt_auth());

    // Key management routes
    let generate_encryption_key = authenticated_base.clone()
        .and(warp::path("keys"))
        .and(warp::path("encryption"))
        .and(warp::path("generate"))
        .and(warp::post())
        .and(warp::body::json())
        .and_then(generate_encryption_key);

    let generate_signing_key = authenticated_base.clone()
        .and(warp::path("keys"))
        .and(warp::path("signing"))
        .and(warp::path("generate"))
        .and(warp::post())
        .and(warp::body::json())
        .and_then(generate_signing_key);

    // Encryption/Decryption routes
    let encrypt_data = authenticated_base.clone()
        .and(warp::path("encrypt"))
        .and(warp::post())
        .and(warp::body::json())
        .and_then(encrypt_data_endpoint);

    let decrypt_data = authenticated_base.clone()
        .and(warp::path("decrypt"))
        .and(warp::post())
        .and(warp::body::json())
        .and_then(decrypt_data_endpoint);

    // Signing routes
    let sign_data = authenticated_base.clone()
        .and(warp::path("sign"))
        .and(warp::post())
        .and(warp::body::json())
        .and_then(sign_data_endpoint);

    let verify_signature = authenticated_base.clone()
        .and(warp::path("verify"))
        .and(warp::post())
        .and(warp::body::json())
        .and_then(verify_signature_endpoint);

    // Password hashing routes
    let hash_password = authenticated_base.clone()
        .and(warp::path("password"))
        .and(warp::path("hash"))
        .and(warp::post())
        .and(warp::body::json())
        .and_then(hash_password_endpoint);

    let verify_password = authenticated_base.clone()
        .and(warp::path("password"))
        .and(warp::path("verify"))
        .and(warp::post())
        .and(warp::body::json())
        .and_then(verify_password_endpoint);

    // Key exchange routes
    let key_exchange = authenticated_base.clone()
        .and(warp::path("key-exchange"))
        .and(warp::post())
        .and_then(key_exchange_endpoint);

    // Hash routes
    let hash_data = authenticated_base.clone()
        .and(warp::path("hash"))
        .and(warp::post())
        .and(warp::body::json())
        .and_then(hash_data_endpoint);

    // Random data generation
    let generate_random = authenticated_base.clone()
        .and(warp::path("random"))
        .and(warp::post())
        .and(warp::body::json())
        .and_then(generate_random_endpoint);

    // Combine all routes
    status
        .or(generate_encryption_key)
        .or(generate_signing_key)
        .or(encrypt_data)
        .or(decrypt_data)
        .or(sign_data)
        .or(verify_signature)
        .or(hash_password)
        .or(verify_password)
        .or(key_exchange)
        .or(hash_data)
        .or(generate_random)
}

// ============================================================================
// HANDLERS
// ============================================================================

/// Get security service status
async fn security_status() -> Result<impl warp::Reply, warp::Rejection> {
    let status = SECURITY_SERVICE.get_security_status().await;
    Ok(warp::reply::json(&status))
}

/// Generate encryption key
async fn generate_encryption_key(
    _claims: crate::middlewares::auth_middleware::Claims,
    body: serde_json::Value
) -> Result<impl warp::Reply, warp::Rejection> {
    let key_id = body.get("key_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| warp::reject::custom(crate::middlewares::auth::AuthError::InvalidKey))?;

    SECURITY_SERVICE.generate_encryption_key(key_id).await
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::VaultError))?;

    Ok(warp::reply::json(&serde_json::json!({
        "status": "success",
        "message": format!("Encryption key '{}' generated successfully", key_id)
    })))
}

/// Generate signing key
async fn generate_signing_key(
    _claims: crate::middlewares::auth_middleware::Claims,
    body: serde_json::Value
) -> Result<impl warp::Reply, warp::Rejection> {
    let key_id = body.get("key_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| warp::reject::custom(crate::middlewares::auth::AuthError::InvalidKey))?;

    let key_type = body.get("key_type")
        .and_then(|v| v.as_str())
        .unwrap_or("ed25519");

    match key_type {
        "ed25519" => {
            SECURITY_SERVICE.generate_api_signing_key(key_id).await
                .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::VaultError))?;
        }
        "ecdsa-p384" => {
            SECURITY_SERVICE.generate_high_security_signing_key(key_id).await
                .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::VaultError))?;
        }
        _ => return Err(warp::reject::custom(crate::middlewares::auth::AuthError::InvalidKeyType)),
    }

    Ok(warp::reply::json(&serde_json::json!({
        "status": "success",
        "message": format!("Signing key '{}' ({}) generated successfully", key_id, key_type)
    })))
}

/// Encrypt data
async fn encrypt_data_endpoint(
    _claims: crate::middlewares::auth_middleware::Claims,
    body: serde_json::Value
) -> Result<impl warp::Reply, warp::Rejection> {
    let key_id = body.get("key_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| warp::reject::custom(crate::middlewares::auth::AuthError::InvalidKey))?;

    let data = body.get("data")
        .and_then(|v| v.as_str())
        .ok_or_else(|| warp::reject::custom(crate::middlewares::auth::AuthError::InvalidKey))?;

    let plaintext = base64::decode(data)
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::InvalidKey))?;

    let ciphertext = SECURITY_SERVICE.encrypt_sensitive_data(key_id, &plaintext).await
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::VaultError))?;

    Ok(warp::reply::json(&serde_json::json!({
        "status": "success",
        "ciphertext": base64::encode(&ciphertext)
    })))
}

/// Decrypt data
async fn decrypt_data_endpoint(
    _claims: crate::middlewares::auth_middleware::Claims,
    body: serde_json::Value
) -> Result<impl warp::Reply, warp::Rejection> {
    let key_id = body.get("key_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| warp::reject::custom(crate::middlewares::auth::AuthError::InvalidKey))?;

    let data = body.get("data")
        .and_then(|v| v.as_str())
        .ok_or_else(|| warp::reject::custom(crate::middlewares::auth::AuthError::InvalidKey))?;

    let ciphertext = base64::decode(data)
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::InvalidKey))?;

    let plaintext = SECURITY_SERVICE.decrypt_sensitive_data(key_id, &ciphertext).await
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::VaultError))?;

    Ok(warp::reply::json(&serde_json::json!({
        "status": "success",
        "plaintext": base64::encode(&plaintext)
    })))
}

/// Sign data
async fn sign_data_endpoint(
    _claims: crate::middlewares::auth_middleware::Claims,
    body: serde_json::Value
) -> Result<impl warp::Reply, warp::Rejection> {
    let key_id = body.get("key_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| warp::reject::custom(crate::middlewares::auth::AuthError::InvalidKey))?;

    let data = body.get("data")
        .and_then(|v| v.as_str())
        .ok_or_else(|| warp::reject::custom(crate::middlewares::auth::AuthError::InvalidKey))?;

    let data_bytes = base64::decode(data)
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::InvalidKey))?;

    let signature = SECURITY_SERVICE.sign_api_token(key_id, &data_bytes).await
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::VaultError))?;

    Ok(warp::reply::json(&serde_json::json!({
        "status": "success",
        "signature": base64::encode(&signature)
    })))
}

/// Verify signature
async fn verify_signature_endpoint(
    _claims: crate::middlewares::auth_middleware::Claims,
    body: serde_json::Value
) -> Result<impl warp::Reply, warp::Rejection> {
    let key_id = body.get("key_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| warp::reject::custom(crate::middlewares::auth::AuthError::InvalidKey))?;

    let data = body.get("data")
        .and_then(|v| v.as_str())
        .ok_or_else(|| warp::reject::custom(crate::middlewares::auth::AuthError::InvalidKey))?;

    let signature = body.get("signature")
        .and_then(|v| v.as_str())
        .ok_or_else(|| warp::reject::custom(crate::middlewares::auth::AuthError::InvalidKey))?;

    let data_bytes = base64::decode(data)
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::InvalidKey))?;

    let signature_bytes = base64::decode(signature)
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::InvalidKey))?;

    let is_valid = SECURITY_SERVICE.verify_api_token(key_id, &data_bytes, &signature_bytes).await.is_ok();

    Ok(warp::reply::json(&serde_json::json!({
        "status": "success",
        "valid": is_valid
    })))
}

/// Hash password
async fn hash_password_endpoint(
    _claims: crate::middlewares::auth_middleware::Claims,
    body: serde_json::Value
) -> Result<impl warp::Reply, warp::Rejection> {
    let password = body.get("password")
        .and_then(|v| v.as_str())
        .ok_or_else(|| warp::reject::custom(crate::middlewares::auth::AuthError::InvalidKey))?;

    let (salt, hash) = SECURITY_SERVICE.hash_password(password.as_bytes()).await
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::VaultError))?;

    Ok(warp::reply::json(&serde_json::json!({
        "status": "success",
        "salt": base64::encode(&salt),
        "hash": hash
    })))
}

/// Verify password
async fn verify_password_endpoint(
    _claims: crate::middlewares::auth_middleware::Claims,
    body: serde_json::Value
) -> Result<impl warp::Reply, warp::Rejection> {
    let password = body.get("password")
        .and_then(|v| v.as_str())
        .ok_or_else(|| warp::reject::custom(crate::middlewares::auth::AuthError::InvalidKey))?;

    let salt = body.get("salt")
        .and_then(|v| v.as_str())
        .ok_or_else(|| warp::reject::custom(crate::middlewares::auth::AuthError::InvalidKey))?;

    let hash = body.get("hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| warp::reject::custom(crate::middlewares::auth::AuthError::InvalidKey))?;

    let salt_bytes = base64::decode(salt)
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::InvalidKey))?;

    let is_valid = SECURITY_SERVICE.verify_password(password.as_bytes(), &salt_bytes, hash).await
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::VaultError))?;

    Ok(warp::reply::json(&serde_json::json!({
        "status": "success",
        "valid": is_valid
    })))
}

/// Perform key exchange
async fn key_exchange_endpoint(
    _claims: crate::middlewares::auth_middleware::Claims
) -> Result<impl warp::Reply, warp::Rejection> {
    let (_alice_keys, _bob_keys, shared_key) = SECURITY_SERVICE.perform_key_exchange().await;

    Ok(warp::reply::json(&serde_json::json!({
        "status": "success",
        "shared_key": base64::encode(&shared_key),
        "note": "In production, keys would be exchanged securely between parties"
    })))
}

/// Hash data
async fn hash_data_endpoint(
    _claims: crate::middlewares::auth_middleware::Claims,
    body: serde_json::Value
) -> Result<impl warp::Reply, warp::Rejection> {
    let data = body.get("data")
        .and_then(|v| v.as_str())
        .ok_or_else(|| warp::reject::custom(crate::middlewares::auth::AuthError::InvalidKey))?;

    let data_bytes = base64::decode(data)
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::InvalidKey))?;

    let hash = SECURITY_SERVICE.hash_data(&data_bytes).await;

    Ok(warp::reply::json(&serde_json::json!({
        "status": "success",
        "algorithm": "SHA-512",
        "hash": base64::encode(&hash)
    })))
}

/// Generate random data
async fn generate_random_endpoint(
    _claims: crate::middlewares::auth_middleware::Claims,
    body: serde_json::Value
) -> Result<impl warp::Reply, warp::Rejection> {
    let length = body.get("length")
        .and_then(|v| v.as_u64())
        .unwrap_or(32) as usize;

    let random_data = SECURITY_SERVICE.generate_secure_random(length).await;

    Ok(warp::reply::json(&serde_json::json!({
        "status": "success",
        "data": base64::encode(&random_data)
    })))
}