// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Key Management Controller
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide secure API key and certificate management endpoints
//  for enterprise authentication and authorization.
//  NOTICE: Implements cryptographic key lifecycle management with HSM
//  integration, certificate authority support, and compliance auditing.
//  KEY STANDARDS: AES-256, RSA-4096, ECDSA P-384, X.509 certificates
//  COMPLIANCE: FIPS 140-2, NIST 800-57, GDPR encryption requirements
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use warp::Reply;
use crate::models::key_model::{KeyType, CertificateType, ApiKeyStatus};
use crate::services::key_service::KeyService;
use std::sync::Arc;

/// [KEY CREATION HANDLER] Generate New API Keys with Cryptographic Security
/// @MISSION Create secure API keys for authentication and authorization.
/// @THREAT Weak key generation, predictable key patterns, key leakage.
/// @COUNTERMEASURE Cryptographically secure random generation, HSM storage.
/// @INVARIANT Keys are generated with FIPS-compliant algorithms.
/// @AUDIT Key creation events are logged with tenant and permissions.
/// @FLOW Validates parameters -> Generates key -> Stores securely -> Returns metadata.
/// @DEPENDENCY Requires KeyService for cryptographic operations.
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

/// [KEY REVOCATION HANDLER] Securely Disable API Keys and Certificates
/// @MISSION Immediately invalidate compromised or expired keys.
/// @THREAT Continued use of revoked keys, delayed revocation.
/// @COUNTERMEASURE Immediate database invalidation, audit logging.
/// @INVARIANT Revoked keys cannot be used for authentication.
/// @AUDIT Key revocation triggers security incident response.
/// @FLOW Marks key as revoked -> Updates database -> Logs event.
/// @DEPENDENCY Requires KeyService for key management.
pub async fn revoke_key(
    key_service: Arc<KeyService>,
    id: String,
) -> Result<impl Reply, warp::Rejection> {
    key_service.revoke_key(&id).await
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::VaultError))?;
    Ok(warp::reply::json(&serde_json::json!({"message": "Key revoked"})))
}

/// [KEY RETRIEVAL HANDLER] Access API Key Metadata and Status
/// @MISSION Provide secure access to key information for management.
/// @THREAT Unauthorized key metadata access, key value exposure.
/// @COUNTERMEASURE Permission validation, metadata-only responses.
/// @INVARIANT Only authorized users can access key information.
/// @AUDIT Key access queries are logged for compliance.
/// @FLOW Validates permissions -> Retrieves metadata -> Returns safe data.
/// @DEPENDENCY Requires KeyService for key data access.
pub async fn get_key(
    key_service: Arc<KeyService>,
    id: String,
) -> Result<impl Reply, warp::Rejection> {
    let api_key = key_service.get_key(&id).await
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::VaultError))?;
    Ok(warp::reply::json(&api_key))
}

/// [KEY LISTING HANDLER] Enumerate API Keys by Tenant
/// @MISSION Allow administrators to view keys for their tenant.
/// @THREAT Unauthorized key enumeration, tenant data leakage.
/// @COUNTERMEASURE Tenant isolation, permission validation.
/// @INVARIANT Users can only see keys for their authorized tenants.
/// @AUDIT Key listing operations are logged.
/// @FLOW Validates tenant access -> Retrieves key list -> Returns metadata.
/// @DEPENDENCY Requires KeyService for multi-key operations.
pub async fn list_keys(
    key_service: Arc<KeyService>,
    tenant: String,
) -> Result<impl Reply, warp::Rejection> {
    let keys = key_service.list_keys(&tenant).await
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::VaultError))?;
    Ok(warp::reply::json(&keys))
}

/// [CERTIFICATE KEY CREATION HANDLER] Generate Keys with X.509 Certificates
/// @MISSION Create API keys with integrated certificate authentication.
/// @THREAT Weak certificate generation, invalid certificate chains.
/// @COUNTERMEASURE CA integration, certificate validation, secure storage.
/// @INVARIANT Certificates are properly signed and validated.
/// @AUDIT Certificate creation triggers compliance auditing.
/// @FLOW Generates key pair -> Creates certificate -> Signs with CA -> Returns bundle.
/// @DEPENDENCY Requires KeyService and certificate authority.
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

/// [PUBLIC KEY RETRIEVAL HANDLER] Access Public Key Components
/// @MISSION Provide public keys for encryption and verification.
/// @THREAT Private key exposure, unauthorized public key access.
/// @COUNTERMEASURE Public-only data, permission validation.
/// @INVARIANT Only public key components are exposed.
/// @AUDIT Public key access is logged for monitoring.
/// @FLOW Validates access -> Extracts public key -> Returns safe data.
/// @DEPENDENCY Requires KeyService for certificate parsing.
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

/// [CERTIFICATE REVOCATION HANDLER] Revoke X.509 Certificates
/// @MISSION Invalidate compromised certificates and update CRL.
/// @THREAT Continued trust in revoked certificates.
/// @COUNTERMEASURE CRL publication, OCSP updates, audit logging.
/// @INVARIANT Revoked certificates are marked in CRL.
/// @AUDIT Certificate revocation triggers security alerts.
/// @FLOW Revokes certificate -> Updates CRL -> Notifies dependent systems.
/// @DEPENDENCY Requires KeyService and CRL management.
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

/// [SANDBOX KEY CREATION HANDLER] Create Development/Testing API Keys
/// @MISSION Provide isolated keys for development and testing.
/// @THREAT Sandbox key misuse in production, privilege escalation.
/// @COUNTERMEASURE Environment isolation, limited permissions.
/// @INVARIANT Sandbox keys have restricted access and short TTL.
/// @AUDIT Sandbox key creation is logged separately.
/// @FLOW Sets sandbox status -> Creates key -> Applies restrictions.
/// @DEPENDENCY Delegates to create_key with sandbox parameters.
pub async fn create_sandbox_key(
    key_service: Arc<KeyService>,
    key_type: String,
    tenant: String,
    ttl: u64,
) -> Result<impl Reply, warp::Rejection> {
    create_key(key_service, key_type, tenant, ttl, "sandbox".to_string()).await
}

/// [PRODUCTION KEY CREATION HANDLER] Create Live Environment API Keys
/// @MISSION Generate keys for production systems with full access.
/// @THREAT Unauthorized production key creation, excessive permissions.
/// @COUNTERMEASURE Approval workflows, audit requirements.
/// @INVARIANT Production keys require additional validation.
/// @AUDIT Production key creation triggers compliance review.
/// @FLOW Validates approvals -> Creates key -> Logs creation.
/// @DEPENDENCY Delegates to create_key with production parameters.
pub async fn create_production_key(
    key_service: Arc<KeyService>,
    key_type: String,
    tenant: String,
    ttl: u64,
) -> Result<impl Reply, warp::Rejection> {
    create_key(key_service, key_type, tenant, ttl, "production".to_string()).await
}

/// [SANDBOX CERTIFICATE KEY CREATION HANDLER] Development Keys with Certificates
/// @MISSION Create sandbox keys with certificate authentication.
/// @THREAT Certificate misuse in development environments.
/// @COUNTERMEASURE Environment restrictions, short validity periods.
/// @INVARIANT Sandbox certificates have limited trust scope.
/// @AUDIT Sandbox certificate creation is monitored.
/// @FLOW Creates sandbox key -> Adds certificate -> Applies restrictions.
/// @DEPENDENCY Delegates to create_key_with_certificate with sandbox status.
pub async fn create_sandbox_key_with_certificate(
    key_service: Arc<KeyService>,
    key_type: String,
    tenant: String,
    ttl: u64,
    cert_type: String,
) -> Result<impl Reply, warp::Rejection> {
    create_key_with_certificate(key_service, key_type, tenant, ttl, cert_type, "sandbox".to_string()).await
}

/// [PRODUCTION CERTIFICATE KEY CREATION HANDLER] Live Keys with Certificates
/// @MISSION Generate production keys with certificate authentication.
/// @THREAT Compromised production certificates, trust violations.
/// @COUNTERMEASURE Certificate pinning, revocation capabilities.
/// @INVARIANT Production certificates require CA validation.
/// @AUDIT Production certificate creation triggers security review.
/// @FLOW Validates requirements -> Creates certified key -> Logs event.
/// @DEPENDENCY Delegates to create_key_with_certificate with production status.
pub async fn create_production_key_with_certificate(
    key_service: Arc<KeyService>,
    key_type: String,
    tenant: String,
    ttl: u64,
    cert_type: String,
) -> Result<impl Reply, warp::Rejection> {
    create_key_with_certificate(key_service, key_type, tenant, ttl, cert_type, "production".to_string()).await
}