// ============================================================================
// Sky Genesis Enterprise API - API Key Authentication Middleware
// ============================================================================

use warp::{Filter, Reply, Rejection};
use std::sync::Arc;
use crate::services::api_keys::ApiKeyService;
use crate::models::api_keys::{ApiKey, KeyType, KeyStatus};
use serde_json;
use chrono::Utc;

// ============================================================================
// Authentication Context
// ============================================================================

#[derive(Debug, Clone)]
pub struct AuthContext {
    pub api_key: ApiKey,
    pub organization_id: uuid::Uuid,
    pub permissions: Vec<String>,
    pub key_type: KeyType,
}

// ============================================================================
// Middleware Filters
// ============================================================================

pub fn with_api_key_service(
    service: Arc<ApiKeyService>
) -> impl Filter<Extract = (Arc<ApiKeyService>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || service.clone())
}

// ============================================================================
// API Key Authentication
// ============================================================================

pub fn authenticate_api_key(
    service: Arc<ApiKeyService>
) -> impl Filter<Extract = (AuthContext,), Error = Rejection> + Clone {
    warp::header::optional::<String>("authorization")
        .or(warp::header::optional::<String>("x-api-key"))
        .unify()
        .and(with_api_key_service(service))
        .and_then(|auth_header: Option<String>, api_key_header: Option<String>, service: Arc<ApiKeyService>| async move {
            // Extract API key from Authorization header (Bearer token) or X-API-Key header
            let key_value = if let Some(auth) = auth_header {
                if auth.starts_with("Bearer ") {
                    Some(auth.trim_start_matches("Bearer "))
                } else if auth.starts_with("sk_") {
                    Some(auth.as_str())
                } else {
                    None
                }
            } else {
                api_key_header.as_deref()
            };

            match key_value {
                Some(key) => {
                    match service.get_key_by_value(key).await {
                        Ok(Some(api_key)) => {
                            // Check if key is active
                            if api_key.status != KeyStatus::Active {
                                return Err(warp::reject::custom(ApiKeyError::InactiveKey));
                            }

                            // Check if key has expired (for client keys)
                            if let Some(expires_at) = api_key.expires_at {
                                if expires_at < Utc::now() {
                                    return Err(warp::reject::custom(ApiKeyError::ExpiredKey));
                                }
                            }

                            // Check quota limit
                            if api_key.usage_count >= api_key.quota_limit {
                                return Err(warp::reject::custom(ApiKeyError::QuotaExceeded));
                            }

                            let context = AuthContext {
                                organization_id: api_key.organization_id,
                                permissions: api_key.permissions.clone(),
                                key_type: api_key.key_type.clone(),
                                api_key,
                            };

                            Ok(context)
                        }
                        Ok(None) => Err(warp::reject::custom(ApiKeyError::InvalidKey)),
                        Err(_) => Err(warp::reject::custom(ApiKeyError::ServiceError)),
                    }
                }
                None => Err(warp::reject::custom(ApiKeyError::MissingKey)),
            }
        })
}

// ============================================================================
// Permission-based Authorization
// ============================================================================

pub fn require_permission(
    permission: &'static str
) -> impl Filter<Extract = (AuthContext,), Error = Rejection> + Clone {
    authenticate_api_key(Arc::new(ApiKeyService::new(/* TODO: Get DB pool */)))
        .and_then(|context: AuthContext| async move {
            if context.permissions.contains(&permission.to_string()) {
                Ok(context)
            } else {
                Err(warp::reject::custom(ApiKeyError::InsufficientPermissions))
            }
        })
}

pub fn require_any_permission(
    permissions: &'static [&'static str]
) -> impl Filter<Extract = (AuthContext,), Error = Rejection> + Clone {
    authenticate_api_key(Arc::new(ApiKeyService::new(/* TODO: Get DB pool */)))
        .and_then(|context: AuthContext| async move {
            let has_permission = permissions.iter().any(|&perm| {
                context.permissions.contains(&perm.to_string())
            });

            if has_permission {
                Ok(context)
            } else {
                Err(warp::reject::custom(ApiKeyError::InsufficientPermissions))
            }
        })
}

pub fn require_all_permissions(
    permissions: &'static [&'static str]
) -> impl Filter<Extract = (AuthContext,), Error = Rejection> + Clone {
    authenticate_api_key(Arc::new(ApiKeyService::new(/* TODO: Get DB pool */)))
        .and_then(|context: AuthContext| async move {
            let has_all_permissions = permissions.iter().all(|&perm| {
                context.permissions.contains(&perm.to_string())
            });

            if has_all_permissions {
                Ok(context)
            } else {
                Err(warp::reject::custom(ApiKeyError::InsufficientPermissions))
            }
        })
}

// ============================================================================
// Key Type-based Authorization
// ============================================================================

pub fn require_key_type(
    allowed_types: &'static [KeyType]
) -> impl Filter(Extract = (AuthContext,), Error = Rejection) + Clone {
    authenticate_api_key(Arc::new(ApiKeyService::new(/* TODO: Get DB pool */)))
        .and_then(|context: AuthContext| async move {
            if allowed_types.contains(&context.key_type) {
                Ok(context)
            } else {
                Err(warp::reject::custom(ApiKeyError::InvalidKeyType))
            }
        })
}

pub fn require_client_key() -> impl Filter<Extract = (AuthContext,), Error = Rejection> + Clone {
    require_key_type(&[KeyType::Client])
}

pub fn require_server_key() -> impl Filter<Extract = (AuthContext,), Error = Rejection> + Clone {
    require_key_type(&[KeyType::Server])
}

pub fn require_database_key() -> impl Filter(Extract = (AuthContext,), Error = Rejection> + Clone {
    require_key_type(&[KeyType::Database])
}

// ============================================================================
// Origin Validation (for Client Keys)
// ============================================================================

pub fn validate_origin(
    allowed_origin: Option<String>
) -> impl Filter<Extract = (AuthContext,), Error = Rejection> + Clone {
    authenticate_api_key(Arc::new(ApiKeyService::new(/* TODO: Get DB pool */)))
        .and(warp::header::optional::<String>("origin"))
        .and_then(|context: AuthContext, request_origin: Option<String>| async move {
            // Only validate origin for client keys
            if context.key_type == KeyType::Client {
                if let Some(key_origin) = &context.api_key.client_origin {
                    if let Some(origin) = request_origin {
                        if origin != *key_origin {
                            return Err(warp::reject::custom(ApiKeyError::InvalidOrigin));
                        }
                    } else {
                        return Err(warp::reject::custom(ApiKeyError::MissingOrigin));
                    }
                }
            }

            Ok(context)
        })
}

// ============================================================================
// Usage Tracking Middleware
// ============================================================================

pub fn track_usage(
    service: Arc<ApiKeyService>
) -> impl Filter<Extract = (AuthContext,), Error = Rejection> + Clone {
    authenticate_api_key(service.clone())
        .and_then(|mut context: AuthContext| async move {
            // Increment usage count
            if let Err(_) = service.increment_usage(context.api_key.id).await {
                // Log error but don't fail the request
                eprintln!("Failed to track usage for key: {}", context.api_key.id);
            }

            // Update last used timestamp in context
            context.api_key.last_used_at = Some(Utc::now());

            Ok(context)
        })
}

// ============================================================================
// Rate Limiting Middleware
// ============================================================================

pub fn rate_limit(
    requests_per_minute: u32
) -> impl Filter<Extract = (AuthContext,), Error = Rejection> + Clone {
    authenticate_api_key(Arc::new(ApiKeyService::new(/* TODO: Get DB pool */)))
        .and_then(|context: AuthContext| async move {
            // TODO: Implement proper rate limiting using Redis or in-memory store
            // For now, just pass through
            Ok(context)
        })
}

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug)]
pub enum ApiKeyError {
    MissingKey,
    InvalidKey,
    InactiveKey,
    ExpiredKey,
    QuotaExceeded,
    InsufficientPermissions,
    InvalidKeyType,
    InvalidOrigin,
    MissingOrigin,
    ServiceError,
}

impl warp::reject::Reject for ApiKeyError {}

// ============================================================================
// Error Handling
// ============================================================================

pub async fn handle_api_key_rejection(err: Rejection) -> Result<impl Reply, Rejection> {
    if let Some(custom) = err.find::<ApiKeyError>() {
        let (code, message, status) = match custom {
            ApiKeyError::MissingKey => ("MISSING_API_KEY", "API key is required", 401),
            ApiKeyError::InvalidKey => ("INVALID_API_KEY", "Invalid or expired API key", 401),
            ApiKeyError::InactiveKey => ("INACTIVE_KEY", "API key is inactive", 401),
            ApiKeyError::ExpiredKey => ("EXPIRED_KEY", "API key has expired", 401),
            ApiKeyError::QuotaExceeded => ("QUOTA_EXCEEDED", "API key quota exceeded", 429),
            ApiKeyError::InsufficientPermissions => ("INSUFFICIENT_PERMISSIONS", "Insufficient permissions", 403),
            ApiKeyError::InvalidKeyType => ("INVALID_KEY_TYPE", "Invalid key type for this operation", 403),
            ApiKeyError::InvalidOrigin => ("INVALID_ORIGIN", "Invalid origin for client key", 403),
            ApiKeyError::MissingOrigin => ("MISSING_ORIGIN", "Origin header required for client key", 403),
            ApiKeyError::ServiceError => ("SERVICE_ERROR", "Internal service error", 500),
        };

        let response = serde_json::json!({
            "success": false,
            "error": message,
            "code": code,
            "timestamp": Utc::now().to_rfc3339()
        });

        Ok(warp::reply::with_status(
            warp::reply::json(&response),
            warp::http::StatusCode::from_u16(status).unwrap()
        ))
    } else {
        Err(err)
    }
}

// ============================================================================
// Middleware Combinators
// ============================================================================

/// Complete authentication middleware with usage tracking
pub fn auth_with_tracking(
    service: Arc<ApiKeyService>
) -> impl Filter<Extract = (AuthContext,), Error = Rejection> + Clone {
    authenticate_api_key(service.clone())
        .and(track_usage(service))
}

/// Authentication with specific permission requirement
pub fn auth_with_permission(
    service: Arc<ApiKeyService>,
    permission: &'static str
) -> impl Filter<Extract = (AuthContext,), Error = Rejection> + Clone {
    authenticate_api_key(service.clone())
        .and(track_usage(service))
        .and_then(|context: AuthContext| async move {
            if context.permissions.contains(&permission.to_string()) {
                Ok(context)
            } else {
                Err(warp::reject::custom(ApiKeyError::InsufficientPermissions))
            }
        })
}

/// Authentication for client keys with origin validation
pub fn auth_client_with_origin(
    service: Arc<ApiKeyService>
) -> impl Filter(Extract = (AuthContext,), Error = Rejection) + Clone {
    authenticate_api_key(service.clone())
        .and(validate_origin(None))
        .and(track_usage(service))
        .and_then(|context: AuthContext| async move {
            if context.key_type == KeyType::Client {
                Ok(context)
            } else {
                Err(warp::reject::custom(ApiKeyError::InvalidKeyType))
            }
        })
}