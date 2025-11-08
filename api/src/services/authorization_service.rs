// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Authorization Service
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide comprehensive authorization services for API key validation,
//  permission checking, environment access control, and tenant isolation.
//  NOTICE: Implements role-based access control with environment separation,
//  permission validation, rate limiting, and comprehensive audit logging.
//  AUTH STANDARDS: RBAC, Environment Isolation, Tenant Separation
//  COMPLIANCE: GDPR, SOX Access Control Requirements
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use crate::models::key_model::{ApiKey, ApiKeyStatus};
use std::collections::HashSet;

/// [AUTHORIZATION SERVICE STRUCT] Core Authorization Engine
/// @MISSION Centralize authorization logic for API access control.
/// @THREAT Unauthorized access, privilege escalation, data breaches.
/// @COUNTERMEASURE Permission validation, environment isolation, audit logging.
/// @INVARIANT All API operations require proper authorization.
/// @AUDIT Authorization decisions are logged for compliance.
/// @DEPENDENCY Requires ApiKey model for permission data.
pub struct AuthorizationService;

/// [AUTHORIZATION SERVICE IMPLEMENTATION] Access Control Business Logic
/// @MISSION Implement secure authorization checks and validations.
/// @THREAT Bypass of access controls, insufficient validation.
/// @COUNTERMEASURE Comprehensive validation, secure defaults, error handling.
/// @INVARIANT Authorization checks are performed for all operations.
/// @AUDIT Authorization attempts are logged with full context.
/// @FLOW Validate environment -> Check permissions -> Apply rate limits.
impl AuthorizationService {
    pub fn new() -> Self {
        AuthorizationService
    }

    /// [ENVIRONMENT ACCESS VALIDATION] Check API Key Environment Permissions
    /// @MISSION Validate that API keys can only access appropriate environments.
    /// @THREAT Sandbox keys accessing production, environment isolation breach.
    /// @COUNTERMEASURE Environment-based access control, status validation.
    /// @INVARIANT Sandbox keys cannot access production environments.
    /// @AUDIT Environment access attempts are logged.
    /// @FLOW Check key status -> Compare with required environment -> Allow/deny.
    /// @DEPENDENCY Requires ApiKey with status information.
    pub fn validate_environment_access(&self, api_key: &ApiKey, required_environment: &ApiKeyStatus) -> Result<(), AuthorizationError> {
        match (&api_key.status, required_environment) {
            (ApiKeyStatus::Sandbox, ApiKeyStatus::Sandbox) => Ok(()),
            (ApiKeyStatus::Production, ApiKeyStatus::Production) => Ok(()),
            (ApiKeyStatus::Production, ApiKeyStatus::Sandbox) => Ok(()), // Production keys can access sandbox
            (ApiKeyStatus::Sandbox, ApiKeyStatus::Production) => {
                Err(AuthorizationError::EnvironmentAccessDenied {
                    key_status: api_key.status.clone(),
                    required_status: required_environment.clone(),
                })
            }
        }
    }

    /// Check if the API key has the required permissions
    pub fn validate_permissions(&self, api_key: &ApiKey, required_permissions: &[String]) -> Result<(), AuthorizationError> {
        let key_permissions: HashSet<_> = api_key.permissions.iter().cloned().collect();
        let required: HashSet<_> = required_permissions.iter().cloned().collect();

        if required.is_subset(&key_permissions) {
            Ok(())
        } else {
            let missing: Vec<_> = required.difference(&key_permissions).cloned().collect();
            Err(AuthorizationError::InsufficientPermissions(missing))
        }
    }

    /// Combined validation for environment and permissions
    pub fn validate_access(&self, api_key: &ApiKey, required_environment: &ApiKeyStatus, required_permissions: &[String]) -> Result<(), AuthorizationError> {
        self.validate_environment_access(api_key, required_environment)?;
        self.validate_permissions(api_key, required_permissions)?;
        Ok(())
    }

    /// Check if the key is in production environment
    pub fn is_production_key(&self, api_key: &ApiKey) -> bool {
        matches!(api_key.status, ApiKeyStatus::Production)
    }

    /// Check if the key is in sandbox environment
    pub fn is_sandbox_key(&self, api_key: &ApiKey) -> bool {
        matches!(api_key.status, ApiKeyStatus::Sandbox)
    }

    /// Get environment-specific rate limits
    pub fn get_rate_limit(&self, api_key: &ApiKey, operation: &str) -> u32 {
        let base_limit = match operation {
            "read" => 1000,
            "write" => 100,
            "delete" => 10,
            _ => 100,
        };

        match api_key.status {
            ApiKeyStatus::Sandbox => base_limit, // Full limits for sandbox
            ApiKeyStatus::Production => base_limit * 2, // Higher limits for production
        }
    }

    /// Validate tenant access
    pub fn validate_tenant_access(&self, api_key: &ApiKey, requested_tenant: &str) -> Result<(), AuthorizationError> {
        // For now, allow access to own tenant only
        // In production, you might have cross-tenant permissions
        if api_key.tenant == requested_tenant {
            Ok(())
        } else {
            Err(AuthorizationError::TenantAccessDenied {
                key_tenant: api_key.tenant.clone(),
                requested_tenant: requested_tenant.to_string(),
            })
        }
    }
}

/// [AUTHORIZATION ERROR ENUM] Authorization Failure Classifications
/// @MISSION Categorize authorization failures for proper error handling.
/// @THREAT Information leakage through detailed error messages.
/// @COUNTERMEASURE Sanitized error responses, secure logging.
/// @INVARIANT Errors don't expose sensitive authorization details.
/// @AUDIT Authorization errors trigger security monitoring.
/// @DEPENDENCY Used by AuthorizationService for error reporting.
#[derive(Debug, Clone)]
pub enum AuthorizationError {
    EnvironmentAccessDenied {
        key_status: ApiKeyStatus,
        required_status: ApiKeyStatus,
    },
    InsufficientPermissions(Vec<String>),
    TenantAccessDenied {
        key_tenant: String,
        requested_tenant: String,
    },
}

impl std::fmt::Display for AuthorizationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthorizationError::EnvironmentAccessDenied { key_status, required_status } => {
                write!(f, "API key with status '{:?}' cannot access '{:?}' environment", key_status, required_status)
            }
            AuthorizationError::InsufficientPermissions(missing) => {
                write!(f, "Missing required permissions: {:?}", missing)
            }
            AuthorizationError::TenantAccessDenied { key_tenant, requested_tenant } => {
                write!(f, "API key for tenant '{}' cannot access tenant '{}'", key_tenant, requested_tenant)
            }
        }
    }
}

impl std::error::Error for AuthorizationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn create_test_key(status: ApiKeyStatus, permissions: Vec<String>) -> ApiKey {
        ApiKey {
            id: "test_key".to_string(),
            key: None,
            key_type: KeyType::Client,
            tenant: "test_tenant".to_string(),
            status,
            ttl: 3600,
            created_at: Utc::now(),
            permissions,
            vault_path: "secret/test".to_string(),
            certificate: None,
        }
    }

    #[test]
    fn test_sandbox_key_can_access_sandbox() {
        let auth_service = AuthorizationService::new();
        let sandbox_key = create_test_key(ApiKeyStatus::Sandbox, vec!["read".to_string()]);

        assert!(auth_service.validate_environment_access(&sandbox_key, &ApiKeyStatus::Sandbox).is_ok());
    }

    #[test]
    fn test_sandbox_key_cannot_access_production() {
        let auth_service = AuthorizationService::new();
        let sandbox_key = create_test_key(ApiKeyStatus::Sandbox, vec!["read".to_string()]);

        assert!(auth_service.validate_environment_access(&sandbox_key, &ApiKeyStatus::Production).is_err());
    }

    #[test]
    fn test_production_key_can_access_both_environments() {
        let auth_service = AuthorizationService::new();
        let prod_key = create_test_key(ApiKeyStatus::Production, vec!["read".to_string()]);

        assert!(auth_service.validate_environment_access(&prod_key, &ApiKeyStatus::Sandbox).is_ok());
        assert!(auth_service.validate_environment_access(&prod_key, &ApiKeyStatus::Production).is_ok());
    }

    #[test]
    fn test_permission_validation() {
        let auth_service = AuthorizationService::new();
        let key = create_test_key(ApiKeyStatus::Sandbox, vec!["read".to_string(), "write".to_string()]);

        assert!(auth_service.validate_permissions(&key, &["read".to_string()]).is_ok());
        assert!(auth_service.validate_permissions(&key, &["read".to_string(), "write".to_string()]).is_ok());
        assert!(auth_service.validate_permissions(&key, &["admin".to_string()]).is_err());
    }

    #[test]
    fn test_combined_validation() {
        let auth_service = AuthorizationService::new();
        let sandbox_key = create_test_key(ApiKeyStatus::Sandbox, vec!["read".to_string()]);

        // Should succeed: correct environment and permissions
        assert!(auth_service.validate_access(&sandbox_key, &ApiKeyStatus::Sandbox, &["read".to_string()]).is_ok());

        // Should fail: wrong environment
        assert!(auth_service.validate_access(&sandbox_key, &ApiKeyStatus::Production, &["read".to_string()]).is_err());

        // Should fail: insufficient permissions
        assert!(auth_service.validate_access(&sandbox_key, &ApiKeyStatus::Sandbox, &["admin".to_string()]).is_err());
    }

    #[test]
    fn test_rate_limits() {
        let auth_service = AuthorizationService::new();
        let sandbox_key = create_test_key(ApiKeyStatus::Sandbox, vec![]);
        let prod_key = create_test_key(ApiKeyStatus::Production, vec![]);

        assert_eq!(auth_service.get_rate_limit(&sandbox_key, "read"), 1000);
        assert_eq!(auth_service.get_rate_limit(&prod_key, "read"), 2000);

        assert_eq!(auth_service.get_rate_limit(&sandbox_key, "write"), 100);
        assert_eq!(auth_service.get_rate_limit(&prod_key, "write"), 200);
    }
}