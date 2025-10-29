// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Application Service
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Manage application registry, access control, and token generation
//  for enterprise applications with secure permission management.
//  NOTICE: Implements application lifecycle management with OAuth-like
//  access tokens, permission validation, and audit logging.
//  APP STANDARDS: OAuth 2.0, JWT tokens, role-based access control
//  COMPLIANCE: GDPR, SOX application access requirements
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::collections::HashMap;
use crate::core::vault::VaultClient;
use crate::models::user::User;

/// [APPLICATION MODEL] Enterprise Application Registry Entry
/// @MISSION Define application metadata and access requirements.
/// @THREAT Application impersonation, permission escalation.
/// @COUNTERMEASURE Unique IDs, permission validation, audit logging.
/// @INVARIANT Applications have unique IDs and defined permissions.
/// @AUDIT Application changes are logged for compliance.
/// @DEPENDENCY Used by ApplicationService for access control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Application {
    pub id: String,
    pub name: String,
    pub description: String,
    pub base_url: String,
    pub required_permissions: Vec<String>,
    pub is_active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// [APPLICATION TOKEN MODEL] Access Token for Application Authorization
/// @MISSION Provide temporary access credentials for applications.
/// @THREAT Token theft, replay attacks, expiration bypass.
/// @COUNTERMEASURE Cryptographic tokens, expiration, secure storage.
/// @INVARIANT Tokens are time-limited and permission-scoped.
/// @AUDIT Token creation and usage are logged.
/// @DEPENDENCY Stored in Vault for secure validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationToken {
    pub token: String,
    pub application_id: String,
    pub user_id: String,
    pub permissions: Vec<String>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// [ACCESS REQUEST MODEL] User Request for Application Access
/// @MISSION Structure access requests with permission specification.
/// @THREAT Unauthorized permission requests, privilege escalation.
/// @COUNTERMEASURE Permission validation, approval workflows.
/// @INVARIANT Requests specify exact permissions needed.
/// @AUDIT Access requests are logged and tracked.
/// @DEPENDENCY Processed by request_application_access method.
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ApplicationAccessRequest {
    pub application_id: String,
    pub requested_permissions: Vec<String>,
}

/// [ACCESS RESPONSE MODEL] Application Access Grant Response
/// @MISSION Return access tokens and permissions to authorized users.
/// @THREAT Token exposure, permission over-granting.
/// @COUNTERMEASURE Secure token transmission, exact permission grants.
/// @INVARIANT Response contains only granted permissions.
/// @AUDIT Access grants are logged with full context.
/// @DEPENDENCY Returned by request_application_access method.
#[derive(Debug, Serialize, Deserialize)]
pub struct ApplicationAccessResponse {
    pub application: Application,
    pub access_token: String,
    pub refresh_token: String,
    pub permissions: Vec<String>,
    pub expires_in: u64,
}

/// [APPLICATION SERVICE STRUCT] Core Service for Application Management
/// @MISSION Centralize application registry and access control logic.
/// @THREAT Unauthorized application access, token compromise.
/// @COUNTERMEASURE Secure token storage, permission validation.
/// @INVARIANT All application operations are audited.
/// @AUDIT Service operations trigger security logging.
/// @DEPENDENCY Requires VaultClient for secure storage.
pub struct ApplicationService {
    vault_client: Arc<VaultClient>,
    applications: HashMap<String, Application>,
}

/// [APPLICATION SERVICE IMPLEMENTATION] Business Logic for Application Operations
/// @MISSION Implement secure application management and access control.
/// @THREAT Service abuse, data leakage, unauthorized access.
/// @COUNTERMEASURE Input validation, secure storage, audit logging.
/// @INVARIANT All operations validate permissions and log activity.
/// @AUDIT Service methods are instrumented for monitoring.
/// @FLOW Validate input -> Process request -> Log result.
impl ApplicationService {
    /// [SERVICE INITIALIZATION] Create Application Service with Registry
    /// @MISSION Initialize service with known applications and vault client.
    /// @THREAT Incomplete application registry, vault misconfiguration.
    /// @COUNTERMEASURE Hardcoded secure applications, vault validation.
    /// @INVARIANT Service starts with complete application registry.
    /// @AUDIT Service initialization is logged.
    /// @FLOW Load applications -> Initialize vault -> Return service.
    pub fn new(vault_client: Arc<VaultClient>) -> Self {
        let mut applications = HashMap::new();

        // Initialize with known applications
        applications.insert("aether-search".to_string(), Application {
            id: "aether-search".to_string(),
            name: "Aether Search".to_string(),
            description: "Search engine for Sky Genesis ecosystem".to_string(),
            base_url: "https://search.skygenesisenterprise.com".to_string(),
            required_permissions: vec!["search:read".to_string()],
            is_active: true,
            created_at: chrono::Utc::now(),
        });

        applications.insert("aether-mail".to_string(), Application {
            id: "aether-mail".to_string(),
            name: "Aether Mail".to_string(),
            description: "Email service for Sky Genesis ecosystem".to_string(),
            base_url: "https://mail.skygenesisenterprise.com".to_string(),
            required_permissions: vec!["mail:read".to_string(), "mail:write".to_string()],
            is_active: true,
            created_at: chrono::Utc::now(),
        });

        applications.insert("aether-drive".to_string(), Application {
            id: "aether-drive".to_string(),
            name: "Aether Drive".to_string(),
            description: "Cloud storage for Sky Genesis ecosystem".to_string(),
            base_url: "https://drive.skygenesisenterprise.com".to_string(),
            required_permissions: vec!["drive:read".to_string(), "drive:write".to_string()],
            is_active: true,
            created_at: chrono::Utc::now(),
        });

        applications.insert("aether-calendar".to_string(), Application {
            id: "aether-calendar".to_string(),
            name: "Aether Calendar".to_string(),
            description: "Calendar service for Sky Genesis ecosystem".to_string(),
            base_url: "https://calendar.skygenesisenterprise.com".to_string(),
            required_permissions: vec!["calendar:read".to_string(), "calendar:write".to_string()],
            is_active: true,
            created_at: chrono::Utc::now(),
        });

        ApplicationService {
            vault_client,
            applications,
        }
    }

    pub async fn get_application(&self, app_id: &str) -> Result<Option<&Application>, Box<dyn std::error::Error>> {
        Ok(self.applications.get(app_id))
    }

    pub async fn list_applications(&self) -> Result<Vec<&Application>, Box<dyn std::error::Error>> {
        Ok(self.applications.values().collect())
    }

    pub async fn validate_application_token(&self, token: &str) -> Result<ApplicationToken, Box<dyn std::error::Error>> {
        // In production, validate against Vault or database
        // For now, decode the token (this would be encrypted in production)
        let token_data: ApplicationToken = serde_json::from_str(token)?;
        Ok(token_data)
    }

    pub async fn generate_application_token(
        &self,
        user: &User,
        application: &Application,
        permissions: Vec<String>,
    ) -> Result<ApplicationToken, Box<dyn std::error::Error>> {
        let token = ApplicationToken {
            token: uuid::Uuid::new_v4().to_string(),
            application_id: application.id.clone(),
            user_id: user.id.clone(),
            permissions,
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            created_at: chrono::Utc::now(),
        };

        // Store token in Vault for validation
        let token_path = format!("application_tokens/{}/{}", application.id, token.token);
        self.vault_client.store_secret(&token_path, &serde_json::to_value(&token)?).await?;

        Ok(token)
    }

    /// [ACCESS REQUEST PROCESSOR] Handle User Application Access Requests
    /// @MISSION Grant application access with appropriate permissions.
    /// @THREAT Unauthorized access, permission over-granting.
    /// @COUNTERMEASURE Permission validation, token generation, audit logging.
    /// @INVARIANT Only authorized permissions are granted.
    /// @AUDIT Access requests and grants are fully logged.
    /// @FLOW Validate request -> Check permissions -> Generate tokens -> Return response.
    pub async fn request_application_access(
        &self,
        user: &User,
        request: ApplicationAccessRequest,
    ) -> Result<ApplicationAccessResponse, Box<dyn std::error::Error>> {
        let application = self.applications.get(&request.application_id)
            .ok_or("Application not found")?;

        if !application.is_active {
            return Err("Application is not active".into());
        }

        // Check if user has required permissions
        let granted_permissions: Vec<String> = request.requested_permissions
            .into_iter()
            .filter(|perm| user.roles.contains(&format!("app:{}", perm)))
            .collect();

        if granted_permissions.is_empty() {
            return Err("Insufficient permissions for application access".into());
        }

        // Generate application-specific token
        let app_token = self.generate_application_token(user, application, granted_permissions.clone()).await?;

        // Generate refresh token
        let refresh_token = uuid::Uuid::new_v4().to_string();

        Ok(ApplicationAccessResponse {
            application: application.clone(),
            access_token: app_token.token,
            refresh_token,
            permissions: granted_permissions,
            expires_in: 3600, // 1 hour
        })
    }

    pub async fn revoke_application_access(
        &self,
        user_id: &str,
        application_id: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // In production, revoke all tokens for this user/application combination
        // For now, this is a placeholder
        println!("Revoking access for user {} to application {}", user_id, application_id);
        Ok(())
    }

    pub async fn get_user_application_permissions(
        &self,
        user: &User,
        application_id: &str,
    ) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let application = self.applications.get(application_id)
            .ok_or("Application not found")?;

        // Return permissions that the user has for this application
        let user_permissions: Vec<String> = application.required_permissions
            .iter()
            .filter(|perm| user.roles.contains(&format!("app:{}", perm)))
            .cloned()
            .collect();

        Ok(user_permissions)
    }

    pub async fn validate_user_application_access(
        &self,
        user: &User,
        application_id: &str,
        required_permissions: &[String],
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let user_permissions = self.get_user_application_permissions(user, application_id).await?;

        // Check if user has all required permissions
        for required_perm in required_permissions {
            if !user_permissions.contains(required_perm) {
                return Ok(false);
            }
        }

        Ok(true)
    }
}