use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::collections::HashMap;
use crate::core::vault::VaultClient;
use crate::models::user::User;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationToken {
    pub token: String,
    pub application_id: String,
    pub user_id: String,
    pub permissions: Vec<String>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApplicationAccessRequest {
    pub application_id: String,
    pub requested_permissions: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApplicationAccessResponse {
    pub application: Application,
    pub access_token: String,
    pub refresh_token: String,
    pub permissions: Vec<String>,
    pub expires_in: u64,
}

pub struct ApplicationService {
    vault_client: Arc<VaultClient>,
    applications: HashMap<String, Application>,
}

impl ApplicationService {
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