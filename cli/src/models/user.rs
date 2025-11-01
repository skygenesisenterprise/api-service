// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise CLI
//  Module: User Models
// ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Define data models for user-related CLI operations.
//  NOTICE: This module contains structures for representing users, roles,
//  permissions, and authentication data in the CLI.
//  SECURITY: Sensitive user data properly handled and validated
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashSet;
use crate::models::{Validate, ValidationError, validate_email, validate_username};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub email: String,
    pub username: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub display_name: Option<String>,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub enabled: bool,
    pub email_verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub login_count: u32,
    pub mfa_enabled: bool,
    pub avatar_url: Option<String>,
    pub timezone: Option<String>,
    pub language: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub user: User,
    pub organizations: Vec<UserOrganization>,
    pub preferences: UserPreferences,
    pub security_settings: SecuritySettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserOrganization {
    pub organization_id: String,
    pub organization_name: String,
    pub role: String,
    pub joined_at: DateTime<Utc>,
    pub permissions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPreferences {
    pub theme: String,
    pub language: String,
    pub timezone: String,
    pub date_format: String,
    pub time_format: String,
    pub items_per_page: u32,
    pub email_notifications: bool,
    pub push_notifications: bool,
    pub weekly_report: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySettings {
    pub mfa_enabled: bool,
    pub mfa_method: Option<String>,
    pub password_last_changed: Option<DateTime<Utc>>,
    pub login_alerts: bool,
    pub session_timeout_minutes: u32,
    pub allowed_ips: Vec<String>,
    pub trusted_devices: Vec<TrustedDevice>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedDevice {
    pub id: String,
    pub name: String,
    pub device_type: String,
    pub browser: Option<String>,
    pub os: Option<String>,
    pub last_used: DateTime<Utc>,
    pub ip_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub username: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub password: String,
    pub roles: Vec<String>,
    pub send_invitation: bool,
    pub organization_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateUserRequest {
    pub email: Option<String>,
    pub username: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub roles: Option<Vec<String>>,
    pub enabled: Option<bool>,
    pub preferences: Option<UserPreferences>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
    pub confirm_password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSession {
    pub id: String,
    pub user_id: String,
    pub ip_address: String,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserActivity {
    pub id: String,
    pub user_id: String,
    pub action: String,
    pub resource: Option<String>,
    pub ip_address: String,
    pub user_agent: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInvitation {
    pub id: String,
    pub email: String,
    pub invited_by: String,
    pub organization_id: Option<String>,
    pub roles: Vec<String>,
    pub expires_at: DateTime<Utc>,
    pub accepted_at: Option<DateTime<Utc>>,
    pub status: InvitationStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InvitationStatus {
    Pending,
    Accepted,
    Expired,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSearchResult {
    pub users: Vec<User>,
    pub total: u64,
    pub query: String,
    pub filters: UserSearchFilters,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSearchFilters {
    pub email: Option<String>,
    pub username: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub roles: Option<Vec<String>>,
    pub enabled: Option<bool>,
    pub organization_id: Option<String>,
    pub created_after: Option<DateTime<Utc>>,
    pub created_before: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: String,
    pub name: String,
    pub description: String,
    pub permissions: Vec<String>,
    pub is_system_role: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    pub id: String,
    pub name: String,
    pub resource: String,
    pub action: String,
    pub description: String,
    pub is_system_permission: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserStats {
    pub total_users: u64,
    pub active_users: u64,
    pub inactive_users: u64,
    pub users_by_role: std::collections::HashMap<String, u64>,
    pub recent_registrations: u64,
    pub recent_logins: u64,
}

// Constructors and utility functions
impl User {
    pub fn new(email: String, first_name: Option<String>, last_name: Option<String>) -> Self {
        let now = Utc::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            email,
            username: None,
            first_name,
            last_name,
            display_name: None,
            roles: vec!["user".to_string()],
            permissions: Vec::new(),
            enabled: true,
            email_verified: false,
            created_at: now,
            updated_at: now,
            last_login: None,
            login_count: 0,
            mfa_enabled: false,
            avatar_url: None,
            timezone: Some("UTC".to_string()),
            language: Some("en".to_string()),
        }
    }

    pub fn full_name(&self) -> String {
        match (&self.first_name, &self.last_name) {
            (Some(first), Some(last)) => format!("{} {}", first, last),
            (Some(first), None) => first.clone(),
            (None, Some(last)) => last.clone(),
            (None, None) => self.email.clone(),
        }
    }

    pub fn has_role(&self, role: &str) -> bool {
        self.roles.contains(&role.to_string())
    }

    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.contains(&permission.to_string()) ||
        self.roles.contains(&"admin".to_string())
    }

    pub fn is_admin(&self) -> bool {
        self.has_role("admin")
    }

    pub fn record_login(&mut self) {
        self.last_login = Some(Utc::now());
        self.login_count += 1;
        self.updated_at = Utc::now();
    }
}

impl Default for UserPreferences {
    fn default() -> Self {
        Self {
            theme: "light".to_string(),
            language: "en".to_string(),
            timezone: "UTC".to_string(),
            date_format: "YYYY-MM-DD".to_string(),
            time_format: "HH:mm:ss".to_string(),
            items_per_page: 25,
            email_notifications: true,
            push_notifications: true,
            weekly_report: true,
        }
    }
}

impl Default for SecuritySettings {
    fn default() -> Self {
        Self {
            mfa_enabled: false,
            mfa_method: None,
            password_last_changed: None,
            login_alerts: true,
            session_timeout_minutes: 480, // 8 hours
            allowed_ips: Vec::new(),
            trusted_devices: Vec::new(),
        }
    }
}

impl CreateUserRequest {
    pub fn new(email: String, password: String) -> Self {
        Self {
            email,
            username: None,
            first_name: None,
            last_name: None,
            password,
            roles: vec!["user".to_string()],
            send_invitation: true,
            organization_id: None,
        }
    }
}

impl InvitationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            InvitationStatus::Pending => "pending",
            InvitationStatus::Accepted => "accepted",
            InvitationStatus::Expired => "expired",
            InvitationStatus::Cancelled => "cancelled",
        }
    }
}

// Validation implementations
impl Validate for User {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_email(&self.email)?;

        if let Some(username) = &self.username {
            validate_username(username)?;
        }

        if let Some(first_name) = &self.first_name {
            if first_name.is_empty() {
                return Err(ValidationError::RequiredField {
                    field: "first_name".to_string(),
                });
            }
        }

        if let Some(last_name) = &self.last_name {
            if last_name.is_empty() {
                return Err(ValidationError::RequiredField {
                    field: "last_name".to_string(),
                });
            }
        }

        Ok(())
    }
}

impl Validate for CreateUserRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_email(&self.email)?;

        if let Some(username) = &self.username {
            validate_username(username)?;
        }

        if self.password.is_empty() {
            return Err(ValidationError::RequiredField {
                field: "password".to_string(),
            });
        }

        if self.password.len() < 8 {
            return Err(ValidationError::TooShort {
                field: "password".to_string(),
                min_len: 8,
            });
        }

        Ok(())
    }
}

impl Validate for UpdateUserRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        if let Some(ref email) = self.email {
            validate_email(email)?;
        }

        if let Some(ref username) = self.username {
            validate_username(username)?;
        }

        Ok(())
    }
}

impl Validate for ChangePasswordRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.new_password != self.confirm_password {
            return Err(ValidationError::Custom {
                message: "Passwords do not match".to_string(),
            });
        }

        if self.new_password.len() < 8 {
            return Err(ValidationError::TooShort {
                field: "new_password".to_string(),
                min_len: 8,
            });
        }

        Ok(())
    }
}

// Utility functions
pub fn generate_username_from_email(email: &str) -> String {
    email.split('@').next().unwrap_or("user").to_string()
}

pub fn is_valid_role(role: &str) -> bool {
    let valid_roles = ["admin", "user", "manager", "operator", "viewer"];
    valid_roles.contains(&role)
}

pub fn get_role_permissions(role: &str) -> Vec<String> {
    match role {
        "admin" => vec![
            "user.*".to_string(),
            "org.*".to_string(),
            "security.*".to_string(),
            "system.*".to_string(),
        ],
        "manager" => vec![
            "user.read".to_string(),
            "user.write".to_string(),
            "org.read".to_string(),
            "system.read".to_string(),
        ],
        "operator" => vec![
            "system.read".to_string(),
            "network.read".to_string(),
            "vpn.write".to_string(),
        ],
        "viewer" => vec![
            "system.read".to_string(),
            "network.read".to_string(),
            "org.read".to_string(),
        ],
        _ => vec!["user.read".to_string()],
    }
}