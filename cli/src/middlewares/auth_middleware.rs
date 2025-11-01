// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise CLI
//  Module: Authentication Middleware
// ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide authentication middleware for CLI command execution.
//  NOTICE: This module validates user authentication and permissions
//  before allowing command execution in the CLI tool.
//  SECURITY: Multi-factor authentication support and session validation
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use crate::core::{AppState, auth::AuthManager};
use anyhow::{Result, anyhow};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct AuthMiddleware {
    auth_manager: AuthManager,
    command_permissions: HashMap<String, Vec<String>>,
}

impl AuthMiddleware {
    pub fn new() -> Result<Self> {
        let auth_manager = AuthManager::new()?;
        let command_permissions = Self::load_command_permissions();

        Ok(Self {
            auth_manager,
            command_permissions,
        })
    }

    fn load_command_permissions() -> HashMap<String, Vec<String>> {
        let mut permissions = HashMap::new();

        // Define permissions required for each command
        permissions.insert("user.list".to_string(), vec!["user.read".to_string()]);
        permissions.insert("user.create".to_string(), vec!["user.write".to_string()]);
        permissions.insert("user.update".to_string(), vec!["user.write".to_string()]);
        permissions.insert("user.delete".to_string(), vec!["user.delete".to_string()]);

        permissions.insert("keys.list".to_string(), vec!["key.read".to_string()]);
        permissions.insert("keys.create".to_string(), vec!["key.write".to_string()]);
        permissions.insert("keys.revoke".to_string(), vec!["key.delete".to_string()]);

        permissions.insert("security.encrypt".to_string(), vec!["crypto.encrypt".to_string()]);
        permissions.insert("security.decrypt".to_string(), vec!["crypto.decrypt".to_string()]);
        permissions.insert("security.sign".to_string(), vec!["crypto.sign".to_string()]);
        permissions.insert("security.verify".to_string(), vec!["crypto.verify".to_string()]);

        permissions.insert("org.list".to_string(), vec!["org.read".to_string()]);
        permissions.insert("org.create".to_string(), vec!["org.write".to_string()]);
        permissions.insert("org.update".to_string(), vec!["org.write".to_string()]);
        permissions.insert("org.delete".to_string(), vec!["org.delete".to_string()]);

        permissions.insert("network.status".to_string(), vec!["network.read".to_string()]);
        permissions.insert("network.interfaces".to_string(), vec!["network.read".to_string()]);
        permissions.insert("network.routes".to_string(), vec!["network.read".to_string()]);

        permissions.insert("vpn.status".to_string(), vec!["vpn.read".to_string()]);
        permissions.insert("vpn.connect".to_string(), vec!["vpn.write".to_string()]);

        permissions.insert("telemetry.status".to_string(), vec!["telemetry.read".to_string()]);
        permissions.insert("telemetry.metrics".to_string(), vec!["telemetry.read".to_string()]);
        permissions.insert("telemetry.logs".to_string(), vec!["logs.read".to_string()]);

        permissions
    }

    pub async fn authenticate(&self) -> Result<()> {
        if !self.auth_manager.get_state().is_authenticated() {
            return Err(anyhow!("Authentication required. Please login first using 'sge auth login'"));
        }

        // Check if token is expired
        if let Some(session) = self.auth_manager.get_state().get_current_user() {
            if session.expires_at <= chrono::Utc::now() {
                return Err(anyhow!("Authentication token expired. Please login again."));
            }
        }

        tracing::debug!("User authentication validated");
        Ok(())
    }

    pub async fn authorize(&self, command: &str, args: &[String]) -> Result<()> {
        // Always allow auth commands
        if command.starts_with("auth.") {
            return Ok(());
        }

        // Check if user is authenticated first
        self.authenticate().await?;

        // Get required permissions for this command
        let required_permissions = self.command_permissions.get(command);

        if let Some(permissions) = required_permissions {
            let auth_state = self.auth_manager.get_state();

            // Check if user has admin role (bypass all permissions)
            if auth_state.has_role("admin") {
                tracing::debug!("Admin user authorized for command: {}", command);
                return Ok(());
            }

            // Check if user has any of the required permissions
            for permission in permissions {
                if auth_state.has_permission(permission) {
                    tracing::debug!("User authorized for command: {} with permission: {}", command, permission);
                    return Ok(());
                }
            }

            return Err(anyhow!(
                "Insufficient permissions for command '{}'. Required: {:?}",
                command, permissions
            ));
        }

        // If no specific permissions defined, allow execution (for development/testing)
        tracing::warn!("No permissions defined for command: {}, allowing execution", command);
        Ok(())
    }

    pub async fn validate_session(&self) -> Result<()> {
        let auth_state = self.auth_manager.get_state();

        if !auth_state.is_authenticated() {
            return Err(anyhow!("No active session. Please login first."));
        }

        // Additional session validation can be added here
        // e.g., check session age, IP address changes, etc.

        Ok(())
    }

    pub async fn refresh_token_if_needed(&mut self) -> Result<()> {
        let auth_state = self.auth_manager.get_state();

        if let Some(session) = auth_state.get_current_user() {
            let time_until_expiry = session.expires_at.signed_duration_since(chrono::Utc::now());
            let five_minutes = chrono::Duration::minutes(5);

            // Refresh token if it expires within 5 minutes
            if time_until_expiry <= five_minutes {
                tracing::info!("Token expires soon, attempting refresh");

                // In a real implementation, you would call the refresh endpoint
                // For now, we'll just log that refresh would be needed
                tracing::warn!("Token refresh needed but not implemented yet");
            }
        }

        Ok(())
    }

    pub fn get_current_user(&self) -> Option<&crate::core::auth::UserSession> {
        self.auth_manager.get_state().get_current_user()
    }

    pub fn has_role(&self, role: &str) -> bool {
        self.auth_manager.get_state().has_role(role)
    }

    pub fn has_permission(&self, permission: &str) -> bool {
        self.auth_manager.get_state().has_permission(permission)
    }

    pub async fn logout(&mut self) -> Result<()> {
        self.auth_manager.logout()?;
        Ok(())
    }

    pub async fn record_login_attempt(&mut self, success: bool) -> Result<()> {
        if !success {
            self.auth_manager.record_failed_attempt()?;
        } else {
            self.auth_manager.get_state_mut().reset_login_attempts();
            self.auth_manager.save()?;
        }
        Ok(())
    }

    pub async fn check_rate_limit(&self) -> Result<()> {
        self.auth_manager.check_rate_limit()
    }
}

// Convenience functions for use in command handlers
pub async fn require_auth(state: &AppState) -> Result<()> {
    let middleware = AuthMiddleware::new()?;
    middleware.authenticate().await
}

pub async fn require_permission(state: &AppState, permission: &str) -> Result<()> {
    let middleware = AuthMiddleware::new()?;
    middleware.authenticate().await?;

    if !middleware.has_permission(permission) && !middleware.has_role("admin") {
        return Err(anyhow!("Permission '{}' required", permission));
    }

    Ok(())
}

pub async fn require_role(state: &AppState, role: &str) -> Result<()> {
    let middleware = AuthMiddleware::new()?;
    middleware.authenticate().await?;

    if !middleware.has_role(role) {
        return Err(anyhow!("Role '{}' required", role));
    }

    Ok(())
}

pub async fn authorize_command(command: &str, args: &[String]) -> Result<()> {
    let middleware = AuthMiddleware::new()?;
    middleware.authorize(command, args).await
}