// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise CLI
//  Module: Authentication Service
// ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide authentication business logic for CLI operations.
//  NOTICE: This module encapsulates authentication operations using the API client.
//  SECURITY: Secure authentication handling and token management
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use crate::core::api_client::SshApiClient;
use crate::queries::user_query::UserQuery;
use anyhow::Result;
use serde_json::Value;

/// Authentication service for CLI operations
#[allow(dead_code)]
pub struct AuthService<'a> {
    client: &'a SshApiClient,
}

#[allow(dead_code)]
impl<'a> AuthService<'a> {
    /// Create new authentication service
    pub fn new(client: &'a SshApiClient) -> Self {
        Self { client }
    }

    /// Authenticate user with username and password
    pub async fn authenticate(&self, username: &str, password: &str) -> Result<Value> {
        let params = UserQuery::authenticate(username, password);
        let result = self.client.call_method("auth.authenticate", params)?;
        Ok(result)
    }

    /// Validate authentication token
    pub async fn validate_token(&self, token: &str) -> Result<Value> {
        let params = serde_json::json!({
            "token": token
        });
        let result = self.client.call_method("auth.validate_token", params)?;
        Ok(result)
    }

    /// Refresh authentication token
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<Value> {
        let params = serde_json::json!({
            "refresh_token": refresh_token
        });
        let result = self.client.call_method("auth.refresh_token", params)?;
        Ok(result)
    }

    /// Logout user
    pub async fn logout(&self, token: &str) -> Result<Value> {
        let params = serde_json::json!({
            "token": token
        });
        let result = self.client.call_method("auth.logout", params)?;
        Ok(result)
    }

    /// Get current user information
    pub async fn get_current_user(&self, token: &str) -> Result<Value> {
        let params = serde_json::json!({
            "token": token
        });
        let result = self.client.call_method("auth.current_user", params)?;
        Ok(result)
    }

    /// Change user password
    pub async fn change_password(&self, username: &str, old_password: &str, new_password: &str) -> Result<Value> {
        let params = UserQuery::change_password(username, old_password, new_password);
        let result = self.client.call_method("auth.change_password", params)?;
        Ok(result)
    }
}