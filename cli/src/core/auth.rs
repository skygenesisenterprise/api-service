// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise CLI
//  Module: Authentication Core
// ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide core authentication functionality for CLI operations.
//  NOTICE: This module handles JWT token management, user sessions,
//  and authentication state for the CLI tool.
//  SECURITY: Secure token storage and validation
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use dirs;
use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSession {
    pub user_id: String,
    pub email: String,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>,
    pub issued_at: DateTime<Utc>,
    pub token_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthState {
    pub current_session: Option<UserSession>,
    pub last_login: Option<DateTime<Utc>>,
    pub login_attempts: u32,
    pub session_count: u32,
}

impl Default for AuthState {
    fn default() -> Self {
        Self {
            current_session: None,
            last_login: None,
            login_attempts: 0,
            session_count: 0,
        }
    }
}

impl AuthState {
    pub fn is_authenticated(&self) -> bool {
        if let Some(session) = &self.current_session {
            session.expires_at > Utc::now()
        } else {
            false
        }
    }

    pub fn has_permission(&self, permission: &str) -> bool {
        if let Some(session) = &self.current_session {
            session.permissions.contains(&permission.to_string()) ||
            session.roles.contains(&"admin".to_string())
        } else {
            false
        }
    }

    pub fn has_role(&self, role: &str) -> bool {
        if let Some(session) = &self.current_session {
            session.roles.contains(&role.to_string())
        } else {
            false
        }
    }

    pub fn get_current_user(&self) -> Option<&UserSession> {
        self.current_session.as_ref()
    }

    pub fn update_session(&mut self, session: UserSession) {
        self.current_session = Some(session);
        self.last_login = Some(Utc::now());
        self.session_count += 1;
    }

    pub fn clear_session(&mut self) {
        self.current_session = None;
    }

    pub fn increment_login_attempts(&mut self) {
        self.login_attempts += 1;
    }

    pub fn reset_login_attempts(&mut self) {
        self.login_attempts = 0;
    }
}

pub struct AuthManager {
    state: AuthState,
    store_path: PathBuf,
}

impl AuthManager {
    pub fn new() -> Result<Self> {
        let store_path = Self::get_store_path()?;
        let state = Self::load_state(&store_path).unwrap_or_default();

        Ok(Self { state, store_path })
    }

    fn get_store_path() -> Result<PathBuf> {
        let mut path = dirs::home_dir()
            .ok_or_else(|| anyhow!("Could not find home directory"))?;
        path.push(".sge");
        fs::create_dir_all(&path)?;
        path.push("auth_state.json");
        Ok(path)
    }

    fn load_state(path: &PathBuf) -> Result<AuthState> {
        if !path.exists() {
            return Ok(AuthState::default());
        }

        let content = fs::read_to_string(path)?;
        let state: AuthState = serde_json::from_str(&content)?;
        Ok(state)
    }

    fn save_state(&self) -> Result<()> {
        let content = serde_json::to_string_pretty(&self.state)?;
        fs::write(&self.store_path, content)?;
        Ok(())
    }

    pub fn get_state(&self) -> &AuthState {
        &self.state
    }

    pub fn get_state_mut(&mut self) -> &mut AuthState {
        &mut self.state
    }

    pub fn save(&self) -> Result<()> {
        self.save_state()
    }

    pub fn authenticate_session(&mut self, session: UserSession) -> Result<()> {
        self.state.update_session(session);
        self.state.reset_login_attempts();
        self.save()?;
        tracing::info!("User authenticated successfully");
        Ok(())
    }

    pub fn logout(&mut self) -> Result<()> {
        self.state.clear_session();
        self.save()?;
        tracing::info!("User logged out");
        Ok(())
    }

    pub fn validate_token(&self, token: &str) -> Result<bool> {
        if let Some(session) = &self.state.current_session {
            if session.access_token == token && session.expires_at > Utc::now() {
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }

    pub fn refresh_token(&mut self, new_session: UserSession) -> Result<()> {
        self.state.update_session(new_session);
        self.save()?;
        tracing::info!("Token refreshed successfully");
        Ok(())
    }

    pub fn check_rate_limit(&self) -> Result<()> {
        if self.state.login_attempts >= 5 {
            return Err(anyhow!("Too many login attempts. Please wait before retrying."));
        }
        Ok(())
    }

    pub fn record_failed_attempt(&mut self) -> Result<()> {
        self.state.increment_login_attempts();
        self.save()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginCredentials {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
    pub token_type: String,
    pub user: UserInfo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: String,
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub enabled: bool,
}

impl From<TokenResponse> for UserSession {
    fn from(token_resp: TokenResponse) -> Self {
        let issued_at = Utc::now();
        let expires_at = issued_at + chrono::Duration::seconds(token_resp.expires_in as i64);

        Self {
            user_id: token_resp.user.id,
            email: token_resp.user.email,
            roles: token_resp.user.roles,
            permissions: token_resp.user.permissions,
            access_token: token_resp.access_token,
            refresh_token: token_resp.refresh_token,
            expires_at,
            issued_at,
            token_type: token_resp.token_type,
        }
    }
}