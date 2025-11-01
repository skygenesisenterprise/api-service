// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise CLI
//  Module: Models
// ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Define data models and structures for CLI operations.
//  NOTICE: This module contains all the data structures used throughout
//  the CLI for representing API responses, configurations, and internal state.
//  SECURITY: Sensitive data properly typed and validated
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

pub mod network;
pub mod response;
pub mod user;
pub mod vpn;

// Re-export commonly used types
pub use network::*;
pub use response::*;
pub use user::*;
pub use vpn::*;

// Common types used across models
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<ApiError>,
    pub timestamp: DateTime<Utc>,
    pub request_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
    pub details: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationInfo {
    pub page: u32,
    pub per_page: u32,
    pub total: u64,
    pub total_pages: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListResponse<T> {
    pub items: Vec<T>,
    pub pagination: PaginationInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub command: String,
    pub success: bool,
    pub output: Option<String>,
    pub error: Option<String>,
    pub execution_time_ms: u64,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliConfig {
    pub api_host: String,
    pub api_port: u16,
    pub ssh_host: String,
    pub ssh_port: u16,
    pub ssh_username: String,
    pub timeout_seconds: u64,
    pub log_level: String,
    pub output_format: OutputFormat,
    pub enable_telemetry: bool,
    pub enable_rate_limiting: bool,
    pub enable_vpn_enforcement: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputFormat {
    Table,
    Json,
    Yaml,
    Compact,
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            api_host: "localhost".to_string(),
            api_port: 8080,
            ssh_host: "localhost".to_string(),
            ssh_port: 22,
            ssh_username: "admin".to_string(),
            timeout_seconds: 30,
            log_level: "info".to_string(),
            output_format: OutputFormat::Table,
            enable_telemetry: true,
            enable_rate_limiting: true,
            enable_vpn_enforcement: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandContext {
    pub command: String,
    pub args: Vec<String>,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub start_time: DateTime<Utc>,
    pub environment: HashMap<String, String>,
}

impl CommandContext {
    pub fn new(command: String, args: Vec<String>) -> Self {
        Self {
            command,
            args,
            user_id: None,
            session_id: None,
            start_time: Utc::now(),
            environment: std::env::vars().collect(),
        }
    }

    pub fn with_user(mut self, user_id: String) -> Self {
        self.user_id = Some(user_id);
        self
    }

    pub fn with_session(mut self, session_id: String) -> Self {
        self.session_id = Some(session_id);
        self
    }
}

// Validation traits
pub trait Validate {
    fn validate(&self) -> Result<(), ValidationError>;
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ValidationError {
    #[error("Field '{field}' is required")]
    RequiredField { field: String },
    #[error("Field '{field}' has invalid format: {message}")]
    InvalidFormat { field: String, message: String },
    #[error("Field '{field}' is too long (max {max_len})")]
    TooLong { field: String, max_len: usize },
    #[error("Field '{field}' is too short (min {min_len})")]
    TooShort { field: String, min_len: usize },
    #[error("Field '{field}' contains invalid characters")]
    InvalidCharacters { field: String },
    #[error("Custom validation error: {message}")]
    Custom { message: String },
}

// Common validation implementations
impl Validate for String {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.is_empty() {
            return Err(ValidationError::RequiredField {
                field: "string".to_string(),
            });
        }
        Ok(())
    }
}

// Utility functions
pub fn validate_email(email: &str) -> Result<(), ValidationError> {
    if email.is_empty() {
        return Err(ValidationError::RequiredField {
            field: "email".to_string(),
        });
    }

    if !email.contains('@') || !email.contains('.') {
        return Err(ValidationError::InvalidFormat {
            field: "email".to_string(),
            message: "Invalid email format".to_string(),
        });
    }

    Ok(())
}

pub fn validate_password(password: &str) -> Result<(), ValidationError> {
    if password.len() < 8 {
        return Err(ValidationError::TooShort {
            field: "password".to_string(),
            min_len: 8,
        });
    }

    if password.len() > 128 {
        return Err(ValidationError::TooLong {
            field: "password".to_string(),
            max_len: 128,
        });
    }

    Ok(())
}

pub fn validate_username(username: &str) -> Result<(), ValidationError> {
    if username.is_empty() {
        return Err(ValidationError::RequiredField {
            field: "username".to_string(),
        });
    }

    if username.len() < 3 {
        return Err(ValidationError::TooShort {
            field: "username".to_string(),
            min_len: 3,
        });
    }

    if username.len() > 50 {
        return Err(ValidationError::TooLong {
            field: "username".to_string(),
            max_len: 50,
        });
    }

    // Check for valid characters (alphanumeric, underscore, dash)
    if !username.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
        return Err(ValidationError::InvalidCharacters {
            field: "username".to_string(),
        });
    }

    Ok(())
}