// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise CLI
//  Module: Response Models
// ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Define response models for CLI API interactions.
//  NOTICE: This module contains structures for representing API responses,
//  error handling, and standardized response formats across the CLI.
//  SECURITY: Response data properly validated and sanitized
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use crate::models::{Validate, ValidationError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<CliError>,
    pub metadata: ResponseMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseMetadata {
    pub timestamp: DateTime<Utc>,
    pub request_id: String,
    pub version: String,
    pub execution_time_ms: u64,
    pub user_id: Option<String>,
    pub command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliError {
    pub code: String,
    pub message: String,
    pub details: Option<HashMap<String, serde_json::Value>>,
    pub help_url: Option<String>,
    pub retryable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<ApiError>,
    pub pagination: Option<PaginationMeta>,
    pub rate_limit: Option<RateLimitInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
    pub field: Option<String>,
    pub details: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationMeta {
    pub page: u32,
    pub per_page: u32,
    pub total: u64,
    pub total_pages: u32,
    pub has_next: bool,
    pub has_prev: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitInfo {
    pub limit: u32,
    pub remaining: u32,
    pub reset_time: DateTime<Utc>,
    pub retry_after_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandExecutionResult {
    pub command: String,
    pub args: Vec<String>,
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub execution_time_ms: u64,
    pub timestamp: DateTime<Utc>,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchResult<T> {
    pub results: Vec<CliResponse<T>>,
    pub summary: BatchSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchSummary {
    pub total: usize,
    pub successful: usize,
    pub failed: usize,
    pub execution_time_ms: u64,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResponse {
    pub status: HealthStatus,
    pub version: String,
    pub uptime_seconds: u64,
    pub timestamp: DateTime<Utc>,
    pub services: HashMap<String, ServiceHealth>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceHealth {
    pub status: HealthStatus,
    pub response_time_ms: Option<u64>,
    pub last_check: DateTime<Utc>,
    pub message: Option<String>,
    pub details: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsResponse {
    pub system: SystemMetrics,
    pub application: ApplicationMetrics,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub cpu_usage_percent: f64,
    pub memory_usage_mb: f64,
    pub memory_total_mb: f64,
    pub disk_usage_gb: f64,
    pub disk_total_gb: f64,
    pub network_rx_mbps: f64,
    pub network_tx_mbps: f64,
    pub load_average: Vec<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationMetrics {
    pub active_connections: u32,
    pub total_requests: u64,
    pub requests_per_second: f64,
    pub average_response_time_ms: f64,
    pub error_rate_percent: f64,
    pub memory_usage_mb: f64,
    pub goroutines: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub level: LogLevel,
    pub message: String,
    pub source: String,
    pub fields: Option<HashMap<String, serde_json::Value>>,
    pub user_id: Option<String>,
    pub request_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigValidationResponse {
    pub valid: bool,
    pub errors: Vec<ConfigError>,
    pub suggestions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigError {
    pub field: String,
    pub error: String,
    pub suggestion: Option<String>,
}

// Constructors and utility functions
impl<T> CliResponse<T> {
    pub fn success(data: T, command: String, execution_time_ms: u64) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            metadata: ResponseMetadata {
                timestamp: Utc::now(),
                request_id: uuid::Uuid::new_v4().to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                execution_time_ms,
                user_id: None,
                command,
            },
        }
    }

    pub fn error(error: CliError, command: String, execution_time_ms: u64) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error),
            metadata: ResponseMetadata {
                timestamp: Utc::now(),
                request_id: uuid::Uuid::new_v4().to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                execution_time_ms,
                user_id: None,
                command,
            },
        }
    }

    pub fn with_user_id(mut self, user_id: String) -> Self {
        self.metadata.user_id = Some(user_id);
        self
    }
}

impl CliError {
    pub fn new(code: String, message: String) -> Self {
        Self {
            code,
            message,
            details: None,
            help_url: None,
            retryable: false,
        }
    }

    pub fn with_details(mut self, details: HashMap<String, serde_json::Value>) -> Self {
        self.details = Some(details);
        self
    }

    pub fn with_help_url(mut self, help_url: String) -> Self {
        self.help_url = Some(help_url);
        self
    }

    pub fn retryable(mut self, retryable: bool) -> Self {
        self.retryable = retryable;
        self
    }
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            pagination: None,
            rate_limit: None,
        }
    }

    pub fn error(error: ApiError) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error),
            pagination: None,
            rate_limit: None,
        }
    }

    pub fn with_pagination(mut self, pagination: PaginationMeta) -> Self {
        self.pagination = Some(pagination);
        self
    }

    pub fn with_rate_limit(mut self, rate_limit: RateLimitInfo) -> Self {
        self.rate_limit = Some(rate_limit);
        self
    }
}

impl ApiError {
    pub fn new(code: String, message: String) -> Self {
        Self {
            code,
            message,
            field: None,
            details: None,
        }
    }

    pub fn with_field(mut self, field: String) -> Self {
        self.field = Some(field);
        self
    }

    pub fn with_details(mut self, details: HashMap<String, serde_json::Value>) -> Self {
        self.details = Some(details);
        self
    }
}

impl PaginationMeta {
    pub fn new(page: u32, per_page: u32, total: u64) -> Self {
        let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;
        Self {
            page,
            per_page,
            total,
            total_pages,
            has_next: page < total_pages,
            has_prev: page > 1,
        }
    }
}

impl RateLimitInfo {
    pub fn new(limit: u32, remaining: u32, reset_time: DateTime<Utc>) -> Self {
        let retry_after_seconds = if remaining == 0 {
            Some((reset_time - Utc::now()).num_seconds() as u64)
        } else {
            None
        };

        Self {
            limit,
            remaining,
            reset_time,
            retry_after_seconds,
        }
    }
}

impl HealthStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            HealthStatus::Healthy => "healthy",
            HealthStatus::Degraded => "degraded",
            HealthStatus::Unhealthy => "unhealthy",
        }
    }
}

impl From<String> for LogLevel {
    fn from(s: String) -> Self {
        match s.to_lowercase().as_str() {
            "trace" => LogLevel::Trace,
            "debug" => LogLevel::Debug,
            "info" => LogLevel::Info,
            "warn" | "warning" => LogLevel::Warn,
            "error" => LogLevel::Error,
            _ => LogLevel::Info,
        }
    }
}

// Validation implementations
impl Validate for CliError {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.code.is_empty() {
            return Err(ValidationError::RequiredField {
                field: "code".to_string(),
            });
        }

        if self.message.is_empty() {
            return Err(ValidationError::RequiredField {
                field: "message".to_string(),
            });
        }

        Ok(())
    }
}

impl Validate for ApiError {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.code.is_empty() {
            return Err(ValidationError::RequiredField {
                field: "code".to_string(),
            });
        }

        if self.message.is_empty() {
            return Err(ValidationError::RequiredField {
                field: "message".to_string(),
            });
        }

        Ok(())
    }
}

// Utility functions
pub fn create_success_response<T>(data: T, command: &str, execution_time_ms: u64) -> CliResponse<T> {
    CliResponse::success(data, command.to_string(), execution_time_ms)
}

pub fn create_error_response<T>(code: &str, message: &str, command: &str, execution_time_ms: u64) -> CliResponse<T> {
    let error = CliError::new(code.to_string(), message.to_string());
    CliResponse::error(error, command.to_string(), execution_time_ms)
}

pub fn create_api_success_response<T>(data: T) -> ApiResponse<T> {
    ApiResponse::success(data)
}

pub fn create_api_error_response<T>(code: &str, message: &str) -> ApiResponse<T> {
    let error = ApiError::new(code.to_string(), message.to_string());
    ApiResponse::error(error)
}