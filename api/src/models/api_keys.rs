// ============================================================================
// Sky Genesis Enterprise API - API Key Models
// ============================================================================

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use std::collections::HashMap;

// ============================================================================
// API Key Types
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyType {
    Client,
    Server,
    Database,
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyType::Client => write!(f, "client"),
            KeyType::Server => write!(f, "server"),
            KeyType::Database => write!(f, "database"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyStatus {
    Active,
    Inactive,
    Revoked,
    Expired,
}

impl std::fmt::Display for KeyStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyStatus::Active => write!(f, "active"),
            KeyStatus::Inactive => write!(f, "inactive"),
            KeyStatus::Revoked => write!(f, "revoked"),
            KeyStatus::Expired => write!(f, "expired"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DatabaseType {
    PostgreSQL,
    MySQL,
    MariaDB,
    MongoDB,
    Redis,
    SQLite,
}

impl std::fmt::Display for DatabaseType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DatabaseType::PostgreSQL => write!(f, "postgresql"),
            DatabaseType::MySQL => write!(f, "mysql"),
            DatabaseType::MariaDB => write!(f, "mariadb"),
            DatabaseType::MongoDB => write!(f, "mongodb"),
            DatabaseType::Redis => write!(f, "redis"),
            DatabaseType::SQLite => write!(f, "sqlite"),
        }
    }
}

// ============================================================================
// API Key Model
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub key_value: String,
    pub key_type: KeyType,
    pub label: Option<String>,
    pub permissions: Vec<String>,
    pub quota_limit: i32,
    pub usage_count: i32,
    pub status: KeyStatus,
    pub public_key: Option<String>,
    pub private_key: Option<String>,
    pub certificate_type: Option<String>,
    pub certificate_fingerprint: Option<String>,
    pub private_key_path: Option<String>,
    
    // Database-specific fields
    pub db_type: Option<DatabaseType>,
    pub db_host: Option<String>,
    pub db_port: Option<i32>,
    pub db_name: Option<String>,
    pub db_username: Option<String>,
    pub db_password_encrypted: Option<String>,
    
    // Server-specific fields
    pub server_endpoint: Option<String>,
    pub server_region: Option<String>,
    
    // Client-specific fields
    pub client_origin: Option<String>,
    pub client_scopes: Option<Vec<String>>,
    pub expires_at: Option<DateTime<Utc>>,
    
    // Timestamps
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ============================================================================
// Create API Key Request Models
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct CreateClientKeyRequest {
    pub label: String,
    pub permissions: Vec<String>,
    pub quota_limit: Option<i32>,
    pub client_origin: Option<String>,
    pub client_scopes: Option<Vec<String>>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct CreateServerKeyRequest {
    pub label: String,
    pub permissions: Vec<String>,
    pub quota_limit: Option<i32>,
    pub server_endpoint: String,
    pub server_region: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateDatabaseKeyRequest {
    pub label: String,
    pub permissions: Vec<String>,
    pub quota_limit: Option<i32>,
    pub db_type: DatabaseType,
    pub db_host: String,
    pub db_port: i32,
    pub db_name: String,
    pub db_username: String,
    pub db_password: String, // Will be encrypted
}

// ============================================================================
// API Key Response Models
// ============================================================================

#[derive(Debug, Serialize)]
pub struct ApiKeyResponse {
    pub id: Uuid,
    pub key_value: String, // Only shown on creation
    pub key_type: KeyType,
    pub label: Option<String>,
    pub permissions: Vec<String>,
    pub quota_limit: i32,
    pub usage_count: i32,
    pub status: KeyStatus,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    
    // Type-specific fields
    pub server_endpoint: Option<String>,
    pub server_region: Option<String>,
    pub db_type: Option<DatabaseType>,
    pub db_host: Option<String>,
    pub client_origin: Option<String>,
    pub client_scopes: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct ApiKeySecretResponse {
    pub id: Uuid,
    pub key_value: String, // Full key value (only shown once)
    pub private_key: Option<String>, // Only shown on creation
    pub db_password: Option<String>, // Only shown on creation for database keys
}

// ============================================================================
// Update API Key Request
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct UpdateApiKeyRequest {
    pub label: Option<String>,
    pub permissions: Option<Vec<String>>,
    pub quota_limit: Option<i32>,
    pub status: Option<KeyStatus>,
    pub client_origin: Option<String>,
    pub client_scopes: Option<Vec<String>>,
    pub server_endpoint: Option<String>,
    pub server_region: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

// ============================================================================
// API Key Usage Log
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyUsage {
    pub id: Uuid,
    pub api_key_id: Uuid,
    pub endpoint: String,
    pub method: String,
    pub ip_address: String,
    pub user_agent: Option<String>,
    pub response_status: i32,
    pub latency_ms: i32,
    pub timestamp: DateTime<Utc>,
}

// ============================================================================
// API Key Statistics
// ============================================================================

#[derive(Debug, Serialize)]
pub struct ApiKeyStats {
    pub total_keys: i64,
    pub active_keys: i64,
    pub client_keys: i64,
    pub server_keys: i64,
    pub database_keys: i64,
    pub total_usage_today: i64,
    pub top_used_keys: Vec<ApiKeyUsageSummary>,
}

#[derive(Debug, Serialize)]
pub struct ApiKeyUsageSummary {
    pub id: Uuid,
    pub label: Option<String>,
    pub key_type: KeyType,
    pub usage_count: i32,
    pub last_used_at: Option<DateTime<Utc>>,
}

// ============================================================================
// Database Row Models (for SQLx)
// ============================================================================

#[derive(Debug, sqlx::FromRow)]
pub struct ApiKeyRow {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub key_value: String,
    pub key_type: String,
    pub label: Option<String>,
    pub permissions: Vec<String>,
    pub quota_limit: i32,
    pub usage_count: i32,
    pub status: String,
    pub public_key: Option<String>,
    pub private_key: Option<String>,
    pub certificate_type: Option<String>,
    pub certificate_fingerprint: Option<String>,
    pub private_key_path: Option<String>,
    pub db_type: Option<String>,
    pub db_host: Option<String>,
    pub db_port: Option<i32>,
    pub db_name: Option<String>,
    pub db_username: Option<String>,
    pub db_password_encrypted: Option<String>,
    pub server_endpoint: Option<String>,
    pub server_region: Option<String>,
    pub client_origin: Option<String>,
    pub client_scopes: Option<Vec<String>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<ApiKeyRow> for ApiKey {
    fn from(row: ApiKeyRow) -> Self {
        ApiKey {
            id: row.id,
            organization_id: row.organization_id,
            key_value: row.key_value,
            key_type: match row.key_type.as_str() {
                "client" => KeyType::Client,
                "server" => KeyType::Server,
                "database" => KeyType::Database,
                _ => KeyType::Client, // Default fallback
            },
            label: row.label,
            permissions: row.permissions,
            quota_limit: row.quota_limit,
            usage_count: row.usage_count,
            status: match row.status.as_str() {
                "active" => KeyStatus::Active,
                "inactive" => KeyStatus::Inactive,
                "revoked" => KeyStatus::Revoked,
                "expired" => KeyStatus::Expired,
                _ => KeyStatus::Active, // Default fallback
            },
            public_key: row.public_key,
            private_key: row.private_key,
            certificate_type: row.certificate_type,
            certificate_fingerprint: row.certificate_fingerprint,
            private_key_path: row.private_key_path,
            db_type: row.db_type.and_then(|t| match t.as_str() {
                "postgresql" => Some(DatabaseType::PostgreSQL),
                "mysql" => Some(DatabaseType::MySQL),
                "mariadb" => Some(DatabaseType::MariaDB),
                "mongodb" => Some(DatabaseType::MongoDB),
                "redis" => Some(DatabaseType::Redis),
                "sqlite" => Some(DatabaseType::SQLite),
                _ => None,
            }),
            db_host: row.db_host,
            db_port: row.db_port,
            db_name: row.db_name,
            db_username: row.db_username,
            db_password_encrypted: row.db_password_encrypted,
            server_endpoint: row.server_endpoint,
            server_region: row.server_region,
            client_origin: row.client_origin,
            client_scopes: row.client_scopes,
            expires_at: row.expires_at,
            last_used_at: row.last_used_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}