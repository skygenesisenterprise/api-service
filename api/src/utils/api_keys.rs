// ============================================================================
// Sky Genesis Enterprise API - API Key Utilities
// ============================================================================

use crate::models::api_keys::{KeyType, DatabaseType, KeyStatus};
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use base64::{Engine as _, engine::general_purpose};
use rand::Rng;
use regex::Regex;
use std::collections::HashMap;

// ============================================================================
// Key Generation Utilities
// ============================================================================

pub struct KeyGenerator;

impl KeyGenerator {
    /// Generate a secure random API key with proper prefix
    pub fn generate_api_key(key_type: &KeyType) -> String {
        let prefix = match key_type {
            KeyType::Client => "sk_client",
            KeyType::Server => "sk_server",
            KeyType::Database => "sk_db",
        };
        
        // Generate 32 random bytes (256 bits)
        let random_bytes: [u8; 32] = rand::thread_rng().gen();
        let random_part = general_purpose::URL_SAFE_NO_PAD.encode(random_bytes);
        
        format!("{}_{}", prefix, random_part)
    }

    /// Generate a secure random secret key
    pub fn generate_secret_key(length: usize) -> String {
        let random_bytes: Vec<u8> = (0..length).map(|_| rand::random::<u8>()).collect();
        general_purpose::URL_SAFE_NO_PAD.encode(random_bytes)
    }

    /// Generate a key ID for internal tracking
    pub fn generate_key_id() -> Uuid {
        Uuid::new_v4()
    }

    /// Generate a certificate fingerprint
    pub fn generate_fingerprint(public_key: &str) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(public_key.as_bytes());
        let result = hasher.finalize();
        hex::encode(result)
    }
}

// ============================================================================
// Validation Utilities
// ============================================================================

pub struct KeyValidator;

impl KeyValidator {
    /// Validate API key format
    pub fn validate_api_key_format(key_value: &str) -> Result<(), String> {
        let key_regex = Regex::new(r"^sk_(client|server|db)_[A-Za-z0-9_-]+$")
            .map_err(|e| format!("Invalid regex: {}", e))?;

        if !key_regex.is_match(key_value) {
            return Err("Invalid API key format".to_string());
        }

        Ok(())
    }

    /// Validate key type from string value
    pub fn validate_key_type(key_type: &str) -> Result<KeyType, String> {
        match key_type.to_lowercase().as_str() {
            "client" => Ok(KeyType::Client),
            "server" => Ok(KeyType::Server),
            "database" | "db" => Ok(KeyType::Database),
            _ => Err("Invalid key type. Must be 'client', 'server', or 'database'".to_string()),
        }
    }

    /// Validate database type
    pub fn validate_database_type(db_type: &str) -> Result<DatabaseType, String> {
        match db_type.to_lowercase().as_str() {
            "postgresql" | "postgres" => Ok(DatabaseType::PostgreSQL),
            "mysql" => Ok(DatabaseType::MySQL),
            "mariadb" => Ok(DatabaseType::MariaDB),
            "mongodb" | "mongo" => Ok(DatabaseType::MongoDB),
            "redis" => Ok(DatabaseType::Redis),
            "sqlite" => Ok(DatabaseType::SQLite),
            _ => Err("Invalid database type. Supported: PostgreSQL, MySQL, MariaDB, MongoDB, Redis, SQLite".to_string()),
        }
    }

    /// Validate permissions array
    pub fn validate_permissions(permissions: &[String]) -> Result<(), String> {
        if permissions.is_empty() {
            return Err("At least one permission is required".to_string());
        }

        let valid_permissions = vec![
            "read", "write", "delete", "admin", "create_keys", "manage_keys",
            "view_stats", "manage_users", "manage_databases", "server_access",
            "client_access", "database_access"
        ];

        for permission in permissions {
            if !valid_permissions.contains(&permission.as_str()) {
                return Err(format!("Invalid permission: {}", permission));
            }
        }

        Ok(())
    }

    /// Validate quota limit
    pub fn validate_quota_limit(quota_limit: i32) -> Result<(), String> {
        if quota_limit < 0 {
            return Err("Quota limit must be non-negative".to_string());
        }

        if quota_limit > 10_000_000 {
            return Err("Quota limit cannot exceed 10,000,000".to_string());
        }

        Ok(())
    }

    /// Validate database connection parameters
    pub fn validate_database_params(
        db_host: &str,
        db_port: i32,
        db_name: &str,
        db_username: &str,
        db_password: &str,
    ) -> Result<(), String> {
        // Validate host
        if db_host.is_empty() {
            return Err("Database host is required".to_string());
        }

        if db_host.len() > 255 {
            return Err("Database host too long (max 255 characters)".to_string());
        }

        // Validate port
        if db_port < 1 || db_port > 65535 {
            return Err("Database port must be between 1 and 65535".to_string());
        }

        // Validate database name
        if db_name.is_empty() {
            return Err("Database name is required".to_string());
        }

        if db_name.len() > 64 {
            return Err("Database name too long (max 64 characters)".to_string());
        }

        // Validate username
        if db_username.is_empty() {
            return Err("Database username is required".to_string());
        }

        if db_username.len() > 128 {
            return Err("Database username too long (max 128 characters)".to_string());
        }

        // Validate password
        if db_password.is_empty() {
            return Err("Database password is required".to_string());
        }

        if db_password.len() > 1024 {
            return Err("Database password too long (max 1024 characters)".to_string());
        }

        Ok(())
    }

    /// Validate server endpoint
    pub fn validate_server_endpoint(endpoint: &str) -> Result<(), String> {
        if endpoint.is_empty() {
            return Err("Server endpoint is required".to_string());
        }

        // Basic URL validation
        if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
            // URL format
            let url_regex = Regex::new(r"^https?://[A-Za-z0-9.-]+(?::\d+)?(?:/.*)?$")
                .map_err(|e| format!("Invalid regex: {}", e))?;

            if !url_regex.is_match(endpoint) {
                return Err("Invalid server endpoint URL format".to_string());
            }
        } else {
            // IP:Port format
            let ip_port_regex = Regex::new(r"^[0-9.]+:\d+$")
                .map_err(|e| format!("Invalid regex: {}", e))?;

            if !ip_port_regex.is_match(endpoint) {
                return Err("Server endpoint must be a valid URL or IP:PORT".to_string());
            }
        }

        Ok(())
    }

    /// Validate client origin
    pub fn validate_client_origin(origin: &str) -> Result<(), String> {
        if origin.is_empty() {
            return Err("Client origin is required for client keys".to_string());
        }

        // Basic origin validation (protocol://host[:port])
        let origin_regex = Regex::new(r"^https?://[A-Za-z0-9.-]+(?::\d+)?(?:/.*)?$")
            .map_err(|e| format!("Invalid regex: {}", e))?;

        if !origin_regex.is_match(origin) {
            return Err("Invalid client origin format".to_string());
        }

        Ok(())
    }

    /// Validate expiration date
    pub fn validate_expiration_date(expires_at: Option<DateTime<Utc>>) -> Result<(), String> {
        if let Some(expiry) = expires_at {
            let now = Utc::now();
            
            if expiry <= now {
                return Err("Expiration date must be in the future".to_string());
            }

            // Max 1 year from now
            let max_expiry = now + Duration::days(365);
            if expiry > max_expiry {
                return Err("Expiration date cannot be more than 1 year from now".to_string());
            }
        }

        Ok(())
    }
}

// ============================================================================
// Encryption Utilities
// ============================================================================

pub struct KeyEncryption;

impl KeyEncryption {
    /// Encrypt sensitive data (basic implementation - use proper encryption in production)
    pub fn encrypt_sensitive_data(data: &str, encryption_key: &str) -> Result<String, String> {
        // This is a placeholder - in production, use proper encryption like AES-256-GCM
        let combined = format!("{}:{}", encryption_key, data);
        Ok(general_purpose::STANDARD.encode(combined.as_bytes()))
    }

    /// Decrypt sensitive data
    pub fn decrypt_sensitive_data(encrypted_data: &str, encryption_key: &str) -> Result<String, String> {
        // This is a placeholder - in production, use proper decryption
        let decoded = general_purpose::STANDARD
            .decode(encrypted_data)
            .map_err(|e| format!("Failed to decode encrypted data: {}", e))?;

        let combined = String::from_utf8(decoded)
            .map_err(|e| format!("Failed to convert to string: {}", e))?;

        if let Some(data) = combined.strip_prefix(&format!("{}:", encryption_key)) {
            Ok(data.to_string())
        } else {
            Err("Invalid encryption key or data format".to_string())
        }
    }

    /// Hash API key for storage (never store raw keys in logs)
    pub fn hash_api_key(key_value: &str) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(key_value.as_bytes());
        let result = hasher.finalize();
        format!("sk_hash_{}", hex::encode(result))
    }
}

// ============================================================================
// Permission Utilities
// ============================================================================

pub struct PermissionUtils;

impl PermissionUtils {
    /// Check if a permission set includes required permission
    pub fn has_permission(user_permissions: &[String], required_permission: &str) -> bool {
        user_permissions.contains(&required_permission.to_string()) ||
        user_permissions.contains(&"admin".to_string())
    }

    /// Check if a permission set includes any of the required permissions
    pub fn has_any_permission(user_permissions: &[String], required_permissions: &[&str]) -> bool {
        required_permissions.iter().any(|&perm| {
            Self::has_permission(user_permissions, perm)
        })
    }

    /// Check if a permission set includes all required permissions
    pub fn has_all_permissions(user_permissions: &[String], required_permissions: &[&str]) -> bool {
        required_permissions.iter().all(|&perm| {
            Self::has_permission(user_permissions, perm)
        })
    }

    /// Get default permissions for key type
    pub fn get_default_permissions(key_type: &KeyType) -> Vec<String> {
        match key_type {
            KeyType::Client => vec!["read".to_string(), "client_access".to_string()],
            KeyType::Server => vec!["read".to_string(), "write".to_string(), "server_access".to_string()],
            KeyType::Database => vec!["read".to_string(), "write".to_string(), "database_access".to_string()],
        }
    }

    /// Get all available permissions
    pub fn get_all_permissions() -> Vec<String> {
        vec![
            "read".to_string(),
            "write".to_string(),
            "delete".to_string(),
            "admin".to_string(),
            "create_keys".to_string(),
            "manage_keys".to_string(),
            "view_stats".to_string(),
            "manage_users".to_string(),
            "manage_databases".to_string(),
            "server_access".to_string(),
            "client_access".to_string(),
            "database_access".to_string(),
        ]
    }
}

// ============================================================================
// Rate Limiting Utilities
// ============================================================================

pub struct RateLimiter {
    // In production, use Redis or a proper rate limiting store
    requests: HashMap<String, Vec<DateTime<Utc>>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            requests: HashMap::new(),
        }
    }

    /// Check if a request is allowed based on rate limit
    pub fn is_allowed(&mut self, key_id: &str, requests_per_minute: u32) -> bool {
        let now = Utc::now();
        let one_minute_ago = now - Duration::minutes(1);

        // Get or create request history for this key
        let key_requests = self.requests.entry(key_id.to_string()).or_insert_with(Vec::new);

        // Remove old requests (older than 1 minute)
        key_requests.retain(|&timestamp| timestamp > one_minute_ago);

        // Check if under limit
        if key_requests.len() < requests_per_minute as usize {
            key_requests.push(now);
            true
        } else {
            false
        }
    }

    /// Clean up old entries
    pub fn cleanup(&mut self) {
        let five_minutes_ago = Utc::now() - Duration::minutes(5);
        
        self.requests.retain(|_, timestamps| {
            timestamps.retain(|&timestamp| timestamp > five_minutes_ago);
            !timestamps.is_empty()
        });
    }
}

// ============================================================================
// Key Type Utilities
// ============================================================================

pub struct KeyTypeUtils;

impl KeyTypeUtils {
    /// Get key type from API key string
    pub fn extract_key_type_from_key(key_value: &str) -> Option<KeyType> {
        if key_value.starts_with("sk_client_") {
            Some(KeyType::Client)
        } else if key_value.starts_with("sk_server_") {
            Some(KeyType::Server)
        } else if key_value.starts_with("sk_db_") {
            Some(KeyType::Database)
        } else {
            None
        }
    }

    /// Get description for key type
    pub fn get_key_type_description(key_type: &KeyType) -> &'static str {
        match key_type {
            KeyType::Client => "Client API key for frontend applications",
            KeyType::Server => "Server API key for backend services",
            KeyType::Database => "Database API key for database connections",
        }
    }

    /// Get default quota limit for key type
    pub fn get_default_quota_limit(key_type: &KeyType) -> i32 {
        match key_type {
            KeyType::Client => 100_000,
            KeyType::Server => 1_000_000,
            KeyType::Database => 500_000,
        }
    }

    /// Check if key type supports expiration
    pub fn supports_expiration(key_type: &KeyType) -> bool {
        matches!(key_type, KeyType::Client)
    }

    /// Check if key type supports origin validation
    pub fn supports_origin_validation(key_type: &KeyType) -> bool {
        matches!(key_type, KeyType::Client)
    }
}

// ============================================================================
// Statistics Utilities
// ============================================================================

pub struct StatsUtils;

impl StatsUtils {
    /// Calculate quota usage percentage
    pub fn calculate_quota_usage(usage_count: i32, quota_limit: i32) -> f64 {
        if quota_limit == 0 {
            0.0
        } else {
            (usage_count as f64 / quota_limit as f64) * 100.0
        }
    }

    /// Check if key is near quota limit
    pub fn is_near_quota_limit(usage_count: i32, quota_limit: i32, threshold_percent: f64) -> bool {
        Self::calculate_quota_usage(usage_count, quota_limit) >= threshold_percent
    }

    /// Get days since last used
    pub fn days_since_last_used(last_used_at: Option<DateTime<Utc>>) -> Option<i64> {
        last_used_at.map(|last_used| {
            let now = Utc::now();
            (now - last_used).num_days()
        })
    }

    /// Check if key is inactive
    pub fn is_inactive(last_used_at: Option<DateTime<Utc>>, threshold_days: i64) -> bool {
        if let Some(days) = Self::days_since_last_used(last_used_at) {
            days > threshold_days
        } else {
            // Never used keys are considered inactive
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let client_key = KeyGenerator::generate_api_key(&KeyType::Client);
        let server_key = KeyGenerator::generate_api_key(&KeyType::Server);
        let db_key = KeyGenerator::generate_api_key(&KeyType::Database);

        assert!(client_key.starts_with("sk_client_"));
        assert!(server_key.starts_with("sk_server_"));
        assert!(db_key.starts_with("sk_db_"));
    }

    #[test]
    fn test_key_validation() {
        assert!(KeyValidator::validate_api_key_format("sk_client_abc123").is_ok());
        assert!(KeyValidator::validate_api_key_format("invalid_key").is_err());
    }

    #[test]
    fn test_permission_utils() {
        let permissions = vec!["read".to_string(), "write".to_string()];
        
        assert!(PermissionUtils::has_permission(&permissions, "read"));
        assert!(!PermissionUtils::has_permission(&permissions, "delete"));
        assert!(PermissionUtils::has_any_permission(&permissions, &["delete", "read"]));
        assert!(!PermissionUtils::has_all_permissions(&permissions, &["read", "delete"]));
    }
}