// ============================================================================
// Sky Genesis Enterprise API - API Key Core Module
// ============================================================================

use std::sync::Arc;
use sqlx::PgPool;
use crate::services::api_keys::ApiKeyService;
use crate::queries::api_keys::ApiKeyQueries;
use crate::utils::api_keys::{RateLimiter, KeyEncryption};

// ============================================================================
// API Key Core Manager
// ============================================================================

pub struct ApiKeyCore {
    pub service: Arc<ApiKeyService>,
    pub queries: Arc<ApiKeyQueries>,
    pub rate_limiter: Arc<std::sync::Mutex<RateLimiter>>,
    pub encryption_key: String,
}

impl ApiKeyCore {
    pub async fn new(database_url: &str, encryption_key: String) -> Result<Self, Box<dyn std::error::Error>> {
        // Create database connection pool
        let pool = PgPool::connect(database_url).await?;
        
        // Run migrations if needed
        sqlx::migrate!("./migrations").run(&pool).await?;

        let service = Arc::new(ApiKeyService::new(Arc::new(pool.clone())));
        let queries = Arc::new(ApiKeyQueries::new(pool));
        let rate_limiter = Arc::new(std::sync::Mutex::new(RateLimiter::new()));

        Ok(Self {
            service,
            queries,
            rate_limiter,
            encryption_key,
        })
    }

    pub fn from_pool(pool: PgPool, encryption_key: String) -> Self {
        let service = Arc::new(ApiKeyService::new(Arc::new(pool.clone())));
        let queries = Arc::new(ApiKeyQueries::new(pool));
        let rate_limiter = Arc::new(std::sync::Mutex::new(RateLimiter::new()));

        Self {
            service,
            queries,
            rate_limiter,
            encryption_key,
        }
    }

    /// Get the API key service
    pub fn service(&self) -> Arc<ApiKeyService> {
        self.service.clone()
    }

    /// Get the API key queries
    pub fn queries(&self) -> Arc<ApiKeyQueries> {
        self.queries.clone()
    }

    /// Get the rate limiter
    pub fn rate_limiter(&self) -> Arc<std::sync::Mutex<RateLimiter>> {
        self.rate_limiter.clone()
    }

    /// Get the encryption key
    pub fn encryption_key(&self) -> &str {
        &self.encryption_key
    }

    /// Encrypt sensitive data using the core encryption key
    pub fn encrypt_data(&self, data: &str) -> Result<String, String> {
        KeyEncryption::encrypt_sensitive_data(data, &self.encryption_key)
    }

    /// Decrypt sensitive data using the core encryption key
    pub fn decrypt_data(&self, encrypted_data: &str) -> Result<String, String> {
        KeyEncryption::decrypt_sensitive_data(encrypted_data, &self.encryption_key)
    }
}

// ============================================================================
// API Key Configuration
// ============================================================================

#[derive(Debug, Clone)]
pub struct ApiKeyConfig {
    pub database_url: String,
    pub encryption_key: String,
    pub default_quota_limits: DefaultQuotaLimits,
    pub rate_limiting: RateLimitConfig,
    pub security: SecurityConfig,
}

#[derive(Debug, Clone)]
pub struct DefaultQuotaLimits {
    pub client_key: i32,
    pub server_key: i32,
    pub database_key: i32,
}

impl Default for DefaultQuotaLimits {
    fn default() -> Self {
        Self {
            client_key: 100_000,
            server_key: 1_000_000,
            database_key: 500_000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub requests_per_minute: u32,
    pub burst_size: u32,
    pub cleanup_interval_minutes: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_minute: 60,
            burst_size: 10,
            cleanup_interval_minutes: 5,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecurityConfig {
    pub require_https: bool,
    pub max_key_length: usize,
    pub allow_key_regeneration: bool,
    pub auto_revoke_expired_keys: bool,
    pub log_all_access: bool,
    pub strict_origin_validation: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            require_https: true,
            max_key_length: 1024,
            allow_key_regeneration: true,
            auto_revoke_expired_keys: true,
            log_all_access: true,
            strict_origin_validation: true,
        }
    }
}

impl Default for ApiKeyConfig {
    fn default() -> Self {
        Self {
            database_url: "postgresql://localhost/api_service".to_string(),
            encryption_key: "change-this-in-production".to_string(),
            default_quota_limits: DefaultQuotaLimits::default(),
            rate_limiting: RateLimitConfig::default(),
            security: SecurityConfig::default(),
        }
    }
}

// ============================================================================
// API Key Factory
// ============================================================================

pub struct ApiKeyFactory;

impl ApiKeyFactory {
    /// Create API key core from configuration
    pub async fn create_from_config(config: ApiKeyConfig) -> Result<ApiKeyCore, Box<dyn std::error::Error>> {
        ApiKeyCore::new(&config.database_url, config.encryption_key).await
    }

    /// Create API key core from environment variables
    pub async fn create_from_env() -> Result<ApiKeyCore, Box<dyn std::error::Error>> {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://localhost/api_service".to_string());
        
        let encryption_key = std::env::var("API_KEY_ENCRYPTION_KEY")
            .unwrap_or_else(|_| "change-this-in-production".to_string());

        ApiKeyCore::new(&database_url, encryption_key).await
    }

    /// Create API key core for testing
    pub fn create_for_test() -> ApiKeyCore {
        // Use in-memory SQLite for testing
        let pool = sqlx::SqlitePool::connect(":memory:").await.unwrap();
        
        // Create tables
        sqlx::query(
            r#"
            CREATE TABLE api_keys (
                id TEXT PRIMARY KEY,
                organization_id TEXT NOT NULL,
                key_value TEXT UNIQUE NOT NULL,
                key_type TEXT NOT NULL,
                label TEXT,
                permissions TEXT,
                quota_limit INTEGER DEFAULT 100000,
                usage_count INTEGER DEFAULT 0,
                status TEXT DEFAULT 'active',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            "#
        )
        .execute(&pool)
        .await
        .unwrap();

        ApiKeyCore::from_pool(pool.into(), "test-key".to_string())
    }
}

// ============================================================================
// API Key Health Check
// ============================================================================

pub struct ApiKeyHealthCheck {
    core: Arc<ApiKeyCore>,
}

impl ApiKeyHealthCheck {
    pub fn new(core: Arc<ApiKeyCore>) -> Self {
        Self { core }
    }

    /// Check database connectivity
    pub async fn check_database(&self) -> Result<bool, Box<dyn std::error::Error>> {
        let result = sqlx::query("SELECT 1")
            .fetch_one(&*self.core.service.db)
            .await;

        Ok(result.is_ok())
    }

    /// Check rate limiter functionality
    pub fn check_rate_limiter(&self) -> bool {
        let mut rate_limiter = self.core.rate_limiter.lock().unwrap();
        
        // Test rate limiting
        let key_id = "test-key";
        let allowed1 = rate_limiter.is_allowed(key_id, 2);
        let allowed2 = rate_limiter.is_allowed(key_id, 2);
        let allowed3 = rate_limiter.is_allowed(key_id, 2); // Should be blocked

        allowed1 && allowed2 && !allowed3
    }

    /// Check encryption/decryption
    pub fn check_encryption(&self) -> bool {
        let test_data = "sensitive-test-data";
        
        match self.core.encrypt_data(test_data) {
            Ok(encrypted) => {
                match self.core.decrypt_data(&encrypted) {
                    Ok(decrypted) => decrypted == test_data,
                    Err(_) => false,
                }
            }
            Err(_) => false,
        }
    }

    /// Perform comprehensive health check
    pub async fn health_check(&self) -> HealthCheckResult {
        let database_ok = self.check_database().await.unwrap_or(false);
        let rate_limiter_ok = self.check_rate_limiter();
        let encryption_ok = self.check_encryption();

        HealthCheckResult {
            overall_healthy: database_ok && rate_limiter_ok && encryption_ok,
            database_connectivity: database_ok,
            rate_limiter_functionality: rate_limiter_ok,
            encryption_functionality: encryption_ok,
            timestamp: chrono::Utc::now(),
        }
    }
}

#[derive(Debug, serde::Serialize)]
pub struct HealthCheckResult {
    pub overall_healthy: bool,
    pub database_connectivity: bool,
    pub rate_limiter_functionality: bool,
    pub encryption_functionality: bool,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

// ============================================================================
// API Key Metrics
// ============================================================================

pub struct ApiKeyMetrics {
    core: Arc<ApiKeyCore>,
}

impl ApiKeyMetrics {
    pub fn new(core: Arc<ApiKeyCore>) -> Self {
        Self { core }
    }

    /// Get total number of API keys
    pub async fn total_keys(&self) -> Result<i64, Box<dyn std::error::Error>> {
        // This would need to be implemented in the service
        Ok(0)
    }

    /// Get active keys count
    pub async fn active_keys(&self) -> Result<i64, Box<dyn std::error::Error>> {
        Ok(0)
    }

    /// Get keys by type
    pub async fn keys_by_type(&self) -> Result<KeyTypeMetrics, Box<dyn std::error::Error>> {
        Ok(KeyTypeMetrics {
            client_keys: 0,
            server_keys: 0,
            database_keys: 0,
        })
    }

    /// Get usage statistics
    pub async fn usage_stats(&self) -> Result<UsageMetrics, Box<dyn std::error::Error>> {
        Ok(UsageMetrics {
            total_requests_today: 0,
            average_requests_per_key: 0.0,
            top_used_keys: Vec::new(),
        })
    }
}

#[derive(Debug, serde::Serialize)]
pub struct KeyTypeMetrics {
    pub client_keys: i64,
    pub server_keys: i64,
    pub database_keys: i64,
}

#[derive(Debug, serde::Serialize)]
pub struct UsageMetrics {
    pub total_requests_today: i64,
    pub average_requests_per_key: f64,
    pub top_used_keys: Vec<String>,
}

// ============================================================================
// Background Tasks
// ============================================================================

pub struct ApiKeyBackgroundTasks {
    core: Arc<ApiKeyCore>,
}

impl ApiKeyBackgroundTasks {
    pub fn new(core: Arc<ApiKeyCore>) -> Self {
        Self { core }
    }

    /// Start background tasks
    pub async fn start_tasks(&self) {
        let core_clone = self.core.clone();
        
        // Cleanup expired keys task
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600)); // Every hour
            
            loop {
                interval.tick().await;
                
                if let Err(e) = Self::cleanup_expired_keys(&core_clone).await {
                    eprintln!("Error cleaning up expired keys: {}", e);
                }
            }
        });

        // Cleanup rate limiter task
        let core_clone = self.core.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300)); // Every 5 minutes
            
            loop {
                interval.tick().await;
                
                core_clone.rate_limiter.lock().unwrap().cleanup();
            }
        });
    }

    /// Clean up expired keys
    async fn cleanup_expired_keys(core: &ApiKeyCore) -> Result<(), Box<dyn std::error::Error>> {
        let expired_keys = core.queries.find_expired_keys().await?;
        
        for key in expired_keys {
            // Update status to expired
            // This would need to be implemented in the service
            println!("Marking key {} as expired", key.id);
        }

        Ok(())
    }
}

// ============================================================================
// Re-exports
// ============================================================================

pub use crate::models::api_keys::*;
pub use crate::services::api_keys::ApiKeyService;
pub use crate::queries::api_keys::ApiKeyQueries;
pub use crate::utils::api_keys::*;