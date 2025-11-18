// ============================================================================
// Sky Genesis Enterprise API - API Key Tests
// ============================================================================

#[cfg(test)]
mod api_key_tests {
    use super::*;
    use crate::models::api_keys::*;
    use crate::services::api_keys::ApiKeyService;
    use crate::utils::api_keys::*;
    use uuid::Uuid;
    chrono::Utc;

    // Mock database pool for testing
    async fn create_test_pool() -> sqlx::PgPool {
        // In a real implementation, you'd use a test database
        // For now, we'll create a mock
        sqlx::PgPool::connect("postgresql://test:test@localhost/test_db")
            .await
            .expect("Failed to create test pool")
    }

    #[tokio::test]
    async fn test_create_client_key() {
        let pool = create_test_pool().await;
        let service = ApiKeyService::new(std::sync::Arc::new(pool));
        
        let organization_id = Uuid::new_v4();
        let request = CreateClientKeyRequest {
            label: "Test Client Key".to_string(),
            permissions: vec!["read".to_string(), "client_access".to_string()],
            quota_limit: Some(1000),
            client_origin: Some("https://example.com".to_string()),
            client_scopes: Some(vec!["api:read".to_string()]),
            expires_at: Some(Utc::now() + chrono::Duration::days(30)),
        };

        let result = service.create_client_key(organization_id, request).await;
        
        assert!(result.is_ok());
        let (response, secret_response) = result.unwrap();
        
        assert_eq!(response.key_type, KeyType::Client);
        assert!(response.key_value.starts_with("sk_client_"));
        assert_eq!(secret_response.key_value, response.key_value);
    }

    #[tokio::test]
    async fn test_create_server_key() {
        let pool = create_test_pool().await;
        let service = ApiKeyService::new(std::sync::Arc::new(pool));
        
        let organization_id = Uuid::new_v4();
        let request = CreateServerKeyRequest {
            label: "Test Server Key".to_string(),
            permissions: vec!["read".to_string(), "write".to_string(), "server_access".to_string()],
            quota_limit: Some(10000),
            server_endpoint: "https://api.example.com".to_string(),
            server_region: Some("us-west-2".to_string()),
        };

        let result = service.create_server_key(organization_id, request).await;
        
        assert!(result.is_ok());
        let (response, secret_response) = result.unwrap();
        
        assert_eq!(response.key_type, KeyType::Server);
        assert!(response.key_value.starts_with("sk_server_"));
        assert_eq!(response.server_endpoint, Some("https://api.example.com".to_string()));
        assert_eq!(secret_response.key_value, response.key_value);
    }

    #[tokio::test]
    async fn test_create_database_key() {
        let pool = create_test_pool().await;
        let service = ApiKeyService::new(std::sync::Arc::new(pool));
        
        let organization_id = Uuid::new_v4();
        let request = CreateDatabaseKeyRequest {
            label: "Test Database Key".to_string(),
            permissions: vec!["read".to_string(), "write".to_string(), "database_access".to_string()],
            quota_limit: Some(5000),
            db_type: DatabaseType::PostgreSQL,
            db_host: "localhost".to_string(),
            db_port: 5432,
            db_name: "test_db".to_string(),
            db_username: "test_user".to_string(),
            db_password: "test_password".to_string(),
        };

        let result = service.create_database_key(organization_id, request).await;
        
        assert!(result.is_ok());
        let (response, secret_response) = result.unwrap();
        
        assert_eq!(response.key_type, KeyType::Database);
        assert!(response.key_value.starts_with("sk_db_"));
        assert_eq!(response.db_type, Some(DatabaseType::PostgreSQL));
        assert_eq!(response.db_host, Some("localhost".to_string()));
        assert_eq!(secret_response.db_password, Some("test_password".to_string()));
    }

    #[test]
    fn test_key_generation() {
        let client_key = KeyGenerator::generate_api_key(&KeyType::Client);
        let server_key = KeyGenerator::generate_api_key(&KeyType::Server);
        let db_key = KeyGenerator::generate_api_key(&KeyType::Database);

        assert!(client_key.starts_with("sk_client_"));
        assert!(server_key.starts_with("sk_server_"));
        assert!(db_key.starts_with("sk_db_"));

        // Test uniqueness
        let client_key2 = KeyGenerator::generate_api_key(&KeyType::Client);
        assert_ne!(client_key, client_key2);
    }

    #[test]
    fn test_key_validation() {
        // Test valid keys
        assert!(KeyValidator::validate_api_key_format("sk_client_abc123").is_ok());
        assert!(KeyValidator::validate_api_key_format("sk_server_def456").is_ok());
        assert!(KeyValidator::validate_api_key_format("sk_db_ghi789").is_ok());

        // Test invalid keys
        assert!(KeyValidator::validate_api_key_format("invalid_key").is_err());
        assert!(KeyValidator::validate_api_key_format("sk_wrong_abc").is_err());
        assert!(KeyValidator::validate_api_key_format("").is_err());

        // Test key type validation
        assert!(KeyValidator::validate_key_type("client").is_ok());
        assert!(KeyValidator::validate_key_type("server").is_ok());
        assert!(KeyValidator::validate_key_type("database").is_ok());
        assert!(KeyValidator::validate_key_type("invalid").is_err());

        // Test database type validation
        assert!(KeyValidator::validate_database_type("postgresql").is_ok());
        assert!(KeyValidator::validate_database_type("mysql").is_ok());
        assert!(KeyValidator::validate_database_type("invalid").is_err());

        // Test permission validation
        assert!(KeyValidator::validate_permissions(&vec!["read".to_string()]).is_ok());
        assert!(KeyValidator::validate_permissions(&vec![]).is_err());
        assert!(KeyValidator::validate_permissions(&vec!["invalid_permission".to_string()]).is_err());

        // Test quota validation
        assert!(KeyValidator::validate_quota_limit(1000).is_ok());
        assert!(KeyValidator::validate_quota_limit(-1).is_err());
        assert!(KeyValidator::validate_quota_limit(20_000_000).is_err());
    }

    #[test]
    fn test_database_validation() {
        // Valid database parameters
        assert!(KeyValidator::validate_database_params(
            "localhost",
            5432,
            "test_db",
            "test_user",
            "test_password"
        ).is_ok());

        // Invalid host
        assert!(KeyValidator::validate_database_params(
            "",
            5432,
            "test_db",
            "test_user",
            "test_password"
        ).is_err());

        // Invalid port
        assert!(KeyValidator::validate_database_params(
            "localhost",
            0,
            "test_db",
            "test_user",
            "test_password"
        ).is_err());

        // Invalid database name
        assert!(KeyValidator::validate_database_params(
            "localhost",
            5432,
            "",
            "test_user",
            "test_password"
        ).is_err());
    }

    #[test]
    fn test_server_endpoint_validation() {
        // Valid URLs
        assert!(KeyValidator::validate_server_endpoint("https://api.example.com").is_ok());
        assert!(KeyValidator::validate_server_endpoint("http://localhost:8080").is_ok());
        assert!(KeyValidator::validate_server_endpoint("192.168.1.100:3000").is_ok());

        // Invalid endpoints
        assert!(KeyValidator::validate_server_endpoint("").is_err());
        assert!(KeyValidator::validate_server_endpoint("not-a-url").is_err());
        assert!(KeyValidator::validate_server_endpoint("ftp://example.com").is_err());
    }

    #[test]
    fn test_client_origin_validation() {
        // Valid origins
        assert!(KeyValidator::validate_client_origin("https://example.com").is_ok());
        assert!(KeyValidator::validate_client_origin("http://localhost:3000").is_ok());
        assert!(KeyValidator::validate_client_origin("https://app.example.com:8443").is_ok());

        // Invalid origins
        assert!(KeyValidator::validate_client_origin("").is_err());
        assert!(KeyValidator::validate_client_origin("example.com").is_err());
        assert!(KeyValidator::validate_client_origin("ftp://example.com").is_err());
    }

    #[test]
    fn test_expiration_validation() {
        let now = Utc::now();
        
        // Valid expiration dates
        assert!(KeyValidator::validate_expiration_date(Some(now + chrono::Duration::days(1))).is_ok());
        assert!(KeyValidator::validate_expiration_date(Some(now + chrono::Duration::days(365))).is_ok());
        assert!(KeyValidator::validate_expiration_date(None).is_ok());

        // Invalid expiration dates
        assert!(KeyValidator::validate_expiration_date(Some(now - chrono::Duration::days(1))).is_err());
        assert!(KeyValidator::validate_expiration_date(Some(now + chrono::Duration::days(400))).is_err());
    }

    #[test]
    fn test_encryption() {
        let encryption_key = "test-key-123";
        let sensitive_data = "super-secret-password";

        // Test encryption
        let encrypted = KeyEncryption::encrypt_sensitive_data(sensitive_data, encryption_key).unwrap();
        assert_ne!(encrypted, sensitive_data);

        // Test decryption
        let decrypted = KeyEncryption::decrypt_sensitive_data(&encrypted, encryption_key).unwrap();
        assert_eq!(decrypted, sensitive_data);

        // Test with wrong key
        let wrong_key = "wrong-key";
        assert!(KeyEncryption::decrypt_sensitive_data(&encrypted, wrong_key).is_err());
    }

    #[test]
    fn test_permission_utils() {
        let permissions = vec![
            "read".to_string(),
            "write".to_string(),
            "client_access".to_string(),
        ];

        // Test individual permission check
        assert!(PermissionUtils::has_permission(&permissions, "read"));
        assert!(PermissionUtils::has_permission(&permissions, "write"));
        assert!(!PermissionUtils::has_permission(&permissions, "delete"));

        // Test admin permission
        let admin_permissions = vec!["admin".to_string()];
        assert!(PermissionUtils::has_permission(&admin_permissions, "any_permission"));

        // Test any permission
        assert!(PermissionUtils::has_any_permission(&permissions, &["delete", "read"]));
        assert!(!PermissionUtils::has_any_permission(&permissions, &["delete", "admin"]));

        // Test all permissions
        assert!(PermissionUtils::has_all_permissions(&permissions, &["read", "write"]));
        assert!(!PermissionUtils::has_all_permissions(&permissions, &["read", "delete"]));

        // Test default permissions
        let client_defaults = PermissionUtils::get_default_permissions(&KeyType::Client);
        assert!(client_defaults.contains(&"read".to_string()));
        assert!(client_defaults.contains(&"client_access".to_string()));
    }

    #[test]
    fn test_rate_limiter() {
        let mut rate_limiter = RateLimiter::new();

        // Test rate limiting
        assert!(rate_limiter.is_allowed("key1", 2)); // 1st request
        assert!(rate_limiter.is_allowed("key1", 2)); // 2nd request
        assert!(!rate_limiter.is_allowed("key1", 2)); // 3rd request - blocked

        // Test different keys
        assert!(rate_limiter.is_allowed("key2", 2)); // Different key, should be allowed

        // Test cleanup
        rate_limiter.cleanup();
    }

    #[test]
    fn test_key_type_utils() {
        // Test key type extraction
        assert_eq!(
            KeyTypeUtils::extract_key_type_from_key("sk_client_abc123"),
            Some(KeyType::Client)
        );
        assert_eq!(
            KeyTypeUtils::extract_key_type_from_key("sk_server_def456"),
            Some(KeyType::Server)
        );
        assert_eq!(
            KeyTypeUtils::extract_key_type_from_key("sk_db_ghi789"),
            Some(KeyType::Database)
        );
        assert_eq!(
            KeyTypeUtils::extract_key_type_from_key("invalid_key"),
            None
        );

        // Test descriptions
        assert!(!KeyTypeUtils::get_key_type_description(&KeyType::Client).is_empty());
        assert!(!KeyTypeUtils::get_key_type_description(&KeyType::Server).is_empty());
        assert!(!KeyTypeUtils::get_key_type_description(&KeyType::Database).is_empty());

        // Test default quotas
        assert!(KeyTypeUtils::get_default_quota_limit(&KeyType::Client) > 0);
        assert!(KeyTypeUtils::get_default_quota_limit(&KeyType::Server) > 0);
        assert!(KeyTypeUtils::get_default_quota_limit(&KeyType::Database) > 0);

        // Test feature support
        assert!(KeyTypeUtils::supports_expiration(&KeyType::Client));
        assert!(!KeyTypeUtils::supports_expiration(&KeyType::Server));
        assert!(!KeyTypeUtils::supports_expiration(&KeyType::Database));

        assert!(KeyTypeUtils::supports_origin_validation(&KeyType::Client));
        assert!(!KeyTypeUtils::supports_origin_validation(&KeyType::Server));
        assert!(!KeyTypeUtils::supports_origin_validation(&KeyType::Database));
    }

    #[test]
    fn test_stats_utils() {
        // Test quota usage calculation
        assert_eq!(StatsUtils::calculate_quota_usage(50, 100), 50.0);
        assert_eq!(StatsUtils::calculate_quota_usage(0, 100), 0.0);
        assert_eq!(StatsUtils::calculate_quota_usage(100, 100), 100.0);
        assert_eq!(StatsUtils::calculate_quota_usage(50, 0), 0.0);

        // Test quota limit checking
        assert!(StatsUtils::is_near_quota_limit(80, 100, 75.0));
        assert!(!StatsUtils::is_near_quota_limit(70, 100, 75.0));

        // Test days since last used
        let now = Utc::now();
        let yesterday = now - chrono::Duration::days(1);
        assert_eq!(StatsUtils::days_since_last_used(Some(yesterday)), Some(1));
        assert_eq!(StatsUtils::days_since_last_used(None), None);

        // Test inactive checking
        assert!(StatsUtils::is_inactive(None, 30)); // Never used = inactive
        assert!(StatsUtils::is_inactive(Some(now - chrono::Duration::days(31)), 30));
        assert!(!StatsUtils::is_inactive(Some(now - chrono::Duration::days(29)), 30));
    }

    #[tokio::test]
    async fn test_api_key_lifecycle() {
        let pool = create_test_pool().await;
        let service = ApiKeyService::new(std::sync::Arc::new(pool));
        
        let organization_id = Uuid::new_v4();

        // Create key
        let create_request = CreateClientKeyRequest {
            label: "Lifecycle Test Key".to_string(),
            permissions: vec!["read".to_string()],
            quota_limit: Some(100),
            client_origin: None,
            client_scopes: None,
            expires_at: None,
        };

        let (created_key, _) = service.create_client_key(organization_id, create_request).await.unwrap();
        let key_id = created_key.id;

        // Get key
        let retrieved_key = service.get_key_by_id(key_id, organization_id).await.unwrap();
        assert!(retrieved_key.is_some());
        assert_eq!(retrieved_key.unwrap().label, Some("Lifecycle Test Key".to_string()));

        // Update key
        let update_request = UpdateApiKeyRequest {
            label: Some("Updated Test Key".to_string()),
            permissions: None,
            quota_limit: Some(200),
            status: None,
            client_origin: None,
            client_scopes: None,
            server_endpoint: None,
            server_region: None,
            expires_at: None,
        };

        let updated_key = service.update_key(key_id, organization_id, update_request).await.unwrap();
        assert!(updated_key.is_some());
        assert_eq!(updated_key.unwrap().label, Some("Updated Test Key".to_string()));

        // Revoke key
        let revoked = service.revoke_key(key_id, organization_id).await.unwrap();
        assert!(revoked);

        // Verify revoked status
        let revoked_key = service.get_key_by_id(key_id, organization_id).await.unwrap();
        assert!(revoked_key.is_some());
        assert_eq!(revoked_key.unwrap().status, KeyStatus::Revoked);
    }
}

// ============================================================================
// Integration Tests
// ============================================================================

#[cfg(test)]
mod integration_tests {
    use super::*;
    use warp::test::request();
    use crate::routes::api_keys::api_key_routes;
    use crate::controllers::api_keys::ApiKeyController;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_api_key_endpoints() {
        // This would require setting up a full test environment
        // with database and all dependencies
        
        // Create test service
        let pool = create_test_pool().await;
        let service = Arc::new(ApiKeyService::new(Arc::new(pool)));
        let routes = api_key_routes(service);

        // Test health endpoint
        let response = request()
            .method("GET")
            .path("/api/v1/health")
            .reply(&routes)
            .await;

        assert_eq!(response.status(), 200);
        
        // Test other endpoints would go here
        // This is a placeholder for integration testing
    }
}

// ============================================================================
// Performance Tests
// ============================================================================

#[cfg(test)]
mod performance_tests {
    use super::*;
    use std::time::Instant;

    #[tokio::test]
    async fn test_key_generation_performance() {
        let start = Instant::now();
        
        for _ in 0..1000 {
            KeyGenerator::generate_api_key(&KeyType::Client);
        }
        
        let duration = start.elapsed();
        println!("Generated 1000 keys in {:?}", duration);
        
        // Should be fast - less than 100ms for 1000 keys
        assert!(duration.as_millis() < 100);
    }

    #[tokio::test]
    async fn test_validation_performance() {
        let start = Instant::now();
        
        for i in 0..1000 {
            let key = format!("sk_client_test_{}", i);
            KeyValidator::validate_api_key_format(&key).unwrap();
        }
        
        let duration = start.elapsed();
        println!("Validated 1000 keys in {:?}", duration);
        
        // Should be very fast - less than 50ms for 1000 validations
        assert!(duration.as_millis() < 50);
    }

    #[tokio::test]
    async fn test_encryption_performance() {
        let start = Instant::now();
        let data = "test-data-for-encryption";
        let key = "test-key";
        
        for _ in 0..100 {
            let encrypted = KeyEncryption::encrypt_sensitive_data(data, key).unwrap();
            let _decrypted = KeyEncryption::decrypt_sensitive_data(&encrypted, key).unwrap();
        }
        
        let duration = start.elapsed();
        println!("Encrypted/decrypted 100 items in {:?}", duration);
        
        // Should be reasonably fast
        assert!(duration.as_millis() < 1000);
    }
}