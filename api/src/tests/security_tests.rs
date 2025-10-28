#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::security_service::SecurityService;
    use warp::http::StatusCode;
    use warp::test::request;

    #[tokio::test]
    async fn test_security_status_endpoint() {
        let routes = crate::routes::security_routes::security_routes();

        let resp = request()
            .method("GET")
            .path("/api/v1/security/status")
            .reply(&routes)
            .await;

        assert_eq!(resp.status(), StatusCode::OK);

        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        assert_eq!(body["security_level"], "high");
        assert!(body["algorithms"]["symmetric_encryption"].as_array().unwrap().len() > 0);
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_flow() {
        let service = SecurityService::new();

        // Generate key
        service.generate_encryption_key("test_key").await.unwrap();

        // Test data
        let original_data = b"Secret message for encryption test";
        let encoded_data = base64::encode(original_data);

        // Simulate API call data
        let encrypt_request = serde_json::json!({
            "key_id": "test_key",
            "data": encoded_data
        });

        // Encrypt
        let ciphertext = service.encrypt_sensitive_data("test_key", original_data).await.unwrap();
        let encoded_ciphertext = base64::encode(&ciphertext);

        // Decrypt
        let decrypted_data = service.decrypt_sensitive_data("test_key", &ciphertext).await.unwrap();

        assert_eq!(original_data, decrypted_data.as_slice());
    }

    #[tokio::test]
    async fn test_signing_flow() {
        let service = SecurityService::new();

        // Generate signing key
        service.generate_api_signing_key("test_signing_key").await.unwrap();

        // Test data
        let data = b"Data to sign for testing";
        let encoded_data = base64::encode(data);

        // Sign
        let signature = service.sign_api_token("test_signing_key", data).await.unwrap();
        let encoded_signature = base64::encode(&signature);

        // Verify
        let is_valid = service.verify_api_token("test_signing_key", data, &signature).await.is_ok();
        assert!(is_valid);
    }

    #[tokio::test]
    async fn test_password_hashing_flow() {
        let service = SecurityService::new();

        let password = "test_password_123";

        // Hash password
        let (salt, hash) = service.hash_password(password.as_bytes()).await.unwrap();

        // Verify password
        let is_valid = service.verify_password(password.as_bytes(), &salt, &hash).await.unwrap();
        assert!(is_valid);

        // Test wrong password
        let wrong_password = "wrong_password";
        let is_invalid = service.verify_password(wrong_password.as_bytes(), &salt, &hash).await.unwrap();
        assert!(!is_invalid);
    }

    #[tokio::test]
    async fn test_key_exchange_flow() {
        let service = SecurityService::new();

        let (alice_keys, bob_keys, shared_key) = service.perform_key_exchange().await;

        // Both parties should be able to derive the same key
        let alice_derived = service.derive_session_key(&shared_key, b"test_context").await.unwrap();
        let bob_derived = service.derive_session_key(&shared_key, b"test_context").await.unwrap();

        assert_eq!(alice_derived, bob_derived);
        assert_eq!(alice_derived.len(), 32); // 256-bit key
    }

    #[tokio::test]
    async fn test_hash_data() {
        let service = SecurityService::new();

        let data = b"Hello, World!";
        let hash1 = service.hash_data(data).await;
        let hash2 = service.hash_data(data).await;

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA-512 produces 64 bytes
    }

    #[tokio::test]
    async fn test_secure_random_generation() {
        let service = SecurityService::new();

        let random1 = service.generate_secure_random(32).await;
        let random2 = service.generate_secure_random(32).await;

        // Random data should be different
        assert_ne!(random1, random2);
        assert_eq!(random1.len(), 32);
        assert_eq!(random2.len(), 32);
    }

    #[tokio::test]
    async fn test_secure_context_creation() {
        let service = SecurityService::new();

        let context_id = "test_context";
        service.create_secure_context(context_id).await.unwrap();

        // Check that both encryption and signing keys were created
        let enc_keys = service.encryption_keys.read().await;
        let sign_keys = service.signing_keys.read().await;

        assert!(enc_keys.contains_key(&format!("{}_enc", context_id)));
        assert!(sign_keys.contains_key(&format!("{}_sign", context_id)));
    }

    #[tokio::test]
    async fn test_secure_wipe() {
        let service = SecurityService::new();

        let mut sensitive_data = vec![1, 2, 3, 4, 5];
        let original_data = sensitive_data.clone();

        service.secure_wipe(&mut sensitive_data).await;

        // Data should be zeroed out
        assert_ne!(sensitive_data, original_data);
        assert!(sensitive_data.iter().all(|&x| x == 0));
    }

    #[tokio::test]
    async fn test_multiple_key_types() {
        let service = SecurityService::new();

        // Generate different types of keys
        service.generate_encryption_key("enc_key").await.unwrap();
        service.generate_api_signing_key("ed25519_key").await.unwrap();
        service.generate_high_security_signing_key("ecdsa_key").await.unwrap();

        // Test encryption
        let test_data = b"Test data";
        let encrypted = service.encrypt_sensitive_data("enc_key", test_data).await.unwrap();
        let decrypted = service.decrypt_sensitive_data("enc_key", &encrypted).await.unwrap();
        assert_eq!(test_data, decrypted.as_slice());

        // Test Ed25519 signing
        let signature = service.sign_api_token("ed25519_key", test_data).await.unwrap();
        let is_valid = service.verify_api_token("ed25519_key", test_data, &signature).await.is_ok();
        assert!(is_valid);
    }

    #[tokio::test]
    async fn test_error_handling() {
        let service = SecurityService::new();

        // Test with non-existent key
        let result = service.encrypt_sensitive_data("non_existent_key", b"test").await;
        assert!(result.is_err());

        // Test signing with non-existent key
        let result = service.sign_api_token("non_existent_key", b"test").await;
        assert!(result.is_err());
    }
}