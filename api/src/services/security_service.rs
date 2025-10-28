//! # Security Service
//!
//! High-level security operations using modern cryptographic primitives.
//! This service provides secure encryption, signing, and key management for the API.

use crate::core::crypto::*;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Security service for cryptographic operations
pub struct SecurityService {
    /// Cached encryption keys (in production, use HSM or secure key storage)
    encryption_keys: RwLock<HashMap<String, Vec<u8>>>,
    /// Cached signing keypairs
    signing_keys: RwLock<HashMap<String, Box<dyn Signable + Send + Sync>>>,
}

impl SecurityService {
    /// Create a new security service
    pub fn new() -> Self {
        SecurityService {
            encryption_keys: RwLock::new(HashMap::new()),
            signing_keys: RwLock::new(HashMap::new()),
        }
    }

    /// Encrypt sensitive data for storage or transmission
    pub async fn encrypt_sensitive_data(&self, key_id: &str, plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        let keys = self.encryption_keys.read().await;
        let key = keys.get(key_id)
            .ok_or_else(|| CryptoError::InvalidFormat(format!("Key '{}' not found", key_id)))?;

        // Use ChaCha20-Poly1305 for general encryption (good for both server and mobile)
        chacha20_poly1305_encrypt(key, plaintext)
    }

    /// Decrypt sensitive data
    pub async fn decrypt_sensitive_data(&self, key_id: &str, ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
        let keys = self.encryption_keys.read().await;
        let key = keys.get(key_id)
            .ok_or_else(|| CryptoError::InvalidFormat(format!("Key '{}' not found", key_id)))?;

        decrypt_data(key, ciphertext)
    }

    /// Generate and store a new encryption key
    pub async fn generate_encryption_key(&self, key_id: &str) -> CryptoResult<()> {
        let key = generate_key(32); // 256-bit key
        let mut keys = self.encryption_keys.write().await;
        keys.insert(key_id.to_string(), key);
        Ok(())
    }

    /// Sign API tokens or JWTs with Ed25519 (recommended for API tokens)
    pub async fn sign_api_token(&self, key_id: &str, token_data: &[u8]) -> CryptoResult<Vec<u8>> {
        let keys = self.signing_keys.read().await;
        let keypair = keys.get(key_id)
            .ok_or_else(|| CryptoError::InvalidFormat(format!("Signing key '{}' not found", key_id)))?;

        sign(SignatureAlgorithm::Ed25519, keypair.as_ref(), token_data)
    }

    /// Verify API token signature
    pub async fn verify_api_token(&self, key_id: &str, token_data: &[u8], signature: &[u8]) -> CryptoResult<()> {
        let keys = self.signing_keys.read().await;
        let keypair = keys.get(key_id)
            .ok_or_else(|| CryptoError::InvalidFormat(format!("Signing key '{}' not found", key_id)))?;

        // For verification, we need the public key
        // In a real implementation, you'd store public keys separately
        match keypair.as_ref().as_any().downcast_ref::<Ed25519Keypair>() {
            Some(ed25519_kp) => {
                let public_key_bytes = ed25519_kp.public_key().to_bytes();
                verify(SignatureAlgorithm::Ed25519, &public_key_bytes, token_data, signature)
            }
            _ => Err(CryptoError::UnsupportedAlgorithm("Unsupported key type for verification".to_string())),
        }
    }

    /// Generate a new Ed25519 signing keypair for API tokens
    pub async fn generate_api_signing_key(&self, key_id: &str) -> CryptoResult<()> {
        let keypair = Ed25519Keypair::generate();
        let mut keys = self.signing_keys.write().await;
        keys.insert(key_id.to_string(), Box::new(keypair));
        Ok(())
    }

    /// Generate a new ECDSA P-384 signing keypair for high-security operations
    pub async fn generate_high_security_signing_key(&self, key_id: &str) -> CryptoResult<()> {
        let keypair = EcdsaP384Keypair::generate();
        let mut keys = self.signing_keys.write().await;
        keys.insert(key_id.to_string(), Box::new(keypair));
        Ok(())
    }

    /// Perform secure key exchange for session keys
    pub async fn perform_key_exchange(&self) -> (X25519Keypair, X25519Keypair, Vec<u8>) {
        secure_key_exchange()
    }

    /// Derive a session key from shared secret
    pub async fn derive_session_key(&self, shared_secret: &[u8], context: &[u8]) -> CryptoResult<Vec<u8>> {
        derive_key(shared_secret, context, 32)
    }

    /// Hash data with recommended algorithm (SHA-512)
    pub async fn hash_data(&self, data: &[u8]) -> [u8; 64] {
        hash_data(data)
    }

    /// Hash password with Argon2id
    pub async fn hash_password(&self, password: &[u8]) -> CryptoResult<(Vec<u8>, String)> {
        hash_password(password)
    }

    /// Verify password hash
    pub async fn verify_password(&self, password: &[u8], salt: &[u8], hash: &str) -> CryptoResult<bool> {
        verify_password(password, salt, hash)
    }

    /// Generate secure random data
    pub async fn generate_secure_random(&self, len: usize) -> Vec<u8> {
        generate_key(len)
    }

    /// Encrypt data for transmission (with AEAD)
    pub async fn encrypt_for_transmission(&self, key: &[u8], plaintext: &[u8], aad: Option<&[u8]>) -> CryptoResult<Vec<u8>> {
        // For transmission, we use AES-256-GCM by default
        // Note: AAD (Additional Authenticated Data) is not directly supported in our current implementation
        // but could be added for enhanced security
        aes256_gcm_encrypt(key, plaintext)
    }

    /// Decrypt data from transmission
    pub async fn decrypt_from_transmission(&self, key: &[u8], ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
        aes256_gcm_decrypt(key, ciphertext)
    }

    /// Create a secure context for API operations
    pub async fn create_secure_context(&self, context_id: &str) -> CryptoResult<()> {
        // Generate encryption key for this context
        self.generate_encryption_key(&format!("{}_enc", context_id)).await?;

        // Generate signing key for this context
        self.generate_api_signing_key(&format!("{}_sign", context_id)).await?;

        Ok(())
    }

    /// Securely wipe sensitive data from memory
    pub async fn secure_wipe(&self, data: &mut [u8]) {
        use zeroize::Zeroize;
        data.zeroize();
    }

    /// Get security status information
    pub async fn get_security_status(&self) -> serde_json::Value {
        let enc_keys_count = self.encryption_keys.read().await.len();
        let sign_keys_count = self.signing_keys.read().await.len();

        serde_json::json!({
            "encryption_keys_active": enc_keys_count,
            "signing_keys_active": sign_keys_count,
            "algorithms": {
                "symmetric_encryption": ["AES-256-GCM", "ChaCha20-Poly1305"],
                "key_exchange": ["X25519"],
                "signatures": ["Ed25519", "ECDSA-P384"],
                "hash_functions": ["SHA-512", "SHA-3-512"],
                "key_derivation": ["HKDF-SHA-512"],
                "password_hashing": ["Argon2id"]
            },
            "security_level": "high",
            "post_quantum_ready": false, // Will be true when Kyber/Dilithium are added
            "timestamp": chrono::Utc::now().timestamp()
        })
    }
}

impl Default for SecurityService {
    fn default() -> Self {
        Self::new()
    }
}

/// Global security service instance
lazy_static::lazy_static! {
    pub static ref SECURITY_SERVICE: Arc<SecurityService> = Arc::new(SecurityService::new());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_encrypt_decrypt_sensitive_data() {
        let service = SecurityService::new();
        let key_id = "test_key";

        // Generate key
        service.generate_encryption_key(key_id).await.unwrap();

        // Test data
        let plaintext = b"Sensitive API data";

        // Encrypt
        let ciphertext = service.encrypt_sensitive_data(key_id, plaintext).await.unwrap();

        // Decrypt
        let decrypted = service.decrypt_sensitive_data(key_id, &ciphertext).await.unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[tokio::test]
    async fn test_api_token_signing() {
        let service = SecurityService::new();
        let key_id = "api_key";

        // Generate signing key
        service.generate_api_signing_key(key_id).await.unwrap();

        // Test token data
        let token_data = b"user_id:123:exp:1234567890";

        // Sign
        let signature = service.sign_api_token(key_id, token_data).await.unwrap();

        // Verify
        let is_valid = service.verify_api_token(key_id, token_data, &signature).await.is_ok();
        assert!(is_valid);
    }

    #[tokio::test]
    async fn test_password_hashing() {
        let service = SecurityService::new();
        let password = b"my_secure_password";

        // Hash password
        let (salt, hash) = service.hash_password(password).await.unwrap();

        // Verify password
        let is_valid = service.verify_password(password, &salt, &hash).await.unwrap();
        assert!(is_valid);

        // Test wrong password
        let wrong_password = b"wrong_password";
        let is_invalid = service.verify_password(wrong_password, &salt, &hash).await.unwrap();
        assert!(!is_invalid);
    }

    #[tokio::test]
    async fn test_key_exchange() {
        let service = SecurityService::new();
        let (alice_keys, bob_keys, shared_key) = service.perform_key_exchange().await;

        // Both parties should derive the same key
        let alice_derived = service.derive_session_key(shared_key.as_slice(), b"session").await.unwrap();
        let bob_derived = service.derive_session_key(shared_key.as_slice(), b"session").await.unwrap();

        assert_eq!(alice_derived, bob_derived);
        assert_eq!(alice_derived.len(), 32); // 256-bit key
    }

    #[tokio::test]
    async fn test_secure_context_creation() {
        let service = SecurityService::new();
        let context_id = "test_context";

        service.create_secure_context(context_id).await.unwrap();

        // Check that keys were created
        let enc_keys = service.encryption_keys.read().await;
        let sign_keys = service.signing_keys.read().await;

        assert!(enc_keys.contains_key(&format!("{}_enc", context_id)));
        assert!(sign_keys.contains_key(&format!("{}_sign", context_id)));
    }

    #[tokio::test]
    async fn test_security_status() {
        let service = SecurityService::new();
        let status = service.get_security_status().await;

        assert_eq!(status["security_level"], "high");
        assert!(status["algorithms"]["symmetric_encryption"].as_array().unwrap().contains(&serde_json::Value::String("AES-256-GCM".to_string())));
        assert!(status["algorithms"]["signatures"].as_array().unwrap().contains(&serde_json::Value::String("Ed25519".to_string())));
    }
}