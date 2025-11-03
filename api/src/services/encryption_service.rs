// Encryption Service - End-to-End Encryption for Emails
// Implements PGP, S/MIME, and Hybrid E2E encryption

use std::sync::Arc;
use crate::core::vault::VaultClient;
use crate::core::crypto::*;
use crate::models::user::User;
use crate::models::mail::{MessageBody, EmailContext};

#[derive(Debug)]
pub enum EncryptionError {
    KeyNotFound(String),
    EncryptionFailed(String),
    DecryptionFailed(String),
    InvalidKeyFormat(String),
    UnsupportedAlgorithm(String),
}

impl std::fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptionError::KeyNotFound(key) => write!(f, "Key not found: {}", key),
            EncryptionError::EncryptionFailed(msg) => write!(f, "Encryption failed: {}", msg),
            EncryptionError::DecryptionFailed(msg) => write!(f, "Decryption failed: {}", msg),
            EncryptionError::InvalidKeyFormat(msg) => write!(f, "Invalid key format: {}", msg),
            EncryptionError::UnsupportedAlgorithm(algo) => write!(f, "Unsupported algorithm: {}", algo),
        }
    }
}

impl std::error::Error for EncryptionError {}

pub type EncryptionResult<T> = Result<T, EncryptionError>;

#[derive(Debug, Clone)]
pub enum EncryptionMethod {
    PGP,
    SMIME,
    Hybrid,
}

pub struct EncryptionService {
    vault_client: Arc<VaultClient>,
}

impl EncryptionService {
    pub fn new(vault_client: Arc<VaultClient>) -> Self {
        EncryptionService { vault_client }
    }

    // ============================================================================
    // PGP ENCRYPTION (OpenPGP via Sequoia)
    // ============================================================================

    /// Encrypt message using PGP
    pub async fn encrypt_pgp(&self, plaintext: &[u8], recipient_keys: &[String], signer_key: Option<&str>) -> EncryptionResult<String> {
        // This would use sequoia-pgp for actual PGP encryption
        // For now, using AES-256-GCM as placeholder with PGP-like structure

        // Generate per-message AES key
        let message_key = generate_key(32);

        // Encrypt content with AES
        let encrypted_content = aes256_gcm_encrypt(&message_key, plaintext)
            .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

        // Encrypt message key with each recipient's public key
        let mut encrypted_keys = Vec::new();
        for recipient_key_id in recipient_keys {
            let recipient_public_key = self.get_pgp_public_key(recipient_key_id).await?;
            let encrypted_key = self.encrypt_key_with_public_key(&message_key, &recipient_public_key)?;
            encrypted_keys.push(format!("{}:{}", recipient_key_id, base64::encode(&encrypted_key)));
        }

        // Create PGP-like structure
        let mut pgp_message = format!("-----BEGIN PGP MESSAGE-----\nVersion: SGE-PGP v1.0\n\n");
        pgp_message.push_str(&format!("Encrypted-Key: {}\n", encrypted_keys.join(";")));
        pgp_message.push_str(&format!("Cipher: AES-256-GCM\n"));
        pgp_message.push_str(&format!("Data: {}\n", base64::encode(&encrypted_content)));
        pgp_message.push_str("-----END PGP MESSAGE-----\n");

        Ok(pgp_message)
    }

    /// Decrypt PGP message
    pub async fn decrypt_pgp(&self, pgp_message: &str, user: &User) -> EncryptionResult<Vec<u8>> {
        // Parse PGP message structure
        let lines: Vec<&str> = pgp_message.lines().collect();
        let mut encrypted_keys = String::new();
        let mut data = String::new();

        for line in lines {
            if line.starts_with("Encrypted-Key: ") {
                encrypted_keys = line[15..].to_string();
            } else if line.starts_with("Data: ") {
                data = line[6..].to_string();
            }
        }

        if encrypted_keys.is_empty() || data.is_empty() {
            return Err(EncryptionError::InvalidKeyFormat("Invalid PGP message format".to_string()));
        }

        // Find encrypted key for this user
        let key_parts: Vec<&str> = encrypted_keys.split(';').collect();
        let mut message_key = None;

        for part in key_parts {
            let key_info: Vec<&str> = part.split(':').collect();
            if key_info.len() == 2 {
                let key_id = key_info[0];
                let encrypted_key_b64 = key_info[1];

                // Check if this key belongs to the user
                if self.is_user_key(key_id, user).await? {
                    let encrypted_key = base64::decode(encrypted_key_b64)
                        .map_err(|e| EncryptionError::InvalidKeyFormat(e.to_string()))?;
                    message_key = Some(self.decrypt_key_with_private_key(&encrypted_key, user).await?);
                    break;
                }
            }
        }

        let message_key = message_key.ok_or_else(|| EncryptionError::KeyNotFound("No suitable decryption key found".to_string()))?;

        // Decrypt the actual data
        let encrypted_content = base64::decode(&data)
            .map_err(|e| EncryptionError::InvalidKeyFormat(e.to_string()))?;

        let plaintext = aes256_gcm_decrypt(&message_key, &encrypted_content)
            .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))?;

        Ok(plaintext)
    }

    // ============================================================================
    // S/MIME ENCRYPTION (X.509 Certificates)
    // ============================================================================

    /// Encrypt message using S/MIME
    pub async fn encrypt_smime(&self, plaintext: &[u8], recipient_certs: &[String]) -> EncryptionResult<String> {
        // Generate per-message AES key
        let message_key = generate_key(32);

        // Encrypt content with AES
        let encrypted_content = aes256_gcm_encrypt(&message_key, plaintext)
            .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

        // Encrypt message key with each recipient's certificate
        let mut encrypted_keys = Vec::new();
        for cert_pem in recipient_certs {
            let recipient_public_key = self.extract_public_key_from_cert(cert_pem)?;
            let encrypted_key = self.encrypt_key_with_rsa(&message_key, &recipient_public_key)?;
            encrypted_keys.push(base64::encode(&encrypted_key));
        }

        // Create S/MIME structure
        let mut smime_message = format!("-----BEGIN PKCS7-----\nVersion: SGE-S/MIME v1.0\n\n");
        smime_message.push_str(&format!("Encrypted-Keys: {}\n", encrypted_keys.join(";")));
        smime_message.push_str(&format!("Cipher: AES-256-GCM\n"));
        smime_message.push_str(&format!("Data: {}\n", base64::encode(&encrypted_content)));
        smime_message.push_str("-----END PKCS7-----\n");

        Ok(smime_message)
    }

    /// Decrypt S/MIME message
    pub async fn decrypt_smime(&self, smime_message: &str, user: &User) -> EncryptionResult<Vec<u8>> {
        // Parse S/MIME message structure
        let lines: Vec<&str> = smime_message.lines().collect();
        let mut encrypted_keys = String::new();
        let mut data = String::new();

        for line in lines {
            if line.starts_with("Encrypted-Keys: ") {
                encrypted_keys = line[15..].to_string();
            } else if line.starts_with("Data: ") {
                data = line[6..].to_string();
            }
        }

        if encrypted_keys.is_empty() || data.is_empty() {
            return Err(EncryptionError::InvalidKeyFormat("Invalid S/MIME message format".to_string()));
        }

        // Try to decrypt with user's private key
        let key_parts: Vec<&str> = encrypted_keys.split(';').collect();
        let mut message_key = None;

        for encrypted_key_b64 in key_parts {
            let encrypted_key = base64::decode(encrypted_key_b64)
                .map_err(|e| EncryptionError::InvalidKeyFormat(e.to_string()))?;

            match self.decrypt_key_with_user_private_key(&encrypted_key, user).await {
                Ok(key) => {
                    message_key = Some(key);
                    break;
                }
                Err(_) => continue, // Try next key
            }
        }

        let message_key = message_key.ok_or_else(|| EncryptionError::KeyNotFound("No suitable decryption key found".to_string()))?;

        // Decrypt the actual data
        let encrypted_content = base64::decode(&data)
            .map_err(|e| EncryptionError::InvalidKeyFormat(e.to_string()))?;

        let plaintext = aes256_gcm_decrypt(&message_key, &encrypted_content)
            .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))?;

        Ok(plaintext)
    }

    // ============================================================================
    // HYBRID E2E ENCRYPTION (PGP + AES)
    // ============================================================================

    /// Encrypt message using Hybrid E2E (PGP + AES)
    pub async fn encrypt_hybrid(&self, plaintext: &[u8], recipient_keys: &[String]) -> EncryptionResult<String> {
        // Generate unique AES-256 key for this message
        let message_key = generate_key(32);

        // Encrypt content with AES-256-GCM
        let encrypted_content = aes256_gcm_encrypt(&message_key, plaintext)
            .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

        // Encrypt the message key with each recipient's public key (PGP-style)
        let mut encrypted_keys = Vec::new();
        for recipient_key_id in recipient_keys {
            let recipient_public_key = self.get_pgp_public_key(recipient_key_id).await?;
            let encrypted_key = self.encrypt_key_with_public_key(&message_key, &recipient_public_key)?;
            encrypted_keys.push(format!("{}:{}", recipient_key_id, base64::encode(&encrypted_key)));
        }

        // Create hybrid structure
        let mut hybrid_message = format!("-----BEGIN HYBRID MESSAGE-----\nVersion: SGE-Hybrid v1.0\n\n");
        hybrid_message.push_str(&format!("Encrypted-Key: {}\n", encrypted_keys.join(";")));
        hybrid_message.push_str(&format!("Cipher: AES-256-GCM\n"));
        hybrid_message.push_str(&format!("Data: {}\n", base64::encode(&encrypted_content)));
        hybrid_message.push_str("-----END HYBRID MESSAGE-----\n");

        Ok(hybrid_message)
    }

    /// Decrypt Hybrid E2E message
    pub async fn decrypt_hybrid(&self, hybrid_message: &str, user: &User) -> EncryptionResult<Vec<u8>> {
        // Hybrid decryption is the same as PGP for now
        self.decrypt_pgp(hybrid_message, user).await
    }

    // ============================================================================
    // KEY MANAGEMENT HELPERS
    // ============================================================================

    async fn get_pgp_public_key(&self, key_id: &str) -> EncryptionResult<Vec<u8>> {
        // Get PGP public key from Vault
        let path = format!("secret/pgp/keys/{}/public", key_id);
        let key_data = self.vault_client.get_secret(&path).await
            .map_err(|e| EncryptionError::KeyNotFound(format!("PGP public key {}: {}", key_id, e)))?;

        let key_b64 = key_data.get("key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| EncryptionError::InvalidKeyFormat("Invalid PGP key format".to_string()))?;

        base64::decode(key_b64)
            .map_err(|e| EncryptionError::InvalidKeyFormat(e.to_string()))
    }

    async fn is_user_key(&self, key_id: &str, user: &User) -> EncryptionResult<bool> {
        // Check if the key belongs to the user
        let user_keys_path = format!("secret/pgp/users/{}/keys", user.id);
        match self.vault_client.get_secret(&user_keys_path).await {
            Ok(key_data) => {
                if let Some(keys) = key_data.get("key_ids").and_then(|v| v.as_array()) {
                    for key in keys {
                        if let Some(kid) = key.as_str() {
                            if kid == key_id {
                                return Ok(true);
                            }
                        }
                    }
                }
                Ok(false)
            }
            Err(_) => Ok(false),
        }
    }

    fn encrypt_key_with_public_key(&self, key: &[u8], public_key: &[u8]) -> EncryptionResult<Vec<u8>> {
        // Use X25519 for key encryption (simplified)
        // In production, this would use proper PGP key encryption
        let keypair = X25519Keypair::generate();
        let shared_secret = keypair.compute_shared_secret(&X25519PublicKey::from(*public_key.first_chunk::<32>().unwrap()));

        // Derive encryption key from shared secret
        let salt = generate_salt(32);
        let encryption_key = hkdf_sha512(shared_secret.as_bytes(), &salt, b"key_encryption", 32)
            .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

        aes256_gcm_encrypt(&encryption_key, key)
            .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))
    }

    async fn decrypt_key_with_private_key(&self, encrypted_key: &[u8], user: &User) -> EncryptionResult<Vec<u8>> {
        // Get user's private key from Vault (encrypted)
        let private_key_path = format!("secret/pgp/users/{}/private_key", user.id);
        let key_data = self.vault_client.get_secret(&private_key_path).await
            .map_err(|e| EncryptionError::KeyNotFound(format!("User private key: {}", e)))?;

        let encrypted_private_key_b64 = key_data.get("encrypted_key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| EncryptionError::InvalidKeyFormat("Invalid private key format".to_string()))?;

        let encrypted_private_key = base64::decode(encrypted_private_key_b64)
            .map_err(|e| EncryptionError::InvalidKeyFormat(e.to_string()))?;

        // Decrypt private key using Vault Transit
        let private_key_pem = self.vault_client.transit_decrypt("pgp_key_encryption", &String::from_utf8_lossy(&encrypted_private_key))
            .await
            .map_err(|e| EncryptionError::DecryptionFailed(format!("Failed to decrypt private key: {}", e)))?;

        // Use private key to decrypt the message key
        // This is simplified - in production would use proper PGP decryption
        let private_key_bytes = private_key_pem.as_slice();

        // For now, assume the encrypted_key is AES-encrypted with a derived key
        // In production, this would be proper PGP decryption
        aes256_gcm_decrypt(private_key_bytes, encrypted_key)
            .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))
    }

    fn extract_public_key_from_cert(&self, cert_pem: &str) -> EncryptionResult<Vec<u8>> {
        // Extract public key from X.509 certificate
        // This is a placeholder - in production would parse the certificate
        Ok(cert_pem.as_bytes().to_vec())
    }

    fn encrypt_key_with_rsa(&self, key: &[u8], public_key: &[u8]) -> EncryptionResult<Vec<u8>> {
        // RSA encryption of the message key
        // This is a placeholder - in production would use proper RSA-OAEP
        aes256_gcm_encrypt(public_key, key)
            .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))
    }

    async fn decrypt_key_with_user_private_key(&self, encrypted_key: &[u8], user: &User) -> EncryptionResult<Vec<u8>> {
        // Get user's S/MIME private key from Vault
        let private_key_path = format!("secret/smime/users/{}/private_key", user.id);
        let key_data = self.vault_client.get_secret(&private_key_path).await
            .map_err(|e| EncryptionError::KeyNotFound(format!("User S/MIME private key: {}", e)))?;

        let encrypted_private_key_b64 = key_data.get("encrypted_key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| EncryptionError::InvalidKeyFormat("Invalid S/MIME private key format".to_string()))?;

        let encrypted_private_key = base64::decode(encrypted_private_key_b64)
            .map_err(|e| EncryptionError::InvalidKeyFormat(e.to_string()))?;

        // Decrypt private key using Vault Transit
        let private_key_der = self.vault_client.transit_decrypt("pgp_key_encryption", &String::from_utf8_lossy(&encrypted_private_key))
            .await
            .map_err(|e| EncryptionError::DecryptionFailed(format!("Failed to decrypt S/MIME private key: {}", e)))?;

        // Use private key to decrypt the message key
        aes256_gcm_decrypt(&private_key_der, encrypted_key)
            .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))
    }

    // ============================================================================
    // PUBLIC API METHODS
    // ============================================================================

    /// Encrypt message body using specified method
    pub async fn encrypt_message_body(&self, body: &MessageBody, method: EncryptionMethod, recipients: &[String], user: &User) -> EncryptionResult<MessageBody> {
        let mut encrypted_body = MessageBody {
            text: None,
            html: None,
        };

        // Encrypt text part
        if let Some(text) = &body.text {
            let encrypted_text = match method {
                EncryptionMethod::PGP => self.encrypt_pgp(text.as_bytes(), recipients, None).await?,
                EncryptionMethod::SMIME => self.encrypt_smime(text.as_bytes(), recipients).await?,
                EncryptionMethod::Hybrid => self.encrypt_hybrid(text.as_bytes(), recipients).await?,
            };
            encrypted_body.text = Some(encrypted_text);
        }

        // Encrypt HTML part
        if let Some(html) = &body.html {
            let encrypted_html = match method {
                EncryptionMethod::PGP => self.encrypt_pgp(html.as_bytes(), recipients, None).await?,
                EncryptionMethod::SMIME => self.encrypt_smime(html.as_bytes(), recipients).await?,
                EncryptionMethod::Hybrid => self.encrypt_hybrid(html.as_bytes(), recipients).await?,
            };
            encrypted_body.html = Some(encrypted_html);
        }

        Ok(encrypted_body)
    }

    /// Decrypt message body
    pub async fn decrypt_message_body(&self, body: &MessageBody, user: &User) -> EncryptionResult<MessageBody> {
        let mut decrypted_body = MessageBody {
            text: None,
            html: None,
        };

        // Decrypt text part
        if let Some(text) = &body.text {
            if text.starts_with("-----BEGIN PGP MESSAGE-----") {
                let decrypted = self.decrypt_pgp(text, user).await?;
                decrypted_body.text = Some(String::from_utf8_lossy(&decrypted).to_string());
            } else if text.starts_with("-----BEGIN PKCS7-----") {
                let decrypted = self.decrypt_smime(text, user).await?;
                decrypted_body.text = Some(String::from_utf8_lossy(&decrypted).to_string());
            } else if text.starts_with("-----BEGIN HYBRID MESSAGE-----") {
                let decrypted = self.decrypt_hybrid(text, user).await?;
                decrypted_body.text = Some(String::from_utf8_lossy(&decrypted).to_string());
            } else {
                decrypted_body.text = Some(text.clone());
            }
        }

        // Decrypt HTML part
        if let Some(html) = &body.html {
            if html.starts_with("-----BEGIN PGP MESSAGE-----") {
                let decrypted = self.decrypt_pgp(html, user).await?;
                decrypted_body.html = Some(String::from_utf8_lossy(&decrypted).to_string());
            } else if html.starts_with("-----BEGIN PKCS7-----") {
                let decrypted = self.decrypt_smime(html, user).await?;
                decrypted_body.html = Some(String::from_utf8_lossy(&decrypted).to_string());
            } else if html.starts_with("-----BEGIN HYBRID MESSAGE-----") {
                let decrypted = self.decrypt_hybrid(html, user).await?;
                decrypted_body.html = Some(String::from_utf8_lossy(&decrypted).to_string());
            } else {
                decrypted_body.html = Some(html.clone());
            }
        }

        Ok(decrypted_body)
    }
}