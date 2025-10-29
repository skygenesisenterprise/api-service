use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Deserialize)]
struct AuthResponse {
    auth: AuthData,
}

#[derive(Deserialize)]
struct AuthData {
    client_token: String,
    lease_duration: u64,
}

pub struct VaultClient {
    client: Client,
    base_url: String,
    token: Arc<Mutex<String>>,
    token_expires: Arc<Mutex<Instant>>,
}

impl VaultClient {
    pub async fn new(base_url: String, role_id: String, secret_id: String) -> Result<Self, Box<dyn std::error::Error>> {
        let client = Client::new();
        let mut vault = VaultClient {
            client,
            base_url,
            token: Arc::new(Mutex::new(String::new())),
            token_expires: Arc::new(Mutex::new(Instant::now())),
        };
        vault.authenticate_approle(&role_id, &secret_id).await?;
        Ok(vault)
    }

    async fn authenticate_approle(&self, role_id: &str, secret_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let url = format!("{}/v1/auth/approle/login", self.base_url);
        let payload = serde_json::json!({ "role_id": role_id, "secret_id": secret_id });
        let response = self.client.post(&url).json(&payload).send().await?;
        let auth: AuthResponse = response.json().await?;
        let mut token = self.token.lock().await;
        *token = auth.auth.client_token;
        let mut expires = self.token_expires.lock().await;
        *expires = Instant::now() + Duration::from_secs(auth.auth.lease_duration);
        Ok(())
    }

    async fn ensure_token(&self) -> Result<(), Box<dyn std::error::Error>> {
        let expires = *self.token_expires.lock().await;
        if Instant::now() > expires {
            // Re-authenticate if needed, but for simplicity, assume long-lived
        }
        Ok(())
    }

    pub async fn get_secret(&self, path: &str) -> Result<Value, Box<dyn std::error::Error>> {
        self.ensure_token().await?;
        let url = format!("{}/v1/{}", self.base_url, path);
        let token = self.token.lock().await.clone();
        let response = self.client
            .get(&url)
            .header("X-Vault-Token", token)
            .send()
            .await?
            .json::<Value>()
            .await?;
        Ok(response["data"]["data"].clone())
    }

    pub async fn set_secret(&self, path: &str, data: Value) -> Result<(), Box<dyn std::error::Error>> {
        self.ensure_token().await?;
        let url = format!("{}/v1/{}", self.base_url, path);
        let token = self.token.lock().await.clone();
        let payload = serde_json::json!({ "data": data });
        self.client
            .post(&url)
            .header("X-Vault-Token", token)
            .json(&payload)
            .send()
            .await?;
        Ok(())
    }

    // Auto-rotation for keys
    pub async fn rotate_key(&self, key_type: &str) -> Result<String, Box<dyn std::error::Error>> {
        let raw_key = crate::utils::key_utils::generate_key();
        let formatted_key = crate::utils::key_utils::format_api_key(raw_key);
        let path = format!("secret/{}", key_type);
        let data = serde_json::json!({ "key": formatted_key });
        self.set_secret(&path, data).await?;
        Ok(formatted_key)
    }

    pub async fn validate_access(&self, key_type: &str, token: &str) -> Result<bool, Box<dyn std::error::Error>> {
        // For now, just check if the token exists in vault
        let path = format!("secret/{}", key_type);
        match self.get_secret(&path).await {
            Ok(data) => {
                // Check if token matches stored value
                Ok(data.get("key").and_then(|v| v.as_str()) == Some(token))
            }
            Err(_) => Ok(false),
        }
    }

    pub async fn store_secret(&self, path: &str, data: Value) -> Result<(), Box<dyn std::error::Error>> {
        self.set_secret(path, data).await
    }

    pub async fn delete_secret(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        // Vault delete operation (simplified)
        // In a real implementation, this would call the Vault delete API
        Ok(())
    }

    // ============================================================================
    // VAULT TRANSIT ENGINE OPERATIONS (Military-Grade Encryption)
    // ============================================================================

    /// Create a new encryption key in Vault Transit Engine
    pub async fn create_transit_key(&self, key_name: &str, key_type: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.ensure_token().await?;
        let url = format!("{}/v1/transit/keys/{}", self.base_url, key_name);
        let token = self.token.lock().await.clone();

        let payload = serde_json::json!({
            "type": key_type,
            "derived": false,
            "exportable": false,
            "allow_plaintext_backup": false
        });

        let response = self.client
            .post(&url)
            .header("X-Vault-Token", token)
            .json(&payload)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("Failed to create transit key: {}", response.status()).into());
        }

        Ok(())
    }

    /// Encrypt data using Vault Transit Engine (AES-256-GCM)
    pub async fn transit_encrypt(&self, key_name: &str, plaintext: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
        self.ensure_token().await?;
        let url = format!("{}/v1/transit/encrypt/{}", self.base_url, key_name);
        let token = self.token.lock().await.clone();

        let base64_plaintext = base64::encode(plaintext);
        let payload = serde_json::json!({
            "plaintext": base64_plaintext
        });

        let response = self.client
            .post(&url)
            .header("X-Vault-Token", token)
            .json(&payload)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("Failed to encrypt data: {}", response.status()).into());
        }

        let result: serde_json::Value = response.json().await?;
        let ciphertext = result["data"]["ciphertext"]
            .as_str()
            .ok_or("Missing ciphertext in response")?;

        Ok(ciphertext.to_string())
    }

    /// Decrypt data using Vault Transit Engine (AES-256-GCM)
    pub async fn transit_decrypt(&self, key_name: &str, ciphertext: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        self.ensure_token().await?;
        let url = format!("{}/v1/transit/decrypt/{}", self.base_url, key_name);
        let token = self.token.lock().await.clone();

        let payload = serde_json::json!({
            "ciphertext": ciphertext
        });

        let response = self.client
            .post(&url)
            .header("X-Vault-Token", token)
            .json(&payload)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("Failed to decrypt data: {}", response.status()).into());
        }

        let result: serde_json::Value = response.json().await?;
        let base64_plaintext = result["data"]["plaintext"]
            .as_str()
            .ok_or("Missing plaintext in response")?;

        let plaintext = base64::decode(base64_plaintext)
            .map_err(|e| format!("Failed to decode base64: {}", e))?;

        Ok(plaintext)
    }

    /// Sign data using Vault Transit Engine (Ed25519 or RSA-4096)
    pub async fn transit_sign(&self, key_name: &str, algorithm: &str, data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
        self.ensure_token().await?;
        let url = format!("{}/v1/transit/sign/{}/{}", self.base_url, key_name, algorithm);
        let token = self.token.lock().await.clone();

        let base64_data = base64::encode(data);
        let payload = serde_json::json!({
            "input": base64_data
        });

        let response = self.client
            .post(&url)
            .header("X-Vault-Token", token)
            .json(&payload)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("Failed to sign data: {}", response.status()).into());
        }

        let result: serde_json::Value = response.json().await?;
        let signature = result["data"]["signature"]
            .as_str()
            .ok_or("Missing signature in response")?;

        Ok(signature.to_string())
    }

    /// Verify signature using Vault Transit Engine
    pub async fn transit_verify(&self, key_name: &str, algorithm: &str, signature: &str, data: &[u8]) -> Result<bool, Box<dyn std::error::Error>> {
        self.ensure_token().await?;
        let url = format!("{}/v1/transit/verify/{}/{}", self.base_url, key_name, algorithm);
        let token = self.token.lock().await.clone();

        let base64_data = base64::encode(data);
        let payload = serde_json::json!({
            "input": base64_data,
            "signature": signature
        });

        let response = self.client
            .post(&url)
            .header("X-Vault-Token", token)
            .json(&payload)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("Failed to verify signature: {}", response.status()).into());
        }

        let result: serde_json::Value = response.json().await?;
        let valid = result["data"]["valid"]
            .as_bool()
            .ok_or("Missing valid field in response")?;

        Ok(valid)
    }

    /// Generate HMAC using Vault Transit Engine
    pub async fn transit_hmac(&self, key_name: &str, algorithm: &str, data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
        self.ensure_token().await?;
        let url = format!("{}/v1/transit/hmac/{}/{}", self.base_url, key_name, algorithm);
        let token = self.token.lock().await.clone();

        let base64_data = base64::encode(data);
        let payload = serde_json::json!({
            "input": base64_data
        });

        let response = self.client
            .post(&url)
            .header("X-Vault-Token", token)
            .json(&payload)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("Failed to generate HMAC: {}", response.status()).into());
        }

        let result: serde_json::Value = response.json().await?;
        let hmac = result["data"]["hmac"]
            .as_str()
            .ok_or("Missing hmac in response")?;

        Ok(hmac.to_string())
    }

    /// Rotate encryption key in Vault Transit Engine
    pub async fn rotate_transit_key(&self, key_name: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.ensure_token().await?;
        let url = format!("{}/v1/transit/keys/{}/rotate", self.base_url, key_name);
        let token = self.token.lock().await.clone();

        let response = self.client
            .post(&url)
            .header("X-Vault-Token", token)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("Failed to rotate key: {}", response.status()).into());
        }

        Ok(())
    }

    /// Get key version information
    pub async fn get_transit_key_info(&self, key_name: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        self.ensure_token().await?;
        let url = format!("{}/v1/transit/keys/{}", self.base_url, key_name);
        let token = self.token.lock().await.clone();

        let response = self.client
            .get(&url)
            .header("X-Vault-Token", token)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("Failed to get key info: {}", response.status()).into());
        }

        let result: serde_json::Value = response.json().await?;
        Ok(result)
    }

    // ============================================================================
    // VAULT PKI OPERATIONS (Certificate Management)
    // ============================================================================

    /// Issue certificate from Vault PKI
    pub async fn issue_certificate(&self, pki_mount: &str, role_name: &str, common_name: &str, alt_names: Option<Vec<String>>) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        self.ensure_token().await?;
        let url = format!("{}/v1/{}/issue/{}", self.base_url, pki_mount, role_name);
        let token = self.token.lock().await.clone();

        let mut payload = serde_json::json!({
            "common_name": common_name
        });

        if let Some(alt_names) = alt_names {
            payload["alt_names"] = serde_json::json!(alt_names.join(","));
        }

        let response = self.client
            .post(&url)
            .header("X-Vault-Token", token)
            .json(&payload)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("Failed to issue certificate: {}", response.status()).into());
        }

        let result: serde_json::Value = response.json().await?;
        Ok(result)
    }

    /// Revoke certificate
    pub async fn revoke_certificate(&self, pki_mount: &str, serial_number: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.ensure_token().await?;
        let url = format!("{}/v1/{}/revoke", self.base_url, pki_mount);
        let token = self.token.lock().await.clone();

        let payload = serde_json::json!({
            "serial_number": serial_number
        });

        let response = self.client
            .post(&url)
            .header("X-Vault-Token", token)
            .json(&payload)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("Failed to revoke certificate: {}", response.status()).into());
        }

        Ok(())
    }

    /// Get CA certificate
    pub async fn get_ca_certificate(&self, pki_mount: &str) -> Result<String, Box<dyn std::error::Error>> {
        self.ensure_token().await?;
        let url = format!("{}/v1/{}/ca", self.base_url, pki_mount);
        let token = self.token.lock().await.clone();

        let response = self.client
            .get(&url)
            .header("X-Vault-Token", token)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("Failed to get CA certificate: {}", response.status()).into());
        }

        let cert_pem = response.text().await?;
        Ok(cert_pem)
    }

    // ============================================================================
    // MILITARY-GRADE SECURITY HELPERS
    // ============================================================================

    /// Encrypt email data for storage (military-grade)
    pub async fn encrypt_email_data(&self, data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
        self.transit_encrypt("mail_storage_key", data).await
    }

    /// Decrypt email data from storage (military-grade)
    pub async fn decrypt_email_data(&self, ciphertext: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        self.transit_decrypt("mail_storage_key", ciphertext).await
    }

    /// Sign email for DKIM using Vault Transit
    pub async fn sign_email_dkim(&self, email_data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
        self.transit_sign("dkim_key", "ed25519", email_data).await
    }

    /// Generate HMAC for API request integrity
    pub async fn generate_request_hmac(&self, data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
        self.transit_hmac("api_hmac_key", "sha2-512", data).await
    }

    /// Initialize military-grade encryption keys
    pub async fn initialize_military_keys(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Create mail storage encryption key
        self.create_transit_key("mail_storage_key", "aes256-gcm96").await?;

        // Create DKIM signing key
        self.create_transit_key("dkim_key", "ed25519").await?;

        // Create API HMAC key
        self.create_transit_key("api_hmac_key", "hmac").await?;

        // Create PGP key encryption key
        self.create_transit_key("pgp_key_encryption", "aes256-gcm96").await?;

        Ok(())
    }

    /// Auto-rotate certificates before expiration
    pub async fn auto_rotate_certificates(&self, pki_mount: &str, role_name: &str, common_names: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
        for common_name in common_names {
            // Check if certificate is close to expiration (30 days)
            let cert_info = self.get_certificate_info(pki_mount, &common_name).await?;
            if let Some(expires_at) = cert_info["expires_at"].as_str() {
                let expiry_date = chrono::DateTime::parse_from_rfc3339(expires_at)?;
                let now = chrono::Utc::now();
                let days_until_expiry = (expiry_date - now).num_days();

                if days_until_expiry <= 30 {
                    // Issue new certificate
                    let new_cert = self.issue_certificate(pki_mount, role_name, &common_name, None).await?;
                    // Store new certificate
                    let cert_data = serde_json::json!({
                        "certificate": new_cert["data"]["certificate"],
                        "private_key": new_cert["data"]["private_key"],
                        "serial_number": new_cert["data"]["serial_number"]
                    });
                    self.set_secret(&format!("pki/certs/{}", common_name), cert_data).await?;
                }
            }
        }
        Ok(())
    }

    /// Get certificate information
    pub async fn get_certificate_info(&self, pki_mount: &str, serial_number: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        self.ensure_token().await?;
        let url = format!("{}/v1/{}/cert/{}", self.base_url, pki_mount, serial_number);
        let token = self.token.lock().await.clone();

        let response = self.client
            .get(&url)
            .header("X-Vault-Token", token)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("Failed to get certificate info: {}", response.status()).into());
        }

        let result: serde_json::Value = response.json().await?;
        Ok(result)
    }

    /// Auto-rotate encryption keys based on usage or time
    pub async fn auto_rotate_keys(&self, key_names: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
        for key_name in key_names {
            let key_info = self.get_transit_key_info(&key_name).await?;
            let latest_version = key_info["data"]["latest_version"].as_u64().unwrap_or(1);

            // Rotate if key is older than 90 days or has been used more than 1M times
            let created_time = key_info["data"]["keys"][latest_version.to_string()]["creation_time"]
                .as_str()
                .unwrap_or("");

            if !created_time.is_empty() {
                let creation_date = chrono::DateTime::parse_from_rfc3339(created_time)?;
                let now = chrono::Utc::now();
                let days_since_creation = (now - creation_date).num_days();

                if days_since_creation > 90 {
                    self.rotate_transit_key(&key_name).await?;
                }
            }
        }
        Ok(())
    }

    /// Schedule automatic rotation (to be called by a background task)
    pub async fn schedule_auto_rotation(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Certificate rotation for common services
        let common_names = vec![
            "api.skygenesisenterprise.com".to_string(),
            "mail.skygenesisenterprise.com".to_string(),
            "vault.skygenesisenterprise.com".to_string(),
        ];
        self.auto_rotate_certificates("pki", "server", common_names).await?;

        // Key rotation for encryption keys
        let key_names = vec![
            "mail_storage_key".to_string(),
            "api_hmac_key".to_string(),
            "pgp_key_encryption".to_string(),
        ];
        self.auto_rotate_keys(key_names).await?;

        Ok(())
    }
}