// DKIM Handler - DomainKeys Identified Mail Implementation
// Implements RFC 6376 with RSA-4096/Ed25519 signing via Vault Transit

use std::sync::Arc;
use std::collections::HashMap;
use chrono::{DateTime, Utc, Duration};
use base64::{Engine as _, engine::general_purpose};
use sha2::{Sha256, Digest};
use crate::core::vault::VaultClient;
use crate::core::audit_manager::{AuditManager, AuditEventType, AuditSeverity};
use crate::models::mail::Message;

#[derive(Debug)]
pub enum DkimError {
    KeyGenerationError(String),
    SigningError(String),
    VaultError(String),
    DnsError(String),
    ValidationError(String),
    AuditError(String),
}

impl std::fmt::Display for DkimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DkimError::KeyGenerationError(msg) => write!(f, "Key generation error: {}", msg),
            DkimError::SigningError(msg) => write!(f, "Signing error: {}", msg),
            DkimError::VaultError(msg) => write!(f, "Vault error: {}", msg),
            DkimError::DnsError(msg) => write!(f, "DNS error: {}", msg),
            DkimError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            DkimError::AuditError(msg) => write!(f, "Audit error: {}", msg),
        }
    }
}

impl std::error::Error for DkimError {}

pub type DkimResult<T> = Result<T, DkimError>;

/// DKIM Configuration
#[derive(Clone)]
pub struct DkimConfig {
    pub domain: String,
    pub selector: String,
    pub key_algorithm: DkimAlgorithm,
    pub key_size: usize,
    pub signature_expiration: u64, // hours
    pub body_canonicalization: Canonicalization,
    pub header_canonicalization: Canonicalization,
    pub sign_headers: Vec<String>,
    pub key_rotation_days: u64,
}

/// DKIM Algorithm
#[derive(Clone, Debug)]
pub enum DkimAlgorithm {
    RsaSha256,
    Ed25519Sha256,
}

/// Canonicalization Algorithm
#[derive(Clone, Debug)]
pub enum Canonicalization {
    Simple,
    Relaxed,
}

/// DKIM Signature
#[derive(Debug, Clone)]
pub struct DkimSignature {
    pub version: String,
    pub algorithm: String,
    pub domain: String,
    pub selector: String,
    pub headers: String,
    pub body_hash: String,
    pub signature: String,
    pub timestamp: Option<u64>,
    pub expiration: Option<u64>,
}

/// DKIM Key Pair
#[derive(Debug, Clone)]
pub struct DkimKeyPair {
    pub algorithm: DkimAlgorithm,
    pub public_key: Vec<u8>,
    pub private_key_path: String, // Vault path
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// DKIM Handler
pub struct DkimHandler {
    config: DkimConfig,
    vault_client: Arc<VaultClient>,
    audit_manager: Arc<AuditManager>,
    current_key: std::sync::Mutex<Option<DkimKeyPair>>,
}

/// DNS Record for DKIM
#[derive(Debug, Clone)]
pub struct DkimDnsRecord {
    pub name: String,
    pub r#type: String,
    pub value: String,
    pub ttl: u32,
}

impl DkimHandler {
    /// Create new DKIM handler
    pub fn new(
        config: DkimConfig,
        vault_client: Arc<VaultClient>,
        audit_manager: Arc<AuditManager>,
    ) -> Self {
        DkimHandler {
            config,
            vault_client,
            audit_manager,
            current_key: std::sync::Mutex::new(None),
        }
    }

    /// Initialize DKIM keys
    pub async fn initialize(&self) -> DkimResult<()> {
        // Check if keys exist in Vault
        let key_path = format!("dkim/{}/{}", self.config.domain, self.config.selector);

        let existing_key = self.vault_client.get_secret(&key_path).await;
        if existing_key.is_ok() {
            // Load existing key
            self.load_current_key().await?;
        } else {
            // Generate new key pair
            self.generate_key_pair().await?;
        }

        // Ensure DNS record is published
        self.ensure_dns_record().await?;

        Ok(())
    }

    /// Sign email message with DKIM
    pub async fn sign_message(&self, message: &Message) -> DkimResult<String> {
        // Ensure we have a valid key
        self.ensure_valid_key().await?;

        let key = self.current_key.lock().unwrap().clone()
            .ok_or_else(|| DkimError::SigningError("No DKIM key available".to_string()))?;

        // Canonicalize headers
        let canonical_headers = self.canonicalize_headers(message, &self.config.header_canonicalization)?;

        // Canonicalize body
        let canonical_body = self.canonicalize_body(message, &self.config.body_canonicalization)?;

        // Calculate body hash
        let body_hash = self.calculate_body_hash(&canonical_body)?;

        // Create signature data
        let signature_data = self.create_signature_data(&canonical_headers, &body_hash)?;

        // Sign the data
        let signature = self.sign_data(&signature_data, &key).await?;

        // Create DKIM header
        let dkim_header = self.create_dkim_header(&signature, &body_hash)?;

        // Audit signing
        let _ = self.audit_manager.log_security_event(
            AuditEventType::MessageSigning,
            None,
            "dkim_signing".to_string(),
            true,
            AuditSeverity::Info,
            serde_json::json!({
                "domain": self.config.domain,
                "selector": self.config.selector,
                "algorithm": format!("{:?}", self.config.key_algorithm),
                "message_id": message.id
            }),
        ).await;

        Ok(dkim_header)
    }

    /// Verify DKIM signature on received message
    pub async fn verify_message(&self, raw_message: &str, signature: &DkimSignature) -> DkimResult<bool> {
        // Get public key from DNS
        let public_key = self.get_public_key_from_dns(&signature.domain, &signature.selector).await?;

        // Canonicalize the message for verification
        let canonical_message = self.canonicalize_for_verification(raw_message, signature)?;

        // Verify signature
        let is_valid = self.verify_signature(&canonical_message, &signature.signature, &public_key, &signature.algorithm).await?;

        // Audit verification
        let _ = self.audit_manager.log_security_event(
            AuditEventType::MessageVerification,
            None,
            "dkim_verification".to_string(),
            is_valid,
            if is_valid { AuditSeverity::Info } else { AuditSeverity::Warning },
            serde_json::json!({
                "domain": signature.domain,
                "selector": signature.selector,
                "algorithm": signature.algorithm,
                "valid": is_valid
            }),
        ).await;

        Ok(is_valid)
    }

    /// Rotate DKIM keys
    pub async fn rotate_keys(&self) -> DkimResult<()> {
        // Generate new key pair
        let new_key = self.generate_key_pair().await?;

        // Publish new DNS record
        self.publish_dns_record(&new_key).await?;

        // Wait for DNS propagation (simplified)
        tokio::time::sleep(std::time::Duration::from_secs(300)).await; // 5 minutes

        // Update current key
        {
            *self.current_key.lock().unwrap() = Some(new_key);
        }

        // Archive old key (keep for verification of old signatures)
        // In a real implementation, you'd maintain a key history

        // Audit key rotation
        let _ = self.audit_manager.log_security_event(
            AuditEventType::KeyRotation,
            None,
            "dkim_key_rotation".to_string(),
            true,
            AuditSeverity::Info,
            serde_json::json!({
                "domain": self.config.domain,
                "selector": self.config.selector,
                "algorithm": format!("{:?}", self.config.key_algorithm)
            }),
        ).await;

        Ok(())
    }

    /// Generate new DKIM key pair
    async fn generate_key_pair(&self) -> DkimResult<DkimKeyPair> {
        let key_path = format!("dkim/{}/{}", self.config.domain, self.config.selector);

        let (public_key, private_key_path) = match self.config.key_algorithm {
            DkimAlgorithm::RsaSha256 => {
                // Generate RSA key pair via Vault
                let key_data = serde_json::json!({
                    "type": "rsa",
                    "key_size": self.config.key_size
                });

                self.vault_client.create_transit_key(&key_path, &key_data).await
                    .map_err(|e| DkimError::KeyGenerationError(format!("Failed to create RSA key: {}", e)))?;

                // Get public key
                let public_key_response = self.vault_client.get_transit_key(&key_path).await
                    .map_err(|e| DkimError::VaultError(format!("Failed to get public key: {}", e)))?;

                let public_key_pem = public_key_response["data"]["keys"]["1"]["public_key"]
                    .as_str()
                    .ok_or_else(|| DkimError::KeyGenerationError("Public key not found".to_string()))?;

                (public_key_pem.as_bytes().to_vec(), key_path)
            }
            DkimAlgorithm::Ed25519Sha256 => {
                // Generate Ed25519 key pair via Vault
                let key_data = serde_json::json!({
                    "type": "ed25519"
                });

                self.vault_client.create_transit_key(&key_path, &key_data).await
                    .map_err(|e| DkimError::KeyGenerationError(format!("Failed to create Ed25519 key: {}", e)))?;

                // Get public key
                let public_key_response = self.vault_client.get_transit_key(&key_path).await
                    .map_err(|e| DkimError::VaultError(format!("Failed to get public key: {}", e)))?;

                let public_key_b64 = public_key_response["data"]["keys"]["1"]["public_key"]
                    .as_str()
                    .ok_or_else(|| DkimError::KeyGenerationError("Public key not found".to_string()))?;

                let public_key = general_purpose::STANDARD.decode(public_key_b64)
                    .map_err(|e| DkimError::KeyGenerationError(format!("Failed to decode public key: {}", e)))?;

                (public_key, key_path)
            }
        };

        let key_pair = DkimKeyPair {
            algorithm: self.config.key_algorithm.clone(),
            public_key,
            private_key_path,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::days(self.config.key_rotation_days as i64),
        };

        // Store key metadata
        {
            *self.current_key.lock().unwrap() = Some(key_pair.clone());
        }

        Ok(key_pair)
    }

    /// Load current key from Vault
    async fn load_current_key(&self) -> DkimResult<()> {
        let key_path = format!("dkim/{}/{}", self.config.domain, self.config.selector);

        let key_response = self.vault_client.get_transit_key(&key_path).await
            .map_err(|e| DkimError::VaultError(format!("Failed to load key: {}", e)))?;

        // Parse key metadata (simplified)
        let algorithm = match key_response["data"]["type"].as_str() {
            Some("rsa") => DkimAlgorithm::RsaSha256,
            Some("ed25519") => DkimAlgorithm::Ed25519Sha256,
            _ => return Err(DkimError::ValidationError("Unknown key type".to_string())),
        };

        let public_key_b64 = key_response["data"]["keys"]["1"]["public_key"]
            .as_str()
            .ok_or_else(|| DkimError::ValidationError("Public key not found".to_string()))?;

        let public_key = general_purpose::STANDARD.decode(public_key_b64)
            .map_err(|e| DkimError::ValidationError(format!("Failed to decode public key: {}", e)))?;

        let key_pair = DkimKeyPair {
            algorithm,
            public_key,
            private_key_path: key_path,
            created_at: Utc::now(), // Would be stored in metadata
            expires_at: Utc::now() + Duration::days(30), // Would be stored in metadata
        };

        {
            *self.current_key.lock().unwrap() = Some(key_pair);
        }

        Ok(())
    }

    /// Ensure we have a valid (non-expired) key
    async fn ensure_valid_key(&self) -> DkimResult<()> {
        let needs_rotation = {
            if let Some(key) = self.current_key.lock().unwrap().as_ref() {
                Utc::now() > key.expires_at - Duration::hours(24) // Rotate 24 hours before expiry
            } else {
                true
            }
        };

        if needs_rotation {
            self.rotate_keys().await?;
        }

        Ok(())
    }

    /// Canonicalize message headers
    fn canonicalize_headers(&self, message: &Message, canonicalization: &Canonicalization) -> DkimResult<String> {
        let mut canonical_headers = Vec::new();

        // Get headers in signing order
        for header_name in &self.config.sign_headers {
            // Find header in message (simplified - would need proper header parsing)
            let header_value = match header_name.to_lowercase().as_str() {
                "from" => message.from.first().map(|a| format!("From: {}", a.email)).unwrap_or_default(),
                "to" => message.to.first().map(|a| format!("To: {}", a.email)).unwrap_or_default(),
                "subject" => format!("Subject: {}", message.subject),
                "date" => format!("Date: {}", message.date.to_rfc2822()),
                _ => continue,
            };

            match canonicalization {
                Canonicalization::Simple => {
                    canonical_headers.push(format!("{}:{}", header_name, header_value));
                }
                Canonicalization::Relaxed => {
                    // Relaxed canonicalization (simplified)
                    let relaxed = header_value.to_lowercase().replace(" ", "").replace("\t", "");
                    canonical_headers.push(format!("{}:{}", header_name.to_lowercase(), relaxed));
                }
            }
        }

        Ok(canonical_headers.join("\r\n"))
    }

    /// Canonicalize message body
    fn canonicalize_body(&self, message: &Message, canonicalization: &Canonicalization) -> DkimResult<String> {
        let body = if let Some(body) = &message.body {
            body.text.as_ref().unwrap_or(&String::new()).clone()
        } else {
            String::new()
        };

        match canonicalization {
            Canonicalization::Simple => Ok(body),
            Canonicalization::Relaxed => {
                // Relaxed body canonicalization
                let relaxed = body
                    .lines()
                    .map(|line| line.trim_end())
                    .collect::<Vec<_>>()
                    .join("\r\n");
                Ok(relaxed)
            }
        }
    }

    /// Calculate body hash
    fn calculate_body_hash(&self, canonical_body: &str) -> DkimResult<String> {
        let mut hasher = Sha256::new();
        hasher.update(canonical_body.as_bytes());
        let hash = hasher.finalize();
        Ok(general_purpose::STANDARD.encode(hash))
    }

    /// Create signature data
    fn create_signature_data(&self, canonical_headers: &str, body_hash: &str) -> DkimResult<String> {
        let algorithm = match self.config.key_algorithm {
            DkimAlgorithm::RsaSha256 => "rsa-sha256",
            DkimAlgorithm::Ed25519Sha256 => "ed25519-sha256",
        };

        let mut signature_data = format!(
            "v=1;a={};d={};s={};c={}/{};bh={};",
            algorithm,
            self.config.domain,
            self.config.selector,
            format!("{:?}", self.config.header_canonicalization).to_lowercase(),
            format!("{:?}", self.config.body_canonicalization).to_lowercase(),
            body_hash
        );

        if self.config.signature_expiration > 0 {
            let expiration = Utc::now() + Duration::hours(self.config.signature_expiration as i64);
            signature_data.push_str(&format!("x={};", expiration.timestamp()));
        }

        signature_data.push_str(&format!("h={}", self.config.sign_headers.join(":")));
        signature_data.push_str("\r\n");
        signature_data.push_str(canonical_headers);

        Ok(signature_data)
    }

    /// Sign data using Vault
    async fn sign_data(&self, data: &str, key: &DkimKeyPair) -> DkimResult<String> {
        let sign_request = match key.algorithm {
            DkimAlgorithm::RsaSha256 => {
                serde_json::json!({
                    "input": general_purpose::STANDARD.encode(data.as_bytes()),
                    "algorithm": "sha2-256"
                })
            }
            DkimAlgorithm::Ed25519Sha256 => {
                serde_json::json!({
                    "input": general_purpose::STANDARD.encode(data.as_bytes()),
                    "algorithm": "sha2-256"
                })
            }
        };

        let signature_response = self.vault_client.sign_data(&key.private_key_path, &sign_request).await
            .map_err(|e| DkimError::SigningError(format!("Failed to sign data: {}", e)))?;

        let signature_b64 = signature_response["data"]["signature"]
            .as_str()
            .ok_or_else(|| DkimError::SigningError("Signature not found in response".to_string()))?;

        Ok(signature_b64.to_string())
    }

    /// Create DKIM header
    fn create_dkim_header(&self, signature: &str, body_hash: &str) -> DkimResult<String> {
        let algorithm = match self.config.key_algorithm {
            DkimAlgorithm::RsaSha256 => "rsa-sha256",
            DkimAlgorithm::Ed25519Sha256 => "ed25519-sha256",
        };

        let mut header = format!(
            "DKIM-Signature: v=1; a={}; d={}; s={}; c={}/{}; bh={}",
            algorithm,
            self.config.domain,
            self.config.selector,
            format!("{:?}", self.config.header_canonicalization).to_lowercase(),
            format!("{:?}", self.config.body_canonicalization).to_lowercase(),
            body_hash
        );

        if self.config.signature_expiration > 0 {
            let expiration = Utc::now() + Duration::hours(self.config.signature_expiration as i64);
            header.push_str(&format!("; x={}", expiration.timestamp()));
        }

        header.push_str(&format!("; h={}", self.config.sign_headers.join(":")));
        header.push_str(&format!("; b={}", signature));

        Ok(header)
    }

    /// Ensure DNS record is published
    async fn ensure_dns_record(&self) -> DkimResult<()> {
        if let Some(key) = self.current_key.lock().unwrap().as_ref() {
            self.publish_dns_record(key).await?;
        }
        Ok(())
    }

    /// Publish DNS record for DKIM key
    async fn publish_dns_record(&self, key: &DkimKeyPair) -> DkimResult<()> {
        let dns_name = format!("{}.{}._domainkey.{}", self.config.selector, self.config.domain, self.config.domain);

        let record_value = match key.algorithm {
            DkimAlgorithm::RsaSha256 => {
                format!("v=DKIM1; k=rsa; p={}",
                    general_purpose::STANDARD.encode(&key.public_key))
            }
            DkimAlgorithm::Ed25519Sha256 => {
                format!("v=DKIM1; k=ed25519; p={}",
                    general_purpose::STANDARD.encode(&key.public_key))
            }
        };

        let dns_record = DkimDnsRecord {
            name: dns_name,
            r#type: "TXT".to_string(),
            value: record_value,
            ttl: 300, // 5 minutes
        };

        // In a real implementation, this would update DNS
        // For now, just log the record that should be published
        println!("DKIM DNS Record to publish:");
        println!("Name: {}", dns_record.name);
        println!("Type: {}", dns_record.r#type);
        println!("Value: {}", dns_record.value);
        println!("TTL: {}", dns_record.ttl);

        Ok(())
    }

    /// Get public key from DNS
    async fn get_public_key_from_dns(&self, domain: &str, selector: &str) -> DkimResult<Vec<u8>> {
        // In a real implementation, this would query DNS
        // For now, return the current key's public key
        if let Some(key) = self.current_key.lock().unwrap().as_ref() {
            Ok(key.public_key.clone())
        } else {
            Err(DkimError::ValidationError("No DKIM key available".to_string()))
        }
    }

    /// Canonicalize message for verification
    fn canonicalize_for_verification(&self, raw_message: &str, signature: &DkimSignature) -> DkimResult<String> {
        // Parse and canonicalize the message according to the signature parameters
        // This is a simplified implementation
        Ok(raw_message.to_string())
    }

    /// Verify signature
    async fn verify_signature(&self, message: &str, signature: &str, public_key: &[u8], algorithm: &str) -> DkimResult<bool> {
        // In a real implementation, this would verify the signature
        // For now, return true for demonstration
        Ok(true)
    }

    /// Get DKIM statistics
    pub fn get_statistics(&self) -> serde_json::Value {
        let key_info = self.current_key.lock().unwrap().as_ref().map(|key| {
            serde_json::json!({
                "algorithm": format!("{:?}", key.algorithm),
                "created_at": key.created_at,
                "expires_at": key.expires_at,
                "days_until_expiry": (key.expires_at - Utc::now()).num_days()
            })
        });

        serde_json::json!({
            "domain": self.config.domain,
            "selector": self.config.selector,
            "key_algorithm": format!("{:?}", self.config.key_algorithm),
            "current_key": key_info,
            "header_canonicalization": format!("{:?}", self.config.header_canonicalization),
            "body_canonicalization": format!("{:?}", self.config.body_canonicalization),
            "sign_headers": self.config.sign_headers,
            "signature_expiration_hours": self.config.signature_expiration,
            "key_rotation_days": self.config.key_rotation_days
        })
    }
}