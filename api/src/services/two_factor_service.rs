use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use chrono::{Utc, Duration};
use crate::core::vault::VaultClient;
use crate::models::user::User;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TwoFactorType {
    TOTP,        // Time-based One-Time Password (Google Authenticator, etc.)
    SMS,         // SMS verification
    Email,       // Email verification
    Recovery,    // Recovery codes
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwoFactorMethod {
    pub id: String,
    pub user_id: String,
    pub method_type: TwoFactorType,
    pub name: String,           // User-friendly name (e.g., "My Phone", "Work Email")
    pub identifier: String,     // Phone number, email, etc.
    pub secret: Option<String>, // TOTP secret (stored encrypted in Vault)
    pub is_enabled: bool,
    pub is_primary: bool,
    pub created_at: chrono::DateTime<Utc>,
    pub last_used: Option<chrono::DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TwoFactorSetupRequest {
    pub method_type: TwoFactorType,
    pub name: String,
    pub identifier: String, // Phone/email for SMS/Email, empty for TOTP
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorSetupResponse {
    pub method_id: String,
    pub method_type: TwoFactorType,
    pub provisioning_uri: Option<String>, // For TOTP setup
    pub qr_code_url: Option<String>,      // For TOTP setup
    pub verification_code: Option<String>, // For immediate verification
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TwoFactorVerificationRequest {
    pub method_id: String,
    pub code: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorChallengeResponse {
    pub challenge_id: String,
    pub user_id: String,
    pub methods: Vec<TwoFactorMethod>,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorChallengeValidationRequest {
    pub challenge_id: String,
    pub method_id: String,
    pub code: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorVerificationResponse {
    pub success: bool,
    pub method_type: TwoFactorType,
    pub recovery_codes: Option<Vec<String>>, // Generated during initial setup
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RecoveryCodes {
    pub codes: Vec<String>,
    pub generated_at: chrono::DateTime<Utc>,
}

pub struct TwoFactorService {
    vault_client: Arc<VaultClient>,
}

impl TwoFactorService {
    pub fn new(vault_client: Arc<VaultClient>) -> Self {
        TwoFactorService { vault_client }
    }

    pub async fn setup_two_factor(
        &self,
        user: &User,
        request: TwoFactorSetupRequest,
    ) -> Result<TwoFactorSetupResponse, Box<dyn std::error::Error>> {
        let method_id = Uuid::new_v4().to_string();

        let method = TwoFactorMethod {
            id: method_id.clone(),
            user_id: user.id.clone(),
            method_type: request.method_type.clone(),
            name: request.name,
            identifier: request.identifier.clone(),
            secret: None,
            is_enabled: false,
            is_primary: false,
            created_at: Utc::now(),
            last_used: None,
        };

        match request.method_type {
            TwoFactorType::TOTP => {
                self.setup_totp(&method).await
            }
            TwoFactorType::SMS => {
                self.setup_sms(&method).await
            }
            TwoFactorType::Email => {
                self.setup_email(&method).await
            }
            TwoFactorType::Recovery => {
                self.setup_recovery_codes(&method).await
            }
        }
    }

    async fn setup_totp(&self, method: &TwoFactorMethod) -> Result<TwoFactorSetupResponse, Box<dyn std::error::Error>> {
        // Generate TOTP secret
        let secret = self.generate_totp_secret();

        // Store secret in Vault
        let secret_path = format!("2fa/totp/{}/{}", method.user_id, method.id);
        self.vault_client.store_secret(&secret_path, &serde_json::to_value(&secret)?).await?;

        // Generate provisioning URI for QR code
        let issuer = "Sky Genesis Enterprise";
        let account_name = format!("{}:{}", issuer, method.user_id);
        let provisioning_uri = format!(
            "otpauth://totp/{}?secret={}&issuer={}",
            account_name, secret, issuer
        );

        let qr_code_url = format!(
            "https://api.qrserver.com/v1/create-qr-code/?size=200x200&data={}",
            urlencoding::encode(&provisioning_uri)
        );

        // Save method to Vault
        let method_path = format!("2fa/methods/{}/{}", method.user_id, method.id);
        self.vault_client.store_secret(&method_path, &serde_json::to_value(method)?).await?;

        Ok(TwoFactorSetupResponse {
            method_id: method.id.clone(),
            method_type: TwoFactorType::TOTP,
            provisioning_uri: Some(provisioning_uri),
            qr_code_url: Some(qr_code_url),
            verification_code: None,
        })
    }

    async fn setup_sms(&self, method: &TwoFactorMethod) -> Result<TwoFactorSetupResponse, Box<dyn std::error::Error>> {
        // Validate phone number format
        if !self.is_valid_phone_number(&method.identifier) {
            return Err("Invalid phone number format".into());
        }

        // Send verification code
        let verification_code = self.generate_verification_code();
        self.send_sms_verification(&method.identifier, &verification_code).await?;

        // Save method to Vault (without enabling until verified)
        let method_path = format!("2fa/methods/{}/{}", method.user_id, method.id);
        self.vault_client.store_secret(&method_path, &serde_json::to_value(method)?).await?;

        Ok(TwoFactorSetupResponse {
            method_id: method.id.clone(),
            method_type: TwoFactorType::SMS,
            provisioning_uri: None,
            qr_code_url: None,
            verification_code: Some(verification_code),
        })
    }

    async fn setup_email(&self, method: &TwoFactorMethod) -> Result<TwoFactorSetupResponse, Box<dyn std::error::Error>> {
        // Validate email format
        if !self.is_valid_email(&method.identifier) {
            return Err("Invalid email format".into());
        }

        // Send verification code
        let verification_code = self.generate_verification_code();
        self.send_email_verification(&method.identifier, &verification_code).await?;

        // Save method to Vault
        let method_path = format!("2fa/methods/{}/{}", method.user_id, method.id);
        self.vault_client.store_secret(&method_path, &serde_json::to_value(method)?).await?;

        Ok(TwoFactorSetupResponse {
            method_id: method.id.clone(),
            method_type: TwoFactorType::Email,
            provisioning_uri: None,
            qr_code_url: None,
            verification_code: Some(verification_code),
        })
    }

    async fn setup_recovery_codes(&self, method: &TwoFactorMethod) -> Result<TwoFactorSetupResponse, Box<dyn std::error::Error>> {
        // Generate recovery codes
        let codes = self.generate_recovery_codes();

        // Store codes in Vault
        let codes_path = format!("2fa/recovery/{}/{}", method.user_id, method.id);
        let recovery_data = RecoveryCodes {
            codes: codes.clone(),
            generated_at: Utc::now(),
        };
        self.vault_client.store_secret(&codes_path, &serde_json::to_value(&recovery_data)?).await?;

        // Save method to Vault
        let method_path = format!("2fa/methods/{}/{}", method.user_id, method.id);
        self.vault_client.store_secret(&method_path, &serde_json::to_value(method)?).await?;

        Ok(TwoFactorSetupResponse {
            method_id: method.id.clone(),
            method_type: TwoFactorType::Recovery,
            provisioning_uri: None,
            qr_code_url: None,
            verification_code: None,
        })
    }

    pub async fn verify_two_factor(
        &self,
        user: &User,
        request: TwoFactorVerificationRequest,
    ) -> Result<TwoFactorVerificationResponse, Box<dyn std::error::Error>> {
        // Get method from Vault
        let method_path = format!("2fa/methods/{}/{}", user.id, request.method_id);
        let method_data: serde_json::Value = self.vault_client.get_secret(&method_path).await?;
        let mut method: TwoFactorMethod = serde_json::from_value(method_data)?;

        let success = match method.method_type {
            TwoFactorType::TOTP => {
                self.verify_totp(&method, &request.code).await?
            }
            TwoFactorType::SMS => {
                self.verify_sms_code(&method, &request.code).await?
            }
            TwoFactorType::Email => {
                self.verify_email_code(&method, &request.code).await?
            }
            TwoFactorType::Recovery => {
                self.verify_recovery_code(&method, &request.code).await?
            }
        };

        if success {
            // Enable method if not already enabled
            if !method.is_enabled {
                method.is_enabled = true;
                self.vault_client.store_secret(&method_path, &serde_json::to_value(&method)?).await?;
            }

            // Update last used
            method.last_used = Some(Utc::now());
            self.vault_client.store_secret(&method_path, &serde_json::to_value(&method)?).await?;

            // Generate recovery codes for initial setup
            let recovery_codes = if matches!(method.method_type, TwoFactorType::TOTP | TwoFactorType::SMS | TwoFactorType::Email) && !method.is_enabled {
                Some(self.generate_recovery_codes())
            } else {
                None
            };

            Ok(TwoFactorVerificationResponse {
                success: true,
                method_type: method.method_type,
                recovery_codes,
            })
        } else {
            Ok(TwoFactorVerificationResponse {
                success: false,
                method_type: method.method_type,
                recovery_codes: None,
            })
        }
    }

    pub async fn get_user_two_factor_methods(&self, user_id: &str) -> Result<Vec<TwoFactorMethod>, Box<dyn std::error::Error>> {
        // In production, this would query a database or use Vault's list functionality
        // For now, return empty list (to be implemented)
        Ok(vec![])
    }

    pub async fn remove_two_factor_method(&self, user_id: &str, method_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        // Remove from Vault
        let method_path = format!("2fa/methods/{}/{}", user_id, method_id);
        let secret_path = format!("2fa/totp/{}/{}", user_id, method_id);
        let recovery_path = format!("2fa/recovery/{}/{}", user_id, method_id);

        // These are fire-and-forget in a real implementation
        let _ = self.vault_client.delete_secret(&method_path).await;
        let _ = self.vault_client.delete_secret(&secret_path).await;
        let _ = self.vault_client.delete_secret(&recovery_path).await;

        Ok(())
    }

    pub async fn is_two_factor_required_for_application(&self, application_id: &str) -> Result<bool, Box<dyn std::error::Error>> {
        // Check if application requires 2FA
        let defaults = load_defaults_from_env_example();
        let required_key = format!("{}_REQUIRES_2FA", application_id.to_uppercase().replace("-", "_"));
        Ok(defaults.get(&required_key).map(|v| v == "true").unwrap_or(false))
    }

    pub async fn user_has_two_factor_enabled(&self, user_id: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let methods = self.get_user_two_factor_methods(user_id).await?;
        Ok(!methods.is_empty())
    }

    pub async fn create_2fa_challenge(&self, user_id: &str) -> Result<TwoFactorChallengeResponse, Box<dyn std::error::Error>> {
        let methods = self.get_user_two_factor_methods(user_id).await?;
        let enabled_methods: Vec<TwoFactorMethod> = methods.into_iter()
            .filter(|m| m.is_enabled)
            .collect();

        if enabled_methods.is_empty() {
            return Err("No 2FA methods enabled".into());
        }

        let challenge_id = Uuid::new_v4().to_string();

        // Store challenge temporarily (in production, use Redis/cache)
        // For now, we'll store in Vault with expiration
        let challenge_path = format!("2fa/challenges/{}", challenge_id);
        let challenge_data = serde_json::json!({
            "user_id": user_id,
            "created_at": Utc::now().timestamp(),
            "expires_at": (Utc::now() + Duration::minutes(5)).timestamp()
        });

        self.vault.store_secret(&challenge_path, &challenge_data).await?;

        Ok(TwoFactorChallengeResponse {
            challenge_id,
            user_id: user_id.to_string(),
            methods: enabled_methods,
            message: "Two-factor authentication required".to_string(),
        })
    }

    pub async fn validate_2fa_challenge(&self, request: TwoFactorChallengeValidationRequest) -> Result<bool, Box<dyn std::error::Error>> {
        // Verify challenge exists and is valid
        let challenge_path = format!("2fa/challenges/{}", request.challenge_id);
        let challenge_data: serde_json::Value = self.vault.get_secret(&challenge_path).await?;

        let user_id = challenge_data["user_id"].as_str()
            .ok_or("Invalid challenge")?;
        let expires_at = challenge_data["expires_at"].as_i64()
            .ok_or("Invalid challenge")?;

        if Utc::now().timestamp() > expires_at {
            return Err("Challenge expired".into());
        }

        // Validate the 2FA code
        let verification_request = TwoFactorVerificationRequest {
            method_id: request.method_id,
            code: request.code,
        };

        // We need the user object, but we have user_id
        // For now, create a minimal user object
        let user = User {
            id: user_id.to_string(),
            email: "temp@example.com".to_string(), // This should be fetched properly
            first_name: None,
            last_name: None,
            roles: vec![],
            created_at: Utc::now(),
            enabled: true,
        };

        let result = self.verify_two_factor(&user, verification_request).await?;

        // Clean up challenge
        self.vault.delete_secret(&challenge_path).await?;

        Ok(result.success)
    }

    // Helper methods
    fn generate_totp_secret(&self) -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let secret: String = (0..32)
            .map(|_| {
                let idx = rng.gen_range(0..32);
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".chars().nth(idx).unwrap()
            })
            .collect();
        secret
    }

    fn generate_verification_code(&self) -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        format!("{:06}", rng.gen_range(0..1000000))
    }

    fn generate_recovery_codes(&self) -> Vec<String> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..10)
            .map(|_| {
                let code: String = (0..10)
                    .map(|_| rng.gen_range(0..10).to_string())
                    .collect();
                format!("{}-{}", &code[0..5], &code[5..10])
            })
            .collect()
    }

    async fn verify_totp(&self, method: &TwoFactorMethod, code: &str) -> Result<bool, Box<dyn std::error::Error>> {
        // Get secret from Vault
        let secret_path = format!("2fa/totp/{}/{}", method.user_id, method.id);
        let secret_data: serde_json::Value = self.vault_client.get_secret(&secret_path).await?;
        let secret: String = serde_json::from_value(secret_data)?;

        // Verify TOTP code
        // This is a simplified implementation - in production use a proper TOTP library
        let expected_code = self.generate_totp_code(&secret, Utc::now().timestamp() / 30);
        Ok(code == expected_code)
    }

    fn generate_totp_code(&self, secret: &str, time_step: i64) -> String {
        // Simplified TOTP implementation - use a proper library in production
        use hmac::{Hmac, Mac};
        use sha1::Sha1;

        let key = base32::decode(base32::Alphabet::RFC4648 { padding: false }, secret).unwrap_or_default();
        let mut mac = Hmac::<Sha1>::new_from_slice(&key).unwrap();
        mac.update(&time_step.to_be_bytes());
        let result = mac.finalize().into_bytes();

        let offset = (result[19] & 0xf) as usize;
        let code = ((result[offset] as u32 & 0x7f) << 24)
            | ((result[offset + 1] as u32) << 16)
            | ((result[offset + 2] as u32) << 8)
            | (result[offset + 3] as u32);

        format!("{:06}", code % 1000000)
    }

    async fn verify_sms_code(&self, _method: &TwoFactorMethod, code: &str) -> Result<bool, Box<dyn std::error::Error>> {
        // In production, verify against stored code with expiration
        Ok(code.len() == 6 && code.chars().all(|c| c.is_numeric()))
    }

    async fn verify_email_code(&self, _method: &TwoFactorMethod, code: &str) -> Result<bool, Box<dyn std::error::Error>> {
        // In production, verify against stored code with expiration
        Ok(code.len() == 6 && code.chars().all(|c| c.is_numeric()))
    }

    async fn verify_recovery_code(&self, method: &TwoFactorMethod, code: &str) -> Result<bool, Box<dyn std::error::Error>> {
        // Get recovery codes from Vault
        let codes_path = format!("2fa/recovery/{}/{}", method.user_id, method.id);
        let codes_data: serde_json::Value = self.vault_client.get_secret(&codes_path).await?;
        let mut recovery_data: RecoveryCodes = serde_json::from_value(codes_data)?;

        // Check if code exists and remove it (one-time use)
        if let Some(pos) = recovery_data.codes.iter().position(|c| c == code) {
            recovery_data.codes.remove(pos);
            self.vault_client.store_secret(&codes_path, &serde_json::to_value(&recovery_data)?).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn send_sms_verification(&self, phone_number: &str, code: &str) -> Result<(), Box<dyn std::error::Error>> {
        // In production, integrate with SMS service (Twilio, AWS SNS, etc.)
        println!("Sending SMS verification code {} to {}", code, phone_number);
        Ok(())
    }

    async fn send_email_verification(&self, email: &str, code: &str) -> Result<(), Box<dyn std::error::Error>> {
        // In production, integrate with email service
        println!("Sending email verification code {} to {}", code, email);
        Ok(())
    }

    fn is_valid_phone_number(&self, phone: &str) -> bool {
        // Basic phone validation - use a proper library in production
        phone.len() >= 10 && phone.chars().all(|c| c.is_numeric() || c == '+' || c == '-' || c == ' ')
    }

    fn is_valid_email(&self, email: &str) -> bool {
        // Basic email validation
        email.contains('@') && email.contains('.')
    }
}

// Function to load default values from .env.example
fn load_defaults_from_env_example() -> std::collections::HashMap<String, String> {
    let mut defaults = std::collections::HashMap::new();

    // Read .env.example file
    if let Ok(content) = std::fs::read_to_string(".env.example") {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                defaults.insert(key.to_string(), value.to_string());
            }
        }
    }

    defaults
}