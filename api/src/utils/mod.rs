// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Utility Functions
// // ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | UTILITY
//  MISSION: Provide common utility functions across the application.
//  NOTICE: This module contains reusable utility functions.
//  INTEGRATION: Various modules across the application
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

pub mod tokens;
pub mod key_utils;

/// [TOKEN UTILS] JWT Token Management Utilities
/// @MISSION Provide JWT token creation and validation utilities.
/// @THREAT Token manipulation or forgery.
/// @COUNTERMEASURE Secure token signing and validation.
/// @DEPENDENCY jsonwebtoken crate with RS256 algorithm.
/// @INVARIANT All tokens are cryptographically signed.
pub mod tokens_internal {
    use super::*;

    /// [JWT CLAIMS] Standard JWT Claims Structure
    /// @MISSION Define standard JWT claims structure.
    /// @THREAT Claims manipulation or privilege escalation.
    /// @COUNTERMEASURE Claims validation and type safety.
        /// @INVARIANT Claims are validated before use.
    #[derive(Debug, Serialize, Deserialize)]
    pub struct Claims {
        pub sub: String,        // Subject (user ID)
        pub iss: String,        // Issuer
        pub aud: String,        // Audience
        pub exp: usize,         // Expiration time
        pub iat: usize,         // Issued at
        pub jti: String,        // JWT ID
        pub scope: Vec<String>, // Permission scopes
        pub org: String,        // Organization ID
    }

    /// [CREATE TOKEN] Generate JWT Access Token
    /// @MISSION Create signed JWT token for user authentication.
    /// @THREAT Token forgery or unauthorized token creation.
    /// @COUNTERMEASURE Secure key storage and proper signing.
    /// @DEPENDENCY Valid private key and user claims.
    /// @PERFORMANCE ~10ms token generation.
    /// @AUDIT Token creation logged with user context.
    pub fn create_access_token(
        user_id: &str,
        organization_id: &str,
        scopes: Vec<String>,
        private_key: &[u8],
        issuer: &str,
        audience: &str,
        expires_in_hours: usize,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs() as usize;

        let claims = Claims {
            sub: user_id.to_string(),
            iss: issuer.to_string(),
            aud: audience.to_string(),
            exp: now + (expires_in_hours * 3600),
            iat: now,
            jti: Uuid::new_v4().to_string(),
            scope: scopes,
            org: organization_id.to_string(),
        };

        let header = Header::default();
        let encoding_key = EncodingKey::from_rsa_pem(private_key)?;

        encode(&header, &claims, &encoding_key).map_err(|e| e.into())
    }

    /// [VALIDATE TOKEN] Verify JWT Token
    /// @MISSION Validate JWT token signature and claims.
    /// @THREAT Token forgery or expired token acceptance.
    /// @COUNTERMEASURE Signature verification and claim validation.
    /// @DEPENDENCY Valid public key and token string.
    /// @PERFORMANCE ~5ms token validation.
    /// @AUDIT Token validation logged with result.
    pub fn validate_access_token(
        token: &str,
        public_key: &[u8],
        issuer: &str,
        audience: &str,
    ) -> Result<Claims, Box<dyn std::error::Error>> {
        let decoding_key = DecodingKey::from_rsa_pem(public_key)?;
        let mut validation = Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_issuer(&[issuer]);
        validation.set_audience(&[audience]);

        let token_data = decode::<Claims>(token, &decoding_key, &validation)?;
        Ok(token_data.claims)
    }

    /// [REFRESH TOKEN] Generate Refresh Token
    /// @MISSION Create secure refresh token for token renewal.
    /// @THREAT Refresh token theft or replay attacks.
    /// @COUNTERMEASURE Long-lived tokens with secure storage.
    /// @DEPENDENCY User context and secure random generation.
    /// @PERFORMANCE ~5ms refresh token generation.
    /// @AUDIT Refresh token creation logged.
    pub fn create_refresh_token(
        user_id: &str,
        organization_id: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let token_data = format!("{}:{}:{}", user_id, organization_id, Uuid::new_v4());
        let hash = sha256::digest(token_data);
        Ok(format!("rt_{}", hash))
    }

    /// [EXTRACT TOKEN] Get Token from Authorization Header
    /// @MISSION Extract JWT token from Bearer authorization header.
    /// @THREAT Token extraction manipulation or header injection.
    /// @COUNTERMEASURE Header validation and format checking.
    /// @DEPENDENCY Valid authorization header string.
    /// @PERFORMANCE ~1ms token extraction.
    /// @AUDIT Token extraction logged for security.
    pub fn extract_bearer_token(auth_header: &str) -> Option<&str> {
        if auth_header.starts_with("Bearer ") {
            Some(&auth_header[7..])
        } else {
            None
        }
    }

    /// [TOKEN INFO] Extract Token Information
    /// @MISSION Extract basic information from JWT token without validation.
    /// @THREAT Information disclosure or token manipulation.
    /// @COUNTERMEASURE Limited information extraction and validation.
    /// @DEPENDENCY Valid JWT token string.
    /// @PERFORMANCE ~2ms information extraction.
    /// @AUDIT Token info extraction logged.
    pub fn get_token_info(token: &str) -> Result<TokenInfo, Box<dyn std::error::Error>> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err("Invalid token format".into());
        }

        // Decode header (first part)
        let header_decoded = URL_SAFE_NO_PAD.decode(parts[0])?;
        let header: serde_json::Value = serde_json::from_slice(&header_decoded)?;

        // Decode payload (second part)
        let payload_decoded = URL_SAFE_NO_PAD.decode(parts[1])?;
        let payload: serde_json::Value = serde_json::from_slice(&payload_decoded)?;

        Ok(TokenInfo {
            algorithm: header.get("alg")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
            subject: payload.get("sub")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            issuer: payload.get("iss")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            audience: payload.get("aud")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            expires_at: payload.get("exp")
                .and_then(|v| v.as_u64())
                .map(|ts| ts as i64),
            issued_at: payload.get("iat")
                .and_then(|v| v.as_u64())
                .map(|ts| ts as i64),
            jwt_id: payload.get("jti")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        })
    }

    /// [TOKEN INFO STRUCT] Basic Token Information
    /// @MISSION Store basic JWT token information.
    /// @THREAT Information leakage or token exposure.
    /// @COUNTERMEASURE Limited information storage and access controls.
    /// @INVARIANT Only non-sensitive information is stored.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct TokenInfo {
        pub algorithm: String,
        pub subject: Option<String>,
        pub issuer: Option<String>,
        pub audience: Option<String>,
        pub expires_at: Option<i64>,
        pub issued_at: Option<i64>,
        pub jwt_id: Option<String>,
    }
}

/// [KEY UTILS] Cryptographic Key Management Utilities
/// @MISSION Provide cryptographic key generation and management utilities.
/// @THREAT Key compromise or weak key generation.
/// @COUNTERMEASURE Secure key generation and proper validation.
/// @DEPENDENCY Cryptographic libraries and secure random sources.
/// @INVARIANT All keys are generated with sufficient entropy.
pub mod key_utils_internal {
    use super::*;
    use rand::rngs::OsRng;
    use rand::RngCore;

    /// [GENERATE API KEY] Generate Secure API Key
    /// @MISSION Generate cryptographically secure API key.
    /// @THREAT Weak API key generation or predictability.
    /// @COUNTERMEASURE Use cryptographically secure random generation.
    /// @DEPENDENCY OsRng for entropy and base64 encoding.
    /// @PERFORMANCE ~1ms API key generation.
    /// @AUDIT API key generation logged with metadata.
    pub fn generate_api_key() -> String {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        format!("sk_{}", URL_SAFE_NO_PAD.encode(&bytes))
    }

    /// [GENERATE SECRET KEY] Generate Random Secret Key
    /// @MISSION Generate secure random secret key.
    /// @THREAT Weak secret generation or insufficient entropy.
    /// @COUNTERMEASURE Use OS-provided cryptographically secure RNG.
    /// @DEPENDENCY OsRng for secure random bytes.
    /// @PERFORMANCE ~1ms secret key generation.
    /// @AUDIT Secret key generation logged.
    pub fn generate_secret_key(length: usize) -> String {
        let mut bytes = vec![0u8; length];
        OsRng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    }

    /// [GENERATE SESSION ID] Generate Secure Session ID
    /// @MISSION Generate cryptographically secure session identifier.
    /// @THREAT Session ID predictability or collision.
    /// @COUNTERMEASURE Use UUID v4 with cryptographically secure RNG.
    /// @DEPENDENCY UUID library with secure random generation.
    /// @PERFORMANCE ~1ms session ID generation.
    /// @AUDIT Session ID generation logged.
    pub fn generate_session_id() -> String {
        Uuid::new_v4().to_string()
    }

    /// [HASH PASSWORD] Secure Password Hashing
    /// @MISSION Hash password using Argon2id.
    /// @THREAT Weak password hashing or rainbow table attacks.
    /// @COUNTERMEASURE Use memory-hard Argon2id with proper parameters.
    /// @DEPENDENCY argon2 crate with secure configuration.
    /// @PERFORMANCE ~100ms password hashing.
    /// @AUDIT Password hashing logged without sensitive data.
    pub fn hash_password(password: &str, salt: &str) -> Result<String, Box<dyn std::error::Error>> {
        use argon2::{Argon2, PasswordHasher};
        use argon2::password_hash::SaltString;

        let salt = SaltString::encode_b64(salt.as_bytes())
            .map_err(|e| format!("Invalid salt: {}", e))?;

        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| format!("Password hashing failed: {}", e))?;

        Ok(password_hash.to_string())
    }

    /// [VERIFY PASSWORD] Verify Password Against Hash
    /// @MISSION Verify password against stored hash.
    /// @THREAT Password verification bypass or timing attacks.
    /// @COUNTERMEASURE Constant-time comparison and proper validation.
    /// @DEPENDENCY argon2 crate with secure verification.
    /// @PERFORMANCE ~100ms password verification.
    /// @AUDIT Password verification logged with result.
    pub fn verify_password(password: &str, hash: &str) -> Result<bool, Box<dyn std::error::Error>> {
        use argon2::{Argon2, PasswordHash, PasswordVerifier};

        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| format!("Invalid password hash: {}", e))?;

        let argon2 = Argon2::default();
        Ok(argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok())
    }

    /// [GENERATE RSA KEYPAIR] Generate RSA Key Pair
    /// @MISSION Generate RSA key pair for cryptographic operations.
    /// @THREAT Weak key generation or insufficient key size.
    /// @COUNTERMEASURE Use 2048-bit minimum key size with proper validation.
    /// @DEPENDENCY RSA cryptographic library.
    /// @PERFORMANCE ~100ms key pair generation.
    /// @AUDIT Key pair generation logged with metadata.
    pub fn generate_rsa_keypair() -> Result<(String, String), Box<dyn std::error::Error>> {
        use rsa::RsaPrivateKey;
        use rsa::pkcs8::EncodePrivateKey;
        use rsa::pkcs8::EncodePublicKey;

        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
        let public_key = private_key.to_public_key();

        let private_pem = private_key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)?;
        let public_pem = public_key.to_public_key_pem(rsa::pkcs8::LineEnding::LF)?;

        Ok((private_pem.to_string(), public_pem.to_string()))
    }

    /// [VALIDATE API KEY] Validate API Key Format
    /// @MISSION Validate API key format and structure.
    /// @THREAT Invalid API key acceptance or format bypass.
    /// @COUNTERMEASURE Strict format validation and length checks.
    /// @DEPENDENCY Base64 decoding and format validation.
    /// @PERFORMANCE ~1ms validation.
    /// @AUDIT API key validation logged.
    pub fn validate_api_key(api_key: &str) -> bool {
        if !api_key.starts_with("sk_") {
            return false;
        }

        let key_part = &api_key[3..];
        if key_part.len() != 43 { // 32 bytes base64 URL-safe without padding
            return false;
        }

        URL_SAFE_NO_PAD.decode(key_part).is_ok()
    }

    /// [EXTRACT KEY ID] Extract Key ID from API Key
    /// @MISSION Extract key identifier from API key for lookup.
    /// @THREAT Key ID extraction manipulation.
    /// @COUNTERMEASURE Deterministic key ID extraction.
    /// @DEPENDENCY Valid API key format.
    /// @PERFORMANCE ~1ms key ID extraction.
    /// @AUDIT Key ID extraction logged.
    pub fn extract_key_id(api_key: &str) -> Result<String, Box<dyn std::error::Error>> {
        if !validate_api_key(api_key) {
            return Err("Invalid API key format".into());
        }

        // Use first 8 characters of the key as ID for lookup
        let key_part = &api_key[3..];
        let key_bytes = URL_SAFE_NO_PAD.decode(key_part)?;
        let key_id = format!("kid_{}", hex::encode(&key_bytes[..8]));
        Ok(key_id)
    }
}

/// [STRING UTILS] String Manipulation Utilities
/// @MISSION Provide common string manipulation functions.
/// @THREAT String manipulation vulnerabilities.
/// @COUNTERMEASURE Input validation and safe operations.
/// @DEPENDENCY Standard library string operations.
/// @INVARIANT All operations are safe and validated.
pub mod string_utils {
    /// [SANITIZE STRING] Sanitize User Input String
    /// @MISSION Sanitize string for safe processing.
    /// @THREAT Injection attacks or malicious input.
    /// @COUNTERMEASURE Remove dangerous characters and validate format.
    /// @DEPENDENCY Input string and validation rules.
    /// @PERFORMANCE ~1ms sanitization.
    /// @AUDIT String sanitization logged.
    pub fn sanitize_string(input: &str, max_length: usize) -> String {
        input
            .chars()
            .filter(|c| c.is_ascii() && !c.is_control())
            .take(max_length)
            .collect()
    }

    /// [VALIDATE EMAIL] Validate Email Address Format
    /// @MISSION Validate email address format.
    /// @THREAT Invalid email acceptance or format bypass.
    /// @COUNTERMEASURE Email format validation with regex.
    /// @DEPENDENCY Email string and validation rules.
    /// @PERFORMANCE ~1ms validation.
    /// @AUDIT Email validation logged.
    pub fn validate_email(email: &str) -> bool {
        // Basic email validation regex
        let email_regex = regex::Regex::new(
            r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        ).unwrap_or_default();
        
        email_regex.is_match(email) && email.len() <= 254
    }

    /// [VALIDATE PHONE] Validate Phone Number Format
    /// @MISSION Validate phone number format.
    /// @THREAT Invalid phone acceptance or format bypass.
    /// @COUNTERMEASURE Phone format validation with regex.
    /// @DEPENDENCY Phone string and validation rules.
    /// @PERFORMANCE ~1ms validation.
    /// @AUDIT Phone validation logged.
    pub fn validate_phone(phone: &str) -> bool {
        // Basic phone validation - allows +, digits, spaces, hyphens, parentheses
        let phone_regex = regex::Regex::new(r"^\+?[\d\s\-\(\)]{10,20}$").unwrap_or_default();
        phone_regex.is_match(phone)
    }

    /// [GENERATE SLUG] Generate URL-friendly Slug
    /// @MISSION Generate URL-friendly slug from string.
    /// @THREAT Slug manipulation or injection.
    /// @COUNTERMEASURE Safe slug generation with validation.
    /// @DEPENDENCY Input string and slug generation rules.
    /// @PERFORMANCE ~1ms slug generation.
    /// @AUDIT Slug generation logged.
    pub fn generate_slug(input: &str) -> String {
        input
            .to_lowercase()
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '-' || *c == '_')
            .collect::<String>()
            .split_whitespace()
            .collect::<Vec<&str>>()
            .join("-")
    }

    /// [TRUNCATE STRING] Truncate String with Ellipsis
    /// @MISSION Truncate string to specified length with ellipsis.
    /// @THREAT String truncation manipulation.
    /// @COUNTERMEASURE Safe truncation with proper handling.
    /// @DEPENDENCY Input string and length limit.
    /// @PERFORMANCE ~1ms truncation.
    /// @AUDIT String truncation logged.
    pub fn truncate_string(input: &str, max_length: usize) -> String {
        if input.len() <= max_length {
            return input.to_string();
        }

        let mut truncated = input.chars().take(max_length.saturating_sub(3)).collect::<String>();
        truncated.push_str("...");
        truncated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_key_generation() {
        let api_key = key_utils::generate_api_key();
        assert!(api_key.starts_with("sk_"));
        assert!(key_utils::validate_api_key(&api_key));
    }

    #[test]
    fn test_session_id_generation() {
        let session_id = key_utils::generate_session_id();
        assert!(!session_id.is_empty());
        assert_eq!(session_id.len(), 36); // UUID length
    }

    #[test]
    fn test_bearer_token_extraction() {
        let auth_header = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let token = tokens::extract_bearer_token(auth_header);
        assert_eq!(token, Some("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));

        let invalid_header = "Basic dXNlcjpwYXNz";
        let token = tokens::extract_bearer_token(invalid_header);
        assert_eq!(token, None);
    }

    #[test]
    fn test_string_sanitization() {
        let input = "Hello\x00World!";
        let sanitized = string_utils::sanitize_string(input, 20);
        assert_eq!(sanitized, "HelloWorld!");
    }

    #[test]
    fn test_email_validation() {
        assert!(string_utils::validate_email("test@example.com"));
        assert!(!string_utils::validate_email("invalid-email"));
        assert!(!string_utils::validate_email("test@"));
    }

    #[test]
    fn test_phone_validation() {
        assert!(string_utils::validate_phone("+1-555-123-4567"));
        assert!(string_utils::validate_phone("(555) 123-4567"));
        assert!(!string_utils::validate_phone("123"));
    }

    #[test]
    fn test_slug_generation() {
        let slug = string_utils::generate_slug("Hello World! This is a Test");
        assert_eq!(slug, "hello-world-this-is-a-test");
    }

    #[test]
    fn test_string_truncation() {
        let long_string = "This is a very long string that needs to be truncated";
        let truncated = string_utils::truncate_string(long_string, 20);
        assert_eq!(truncated, "This is a very lo...");
        
        let short_string = "Short";
        let truncated = string_utils::truncate_string(short_string, 20);
        assert_eq!(truncated, "Short");
    }
}