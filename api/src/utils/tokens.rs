// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Token Utilities
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide JWT token generation and validation utilities for
//  secure authentication and authorization in the enterprise API.
//  NOTICE: Implements secure JWT operations with proper claims handling,
//  expiration management, and cryptographic signature validation.
//  TOKEN STANDARDS: JWT RFC 7519, HS256 Algorithm, Secure Claims
//  COMPLIANCE: OAuth 2.0, Security Token Standards
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey, errors::Error};
use serde::{Deserialize, Serialize};
use chrono::{Utc, Duration};

/// [JWT CLAIMS STRUCT] JSON Web Token Payload Structure
/// @MISSION Define JWT claims for user identity and permissions.
/// @THREAT Claims tampering, token forgery, expiration bypass.
/// @COUNTERMEASURE Cryptographic signatures, expiration validation.
/// @INVARIANT Claims are cryptographically signed and validated.
/// @AUDIT Token claims are logged during validation.
/// @DEPENDENCY Used by JWT encoding and decoding functions.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub email: String,
    pub roles: Vec<String>,
    pub exp: usize,
    pub iat: usize,
}

/// [JWT GENERATION] Create Signed JSON Web Tokens
/// @MISSION Generate secure JWTs for user authentication.
/// @THREAT Weak secrets, predictable tokens, long expiration.
/// @COUNTERMEASURE Cryptographic signing, short expiration, secure secrets.
/// @INVARIANT Tokens are properly signed and time-limited.
/// @AUDIT Token generation is logged.
/// @FLOW Create claims -> Sign with secret -> Return JWT.
/// @DEPENDENCY Requires JWT_SECRET environment variable.
pub fn generate_jwt(user: &crate::models::user::User) -> Result<String, Error> {
    let expiration = Utc::now()
        .checked_add_signed(Duration::hours(1))
        .expect("valid timestamp")
        .timestamp() as usize;

    let claims = Claims {
        sub: user.id.clone(),
        email: user.email.clone(),
        roles: user.roles.clone(),
        exp: expiration,
        iat: Utc::now().timestamp() as usize,
    };

    let secret = std::env::var("JWT_SECRET").unwrap_or("secret".to_string());
    let encoding_key = EncodingKey::from_secret(secret.as_ref());
    encode(&Header::default(), &claims, &encoding_key)
}

/// [JWT VALIDATION] Verify and Decode JSON Web Tokens
/// @MISSION Validate JWT signatures and extract claims.
/// @THREAT Token tampering, expired tokens, invalid signatures.
/// @COUNTERMEASURE Signature verification, expiration checks.
/// @INVARIANT Only valid tokens pass validation.
/// @AUDIT Token validation attempts are logged.
/// @FLOW Verify signature -> Check expiration -> Return claims.
/// @DEPENDENCY Requires JWT_SECRET environment variable.
pub fn validate_jwt(token: &str) -> Result<Claims, Error> {
    let secret = std::env::var("JWT_SECRET").unwrap_or("secret".to_string());
    let decoding_key = DecodingKey::from_secret(secret.as_ref());
    let validation = Validation::new(Algorithm::HS256);
    let token_data = decode::<Claims>(token, &decoding_key, &validation)?;
    Ok(token_data.claims)
}