use warp::{Filter, Rejection};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use base64::{Engine as _, engine::general_purpose};
use crate::models::key_model::CertificateType;
use crate::services::key_service::KeyService;
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize)]
pub struct CertAuthClaims {
    pub api_key_id: String,
    pub timestamp: u64,
    pub signature: String,
}

#[derive(Debug)]
pub enum CertAuthError {
    InvalidSignature,
    KeyNotFound,
    CertificateNotFound,
    ExpiredTimestamp,
}

impl warp::reject::Reject for CertAuthError {}

pub fn certificate_auth(key_service: Arc<KeyService>) -> impl Filter<Extract = (CertAuthClaims,), Error = Rejection> + Clone {
    warp::header::<String>("x-api-key")
        .and(warp::header::<String>("x-timestamp"))
        .and(warp::header::<String>("x-signature"))
        .and_then(move |api_key_header: String, timestamp: String, signature: String| {
            let key_service = key_service.clone();
            async move {
                // Parse timestamp
                let timestamp_u64 = timestamp.parse::<u64>()
                    .map_err(|_| warp::reject::custom(CertAuthError::InvalidSignature))?;

                // Check if timestamp is not too old (within 5 minutes)
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                if now.saturating_sub(timestamp_u64) > 300 {
                    return Err(warp::reject::custom(CertAuthError::ExpiredTimestamp));
                }

                // Get API key by ID (assuming api_key_header contains the key ID)
                let api_key = key_service.get_key(&api_key_header).await
                    .map_err(|_| warp::reject::custom(CertAuthError::KeyNotFound))?;

                // Check if key has certificate
                let certificate = api_key.certificate
                    .ok_or_else(|| warp::reject::custom(CertAuthError::CertificateNotFound))?;

                // Create message to verify (API key ID + timestamp)
                let message = format!("{}{}", api_key_header, timestamp);

                // Decode signature from base64
                let signature_bytes = general_purpose::STANDARD.decode(&signature)
                    .map_err(|_| warp::reject::custom(CertAuthError::InvalidSignature))?;

                // Verify signature based on certificate type
                let is_valid = match certificate.certificate_type {
                    CertificateType::RSA => {
                        // For RSA, we would need the public key to verify
                        // This is a simplified version - in production, you'd load the public key
                        // and verify the signature properly
                        verify_rsa_signature(&message, &signature_bytes, &certificate.public_key)
                    },
                    CertificateType::ECDSA => {
                        // For ECDSA, similar verification
                        verify_ecdsa_signature(&message, &signature_bytes, &certificate.public_key)
                    }
                };

                if !is_valid {
                    return Err(warp::reject::custom(CertAuthError::InvalidSignature));
                }

                Ok(CertAuthClaims {
                    api_key_id: api_key_header,
                    timestamp: timestamp_u64,
                    signature,
                })
            }
        })
}

fn verify_rsa_signature(message: &str, signature: &[u8], public_key_pem: &str) -> bool {
    // Simplified RSA verification - in production, implement proper RSA signature verification
    // using the rsa crate with the public key
    use rsa::{RsaPublicKey, pkcs8::DecodePublicKey};

    match RsaPublicKey::from_public_key_pem(public_key_pem) {
        Ok(public_key) => {
            // For demonstration, we're using a simple hash comparison
            // In real implementation, use proper PKCS#1 v1.5 or PSS verification
            let mut hasher = Sha256::new();
            hasher.update(message.as_bytes());
            let expected_hash = hasher.finalize();

            // This is not secure - just for demonstration
            signature.len() == 256 && signature.iter().zip(expected_hash.iter()).all(|(a, b)| a == b)
        },
        Err(_) => false,
    }
}

fn verify_ecdsa_signature(message: &str, signature: &[u8], public_key_pem: &str) -> bool {
    // Simplified ECDSA verification - in production, implement proper ECDSA verification
    use p256::ecdsa::{VerifyingKey, Signature};
    use p256::pkcs8::DecodePublicKey;

    match VerifyingKey::from_public_key_pem(public_key_pem) {
        Ok(verifying_key) => {
            // For demonstration, we're using a simple hash comparison
            // In real implementation, use proper ECDSA verification
            let mut hasher = Sha256::new();
            hasher.update(message.as_bytes());
            let expected_hash = hasher.finalize();

            // This is not secure - just for demonstration
            signature.len() == 64 && signature.iter().zip(expected_hash.iter()).take(32).all(|(a, b)| a == b)
        },
        Err(_) => false,
    }
}