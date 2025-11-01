// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise CLI
//  Module: Crypto Utilities
// ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide cryptographic utilities for CLI operations.
//  NOTICE: This module contains encryption, decryption, and hashing functions.
//  SECURITY: Cryptographic operations for secure data handling
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use anyhow::{Result, anyhow};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::digest::{Context, SHA256, SHA384};
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use std::num::NonZeroU32;

/// Cryptographic utilities
pub struct CryptoUtils;

impl CryptoUtils {
    /// Generate a random nonce for AES-GCM
    pub fn generate_nonce() -> Result<[u8; 12]> {
        let rng = SystemRandom::new();
        let mut nonce = [0u8; 12];
        rng.fill(&mut nonce)
            .map_err(|_| anyhow!("Failed to generate nonce"))?;
        Ok(nonce)
    }

    /// Derive key from password using PBKDF2
    pub fn derive_key(password: &str, salt: &[u8], iterations: u32) -> Result<[u8; 32]> {
        let mut key = [0u8; 32];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(iterations).unwrap(),
            salt,
            password.as_bytes(),
            &mut key,
        );
        Ok(key)
    }

    /// Encrypt data using AES-256-GCM
    pub fn encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>> {
        let unbound_key = UnboundKey::new(&AES_256_GCM, key)
            .map_err(|_| anyhow!("Invalid key"))?;
        let less_safe_key = LessSafeKey::new(unbound_key);
        let nonce = Nonce::assume_unique_for_key(*nonce);

        let mut in_out = plaintext.to_vec();
        less_safe_key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| anyhow!("Encryption failed"))?;

        Ok(in_out)
    }

    /// Decrypt data using AES-256-GCM
    pub fn decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let unbound_key = UnboundKey::new(&AES_256_GCM, key)
            .map_err(|_| anyhow!("Invalid key"))?;
        let less_safe_key = LessSafeKey::new(unbound_key);
        let nonce = Nonce::assume_unique_for_key(*nonce);

        let mut in_out = ciphertext.to_vec();
        less_safe_key.open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| anyhow!("Decryption failed"))?;

        // Remove the tag (last 16 bytes)
        in_out.truncate(in_out.len() - 16);
        Ok(in_out)
    }

    /// Generate SHA-256 hash
    pub fn sha256(data: &[u8]) -> [u8; 32] {
        let mut context = Context::new(&SHA256);
        context.update(data);
        context.finish().as_ref().try_into().unwrap()
    }

    /// Generate SHA-384 hash
    pub fn sha384(data: &[u8]) -> [u8; 48] {
        let mut context = Context::new(&SHA384);
        context.update(data);
        context.finish().as_ref().try_into().unwrap()
    }

    /// Generate random bytes
    pub fn random_bytes(length: usize) -> Result<Vec<u8>> {
        let rng = SystemRandom::new();
        let mut bytes = vec![0u8; length];
        rng.fill(&mut bytes)
            .map_err(|_| anyhow!("Failed to generate random bytes"))?;
        Ok(bytes)
    }

    /// Generate a secure random password
    pub fn generate_password(length: usize) -> Result<String> {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                abcdefghijklmnopqrstuvwxyz\
                                0123456789\
                                !@#$%^&*()_+-=[]{}|;:,.<>?";

        let rng = SystemRandom::new();
        let mut password = Vec::with_capacity(length);

        for _ in 0..length {
            let mut byte = [0u8; 1];
            rng.fill(&mut byte)
                .map_err(|_| anyhow!("Failed to generate password"))?;
            password.push(CHARSET[byte[0] as usize % CHARSET.len()]);
        }

        String::from_utf8(password)
            .map_err(|_| anyhow!("Generated invalid UTF-8"))
    }
}