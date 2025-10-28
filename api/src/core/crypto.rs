//! # Sky Genesis Enterprise - Cryptographic Module
//!
//! This module provides modern cryptographic primitives following the latest security recommendations.
//! All implementations prioritize security, performance, and forward compatibility.
//!
//! ## Security Levels Implemented:
//!
//! - **Symmetric Encryption**: AES-256-GCM, ChaCha20-Poly1305 (AEAD)
//! - **Key Exchange**: X25519 (ECDH)
//! - **Digital Signatures**: Ed25519, ECDSA P-384
//! - **Hash Functions**: SHA-512, SHA-3-512
//! - **Key Derivation**: HKDF-SHA-512
//! - **Password Hashing**: Argon2id
//! - **Post-Quantum Ready**: Hybrid schemes (when available)

use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use argon2::{Argon2, Params};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce};
use chacha20poly1305::aead::{Aead as ChaChaAead, KeyInit as ChaChaKeyInit};
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};
use hkdf::Hkdf;
use p384::ecdsa::{SigningKey, VerifyingKey, signature::{Signer as EcdsaSigner, Verifier as EcdsaVerifier}};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Sha512, Digest as Sha2Digest};
use sha3::{Sha3_512, Digest as Sha3Digest};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, SharedSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use std::fmt;

/// Cryptographic operation result
pub type CryptoResult<T> = Result<T, CryptoError>;

/// Cryptographic errors
#[derive(Debug)]
pub enum CryptoError {
    EncryptionFailed(String),
    DecryptionFailed(String),
    SignatureVerificationFailed,
    InvalidKeyLength,
    InvalidNonceLength,
    KeyDerivationFailed,
    PasswordHashingFailed,
    InvalidFormat(String),
    UnsupportedAlgorithm(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::EncryptionFailed(msg) => write!(f, "Encryption failed: {}", msg),
            CryptoError::DecryptionFailed(msg) => write!(f, "Decryption failed: {}", msg),
            CryptoError::SignatureVerificationFailed => write!(f, "Signature verification failed"),
            CryptoError::InvalidKeyLength => write!(f, "Invalid key length"),
            CryptoError::InvalidNonceLength => write!(f, "Invalid nonce length"),
            CryptoError::KeyDerivationFailed => write!(f, "Key derivation failed"),
            CryptoError::PasswordHashingFailed => write!(f, "Password hashing failed"),
            CryptoError::InvalidFormat(msg) => write!(f, "Invalid format: {}", msg),
            CryptoError::UnsupportedAlgorithm(algo) => write!(f, "Unsupported algorithm: {}", algo),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Symmetric encryption algorithms
#[derive(Debug, Clone, Copy)]
pub enum SymmetricAlgorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
}

/// Key exchange algorithms
#[derive(Debug, Clone, Copy)]
pub enum KeyExchangeAlgorithm {
    X25519,
}

/// Signature algorithms
#[derive(Debug, Clone, Copy)]
pub enum SignatureAlgorithm {
    Ed25519,
    EcdsaP384,
}

/// Hash algorithms
#[derive(Debug, Clone, Copy)]
pub enum HashAlgorithm {
    Sha512,
    Sha3_512,
}

/// Key derivation algorithms
#[derive(Debug, Clone, Copy)]
pub enum KdfAlgorithm {
    HkdfSha512,
    HkdfSha256,
}

/// Password hashing algorithms
#[derive(Debug, Clone, Copy)]
pub enum PasswordHashAlgorithm {
    Argon2id,
}

// ============================================================================
// SYMMETRIC ENCRYPTION (AES-256-GCM, ChaCha20-Poly1305)
// ============================================================================

/// Encrypt data using AES-256-GCM
pub fn aes256_gcm_encrypt(key: &[u8], plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength);
    }

    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    // Prepend nonce to ciphertext
    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt data using AES-256-GCM
pub fn aes256_gcm_decrypt(key: &[u8], ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength);
    }
    if ciphertext.len() < 12 {
        return Err(CryptoError::InvalidNonceLength);
    }

    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&ciphertext[..12]);
    let ciphertext = &ciphertext[12..];

    cipher.decrypt(nonce, ciphertext)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
}

/// Encrypt data using ChaCha20-Poly1305
pub fn chacha20_poly1305_encrypt(key: &[u8], plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength);
    }

    let key = ChaChaKey::from_slice(key);
    let cipher = ChaCha20Poly1305::new(key);
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = ChaChaNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    // Prepend nonce to ciphertext
    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt data using ChaCha20-Poly1305
pub fn chacha20_poly1305_decrypt(key: &[u8], ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength);
    }
    if ciphertext.len() < 12 {
        return Err(CryptoError::InvalidNonceLength);
    }

    let key = ChaChaKey::from_slice(key);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = ChaChaNonce::from_slice(&ciphertext[..12]);
    let ciphertext = &ciphertext[12..];

    cipher.decrypt(nonce, ciphertext)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
}

/// Generic symmetric encryption with algorithm selection
pub fn symmetric_encrypt(algorithm: SymmetricAlgorithm, key: &[u8], plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
    match algorithm {
        SymmetricAlgorithm::Aes256Gcm => aes256_gcm_encrypt(key, plaintext),
        SymmetricAlgorithm::ChaCha20Poly1305 => chacha20_poly1305_encrypt(key, plaintext),
    }
}

/// Generic symmetric decryption with algorithm selection
pub fn symmetric_decrypt(algorithm: SymmetricAlgorithm, key: &[u8], ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
    match algorithm {
        SymmetricAlgorithm::Aes256Gcm => aes256_gcm_decrypt(key, ciphertext),
        SymmetricAlgorithm::ChaCha20Poly1305 => chacha20_poly1305_decrypt(key, ciphertext),
    }
}

// ============================================================================
// KEY EXCHANGE (X25519 ECDH)
// ============================================================================

/// X25519 keypair for key exchange
#[derive(ZeroizeOnDrop)]
pub struct X25519Keypair {
    pub secret: EphemeralSecret,
    pub public: X25519PublicKey,
}

impl X25519Keypair {
    /// Generate a new X25519 keypair
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);
        X25519Keypair { secret, public }
    }

    /// Compute shared secret with peer's public key
    pub fn compute_shared_secret(&self, peer_public: &X25519PublicKey) -> SharedSecret {
        self.secret.diffie_hellman(peer_public)
    }

    /// Get public key as bytes
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }
}

/// Perform X25519 key exchange
pub fn x25519_key_exchange() -> (X25519Keypair, X25519Keypair) {
    let alice = X25519Keypair::generate();
    let bob = X25519Keypair::generate();
    (alice, bob)
}

/// Compute shared secret from key exchange
pub fn x25519_shared_secret(local: &X25519Keypair, peer_public: &X25519PublicKey) -> SharedSecret {
    local.compute_shared_secret(peer_public)
}

// ============================================================================
// DIGITAL SIGNATURES (Ed25519, ECDSA P-384)
// ============================================================================

/// Ed25519 keypair for signing
#[derive(ZeroizeOnDrop)]
pub struct Ed25519Keypair {
    pub keypair: Keypair,
}

impl Ed25519Keypair {
    /// Generate a new Ed25519 keypair
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let keypair = Keypair::generate(&mut csprng);
        Ed25519Keypair { keypair }
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.keypair.sign(message)
    }

    /// Get public key
    pub fn public_key(&self) -> PublicKey {
        self.keypair.public
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &Signature) -> CryptoResult<()> {
        self.keypair.public.verify(message, signature)
            .map_err(|_| CryptoError::SignatureVerificationFailed)
    }
}

/// ECDSA P-384 keypair for signing
#[derive(ZeroizeOnDrop)]
pub struct EcdsaP384Keypair {
    pub signing_key: SigningKey,
}

impl EcdsaP384Keypair {
    /// Generate a new ECDSA P-384 keypair
    pub fn generate() -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        EcdsaP384Keypair { signing_key }
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> p384::ecdsa::Signature {
        self.signing_key.sign(message)
    }

    /// Get verifying key
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &p384::ecdsa::Signature) -> CryptoResult<()> {
        self.signing_key.verifying_key().verify(message, signature)
            .map_err(|_| CryptoError::SignatureVerificationFailed)
    }
}

/// Generic signature creation
pub fn sign(algorithm: SignatureAlgorithm, keypair: &dyn Signable, message: &[u8]) -> CryptoResult<Vec<u8>> {
    match algorithm {
        SignatureAlgorithm::Ed25519 => {
            let kp = keypair.as_any().downcast_ref::<Ed25519Keypair>()
                .ok_or_else(|| CryptoError::InvalidFormat("Invalid keypair type for Ed25519".to_string()))?;
            Ok(kp.sign(message).to_bytes().to_vec())
        }
        SignatureAlgorithm::EcdsaP384 => {
            let kp = keypair.as_any().downcast_ref::<EcdsaP384Keypair>()
                .ok_or_else(|| CryptoError::InvalidFormat("Invalid keypair type for ECDSA P-384".to_string()))?;
            Ok(kp.sign(message).to_bytes().to_vec())
        }
    }
}

/// Generic signature verification
pub fn verify(algorithm: SignatureAlgorithm, public_key: &[u8], message: &[u8], signature: &[u8]) -> CryptoResult<()> {
    match algorithm {
        SignatureAlgorithm::Ed25519 => {
            let pk = PublicKey::from_bytes(public_key)
                .map_err(|_| CryptoError::InvalidFormat("Invalid Ed25519 public key".to_string()))?;
            let sig = Signature::from_bytes(signature)
                .map_err(|_| CryptoError::InvalidFormat("Invalid Ed25519 signature".to_string()))?;
            pk.verify(message, &sig)
                .map_err(|_| CryptoError::SignatureVerificationFailed)
        }
        SignatureAlgorithm::EcdsaP384 => {
            let vk = VerifyingKey::from_sec1_bytes(public_key)
                .map_err(|_| CryptoError::InvalidFormat("Invalid ECDSA P-384 public key".to_string()))?;
            let sig = p384::ecdsa::Signature::from_bytes(signature)
                .map_err(|_| CryptoError::InvalidFormat("Invalid ECDSA P-384 signature".to_string()))?;
            vk.verify(message, &sig)
                .map_err(|_| CryptoError::SignatureVerificationFailed)
        }
    }
}

// Trait for signable keypairs
pub trait Signable {
    fn as_any(&self) -> &dyn std::any::Any;
}

impl Signable for Ed25519Keypair {
    fn as_any(&self) -> &dyn std::any::Any { self }
}

impl Signable for EcdsaP384Keypair {
    fn as_any(&self) -> &dyn std::any::Any { self }
}

// ============================================================================
// HASH FUNCTIONS (SHA-512, SHA-3-512)
// ============================================================================

/// Compute SHA-512 hash
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute SHA-3-512 hash
pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Generic hash function
pub fn hash(algorithm: HashAlgorithm, data: &[u8]) -> Vec<u8> {
    match algorithm {
        HashAlgorithm::Sha512 => sha512(data).to_vec(),
        HashAlgorithm::Sha3_512 => sha3_512(data).to_vec(),
    }
}

// ============================================================================
// KEY DERIVATION (HKDF)
// ============================================================================

/// Derive key using HKDF-SHA-512
pub fn hkdf_sha512(ikm: &[u8], salt: &[u8], info: &[u8], output_len: usize) -> CryptoResult<Vec<u8>> {
    let hkdf = Hkdf::<Sha512>::new(Some(salt), ikm);
    let mut okm = vec![0u8; output_len];
    hkdf.expand(info, &mut okm)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(okm)
}

/// Derive key using HKDF-SHA-256
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], output_len: usize) -> CryptoResult<Vec<u8>> {
    let hkdf = Hkdf::<sha2::Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; output_len];
    hkdf.expand(info, &mut okm)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(okm)
}

/// Generic key derivation
pub fn kdf_derive(algorithm: KdfAlgorithm, ikm: &[u8], salt: &[u8], info: &[u8], output_len: usize) -> CryptoResult<Vec<u8>> {
    match algorithm {
        KdfAlgorithm::HkdfSha512 => hkdf_sha512(ikm, salt, info, output_len),
        KdfAlgorithm::HkdfSha256 => hkdf_sha256(ikm, salt, info, output_len),
    }
}

// ============================================================================
// PASSWORD HASHING (Argon2id)
// ============================================================================

/// Hash a password using Argon2id with recommended parameters
pub fn argon2id_hash(password: &[u8], salt: &[u8]) -> CryptoResult<String> {
    // Recommended parameters: time=3, mem=64MiB, parallelism=4
    let params = Params::new(65536, 3, 4, None) // 64 MiB, 3 iterations, 4 lanes
        .map_err(|_| CryptoError::PasswordHashingFailed)?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut hash = [0u8; 32]; // 256-bit output

    argon2.hash_password_into(password, salt, &mut hash)
        .map_err(|_| CryptoError::PasswordHashingFailed)?;

    Ok(base64::encode(&hash))
}

/// Verify a password against its Argon2id hash
pub fn argon2id_verify(password: &[u8], salt: &[u8], expected_hash: &str) -> CryptoResult<bool> {
    let expected_hash_bytes = base64::decode(expected_hash)
        .map_err(|_| CryptoError::InvalidFormat("Invalid base64 hash".to_string()))?;

    let params = Params::new(65536, 3, 4, None)
        .map_err(|_| CryptoError::PasswordHashingFailed)?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut hash = [0u8; 32];

    argon2.hash_password_into(password, salt, &mut hash)
        .map_err(|_| CryptoError::PasswordHashingFailed)?;

    Ok(hash.as_ref() == expected_hash_bytes.as_slice())
}

/// Generic password hashing
pub fn password_hash(algorithm: PasswordHashAlgorithm, password: &[u8], salt: &[u8]) -> CryptoResult<String> {
    match algorithm {
        PasswordHashAlgorithm::Argon2id => argon2id_hash(password, salt),
    }
}

/// Generic password verification
pub fn password_verify(algorithm: PasswordHashAlgorithm, password: &[u8], salt: &[u8], hash: &str) -> CryptoResult<bool> {
    match algorithm {
        PasswordHashAlgorithm::Argon2id => argon2id_verify(password, salt, hash),
    }
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/// Generate a random salt
pub fn generate_salt(len: usize) -> Vec<u8> {
    let mut salt = vec![0u8; len];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Generate a random key of specified length
pub fn generate_key(len: usize) -> Vec<u8> {
    let mut key = vec![0u8; len];
    OsRng.fill_bytes(&mut key);
    key
}

/// Generate a random nonce
pub fn generate_nonce(len: usize) -> Vec<u8> {
    let mut nonce = vec![0u8; len];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Securely compare two byte slices (constant time)
pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

// ============================================================================
// HIGH-LEVEL CONVENIENCE FUNCTIONS
// ============================================================================

/// Encrypt data with automatic algorithm selection (ChaCha20-Poly1305 preferred for mobile)
pub fn encrypt_data(key: &[u8], plaintext: &[u8], prefer_mobile: bool) -> CryptoResult<Vec<u8>> {
    let algorithm = if prefer_mobile {
        SymmetricAlgorithm::ChaCha20Poly1305
    } else {
        SymmetricAlgorithm::Aes256Gcm
    };
    symmetric_encrypt(algorithm, key, plaintext)
}

/// Decrypt data with automatic algorithm detection
pub fn decrypt_data(key: &[u8], ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
    // Try ChaCha20-Poly1305 first (more common for mobile), then AES-256-GCM
    match chacha20_poly1305_decrypt(key, ciphertext) {
        Ok(plaintext) => Ok(plaintext),
        Err(_) => aes256_gcm_decrypt(key, ciphertext),
    }
}

/// Create a secure key exchange and derive shared key
pub fn secure_key_exchange() -> (X25519Keypair, X25519Keypair, Vec<u8>) {
    let (alice, bob) = x25519_key_exchange();
    let shared_secret = alice.compute_shared_secret(&bob.public);
    let derived_key = hkdf_sha512(shared_secret.as_bytes(), b"key_exchange_salt", b"shared_key", 32)
        .unwrap_or_else(|_| generate_key(32));
    (alice, bob, derived_key)
}

/// Sign data with recommended algorithm (Ed25519)
pub fn sign_data(keypair: &Ed25519Keypair, data: &[u8]) -> Vec<u8> {
    keypair.sign(data).to_bytes().to_vec()
}

/// Verify signature with recommended algorithm (Ed25519)
pub fn verify_signature(public_key: &PublicKey, data: &[u8], signature: &Signature) -> CryptoResult<()> {
    public_key.verify(data, signature)
        .map_err(|_| CryptoError::SignatureVerificationFailed)
}

/// Hash data with recommended algorithm (SHA-512)
pub fn hash_data(data: &[u8]) -> [u8; 64] {
    sha512(data)
}

/// Derive key with recommended algorithm (HKDF-SHA-512)
pub fn derive_key(master_key: &[u8], context: &[u8], output_len: usize) -> CryptoResult<Vec<u8>> {
    let salt = generate_salt(32);
    hkdf_sha512(master_key, &salt, context, output_len)
}

/// Hash password with recommended algorithm (Argon2id)
pub fn hash_password(password: &[u8]) -> CryptoResult<(Vec<u8>, String)> {
    let salt = generate_salt(32);
    let hash = argon2id_hash(password, &salt)?;
    Ok((salt, hash))
}

/// Verify password with recommended algorithm (Argon2id)
pub fn verify_password(password: &[u8], salt: &[u8], hash: &str) -> CryptoResult<bool> {
    argon2id_verify(password, salt, hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes256_gcm_encrypt_decrypt() {
        let key = generate_key(32);
        let plaintext = b"Hello, World!";
        let ciphertext = aes256_gcm_encrypt(&key, plaintext).unwrap();
        let decrypted = aes256_gcm_decrypt(&key, &ciphertext).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_chacha20_poly1305_encrypt_decrypt() {
        let key = generate_key(32);
        let plaintext = b"Hello, World!";
        let ciphertext = chacha20_poly1305_encrypt(&key, plaintext).unwrap();
        let decrypted = chacha20_poly1305_decrypt(&key, &ciphertext).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_x25519_key_exchange() {
        let alice = X25519Keypair::generate();
        let bob = X25519Keypair::generate();

        let alice_shared = alice.compute_shared_secret(&bob.public);
        let bob_shared = bob.compute_shared_secret(&alice.public);

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_ed25519_sign_verify() {
        let keypair = Ed25519Keypair::generate();
        let message = b"Hello, World!";
        let signature = keypair.sign(message);
        assert!(keypair.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_sha512_hash() {
        let data = b"Hello, World!";
        let hash1 = sha512(data);
        let hash2 = sha512(data);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64);
    }

    #[test]
    fn test_hkdf_sha512() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"context info";
        let key1 = hkdf_sha512(ikm, salt, info, 32).unwrap();
        let key2 = hkdf_sha512(ikm, salt, info, 32).unwrap();
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn test_argon2id_hash_verify() {
        let password = b"my_password";
        let salt = generate_salt(32);
        let hash = argon2id_hash(password, &salt).unwrap();
        let is_valid = argon2id_verify(password, &salt, &hash).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_secure_compare() {
        let a = b"test";
        let b = b"test";
        let c = b"different";
        assert!(secure_compare(a, b));
        assert!(!secure_compare(a, c));
    }
}