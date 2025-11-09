// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
// Sovereign Infrastructure Initiative
// Project: Enterprise API Service
// Module: Core Defense Systems (Minimal Working Version)
// ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | SECURITY-CRITICAL
//  MISSION: Provide essential cryptographic and network capabilities.
//  NOTICE: This is a minimal working version with only essential modules.
//  All operations are cryptographically auditable via OpenTelemetry.
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

/// [CRYPTO DOMAIN] Core Cryptographic Operations
/// @MISSION Maintain integrity of all key material and encrypted communications.
/// @THREAT Cryptographic weaknesses or key compromise.
/// @COUNTERMEASURE Use FIPS-compliant algorithms with regular key rotation.
/// @AUDIT All crypto operations logged with hash integrity.
pub mod core;

/// [CRYPTO PRIMITIVES] Low-level Cryptographic Functions
/// @MISSION Implement secure cryptographic primitives.
/// @THREAT Side-channel attacks or weak implementations.
/// @COUNTERMEASURE Use audited crypto libraries with constant-time operations.
/// @DEPENDENCY aes-gcm, ed25519-dalek, argon2 crates.
pub mod crypto;

// All other modules temporarily disabled to create a minimal working version
// These will be progressively re-enabled as dependencies are fixed