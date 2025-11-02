// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Utilities Module
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | SENSITIVE
//  MISSION: Organize utility functions for the enterprise API service,
//  providing cryptographic operations, token management, and common utilities.
//  NOTICE: Utilities implement secure operations with proper error handling,
//  logging, and enterprise security standards.
//  UTILITY STANDARDS: Cryptography, Token Management, Error Handling
//  COMPLIANCE: Security Best Practices, Cryptographic Standards
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

/// [GENERAL UTILITIES] Common utility functions
pub mod util;
/// [KEY UTILITIES] Cryptographic key and certificate operations
pub mod key_utils;
/// [TOKEN UTILITIES] JWT and authentication token management
pub mod tokens;
/// [VOIP UTILITIES] VoIP-specific utility functions and helpers
pub mod voip_utils;
/// [DISCORD UTILITIES] Discord-specific utility functions for formatting and validation
pub mod discord_utils;
/// [GIT UTILITIES] GitHub-specific utility functions for formatting and validation
pub mod git_utils;
/// [MAC UTILITIES] MAC identity utility functions for formatting, conversion, and validation
pub mod mac_utils;
/// [MAC CERTIFICATE UTILITIES] MAC certificate utility functions for validation and management
pub mod mac_cert_utils;