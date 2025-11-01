// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Controllers Module
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | SENSITIVE
//  MISSION: Organize and expose controller modules for API request handling,
//  providing a unified interface for authentication, key management, and mail
//  operations with enterprise security standards.
//  NOTICE: Controllers implement RESTful endpoints with authentication,
//  validation, and audit logging for all API operations.
//  CONTROLLER STANDARDS: REST API, JSON responses, error handling
//  COMPLIANCE: API security best practices, GDPR data handling
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

/// [CONTROLLER MODULE] Base controller for generic API operations
pub mod controller;
/// [AUTH CONTROLLER MODULE] Authentication and session management
pub mod auth_controller;
/// [KEY CONTROLLER MODULE] API key and certificate lifecycle management
pub mod key_controller;
/// [DATA CONTROLLER MODULE] Database connection and query management
pub mod data_controller;
/// [OPENPGP CONTROLLER MODULE] OpenPGP cryptographic operations
pub mod openpgp_controller;