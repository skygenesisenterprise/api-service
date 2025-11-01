// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Middlewares Module
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Organize and expose middleware modules for request processing,
//  authentication, authorization, and security enforcement.
//  NOTICE: Middlewares implement cross-cutting concerns with security,
//  logging, and request processing for all API endpoints.
//  MIDDLEWARE STANDARDS: Authentication, Authorization, Logging, Security
//  COMPLIANCE: Security Best Practices, API Security Standards
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

/// [AUTH MIDDLEWARE MODULE] API key authentication and validation
pub mod auth;
/// [LOGGING MIDDLEWARE MODULE] Request/response logging and monitoring
pub mod logging;
/// [ADVANCED AUTH MIDDLEWARE MODULE] JWT, mTLS, and combined authentication
pub mod auth_middleware;
/// [AUTH GUARD MIDDLEWARE MODULE] JWT token validation and claims extraction
pub mod auth_guard;
/// [CERT AUTH MIDDLEWARE MODULE] Certificate-based authentication with signatures
pub mod cert_auth_middleware;
/// [OPENPGP MIDDLEWARE MODULE] PGP key validation and cryptographic middleware
pub mod openpgp_middleware;