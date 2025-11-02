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
/// [DEVICE CONTROLLER MODULE] Remote device management operations
pub mod device_controller;
/// [MAC CONTROLLER MODULE] MAC identity management operations
pub mod mac_controller;
/// [VOIP CONTROLLER MODULE] Voice over IP and video conferencing operations
pub mod voip_controller;
/// [DISCORD CONTROLLER MODULE] Discord bot integration operations
pub mod discord_controller;
/// [GIT CONTROLLER MODULE] GitHub webhook integration operations
pub mod git_controller;
/// [LOGGER CONTROLLER MODULE] Logger operations and API endpoints
pub mod logger_controller;
/// [GRAFANA CONTROLLER MODULE] Grafana API management operations
pub mod grafana_controller;