// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise CLI
//  Module: Services
// ----------------------------------------------------------------------------
 //  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Module declarations for service layers.
//  NOTICE: This module exports all service modules.
//  SECURITY: Service layers for secure API interactions
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

pub mod auth_service;
pub mod mail_service;
pub mod search_service;
pub mod telemetry_service;
pub mod vpn_service;

// Re-export commonly used types
pub use auth_service::*;
pub use mail_service::*;
pub use search_service::*;
pub use telemetry_service::*;
pub use vpn_service::*;