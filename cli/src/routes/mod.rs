// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise CLI
//  Module: Routes
// ----------------------------------------------------------------------------
 //  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Module declarations for route definitions.
//  NOTICE: This module exports all route modules.
//  SECURITY: Route definitions for secure API access
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

pub mod mail_routes;
pub mod network_routes;
pub mod search_routes;
pub mod system_routes;
pub mod vpn_routes;

// Re-export commonly used types
pub use mail_routes::*;
pub use network_routes::*;
pub use search_routes::*;
pub use system_routes::*;
pub use vpn_routes::*;