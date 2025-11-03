// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise CLI
//  Module: Network Routes
// ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Define API endpoint paths for network service operations.
//  NOTICE: This module provides route constants for network API endpoints.
//  SECURITY: Route definitions for secure API access
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

/// Network service API routes
#[allow(dead_code)]
pub struct NetworkRoutes;

#[allow(dead_code)]
impl NetworkRoutes {
    /// Base path for network service
    pub const BASE: &str = "/api/v1/network";

    /// Status endpoint
    pub const STATUS: &str = "/api/v1/network/status";

    /// Interfaces endpoint
    pub const INTERFACES: &str = "/api/v1/network/interfaces";

    /// Routes endpoint
    pub const ROUTES: &str = "/api/v1/network/routes";

    /// Connections endpoint
    pub const CONNECTIONS: &str = "/api/v1/network/connections";

    /// Firewall rules endpoint
    pub const FIREWALL: &str = "/api/v1/network/firewall";

    /// DNS configuration endpoint
    pub const DNS: &str = "/api/v1/network/dns";

    /// DHCP configuration endpoint
    pub const DHCP: &str = "/api/v1/network/dhcp";

    /// Bandwidth monitoring endpoint
    pub const BANDWIDTH: &str = "/api/v1/network/bandwidth";

    /// Build dynamic route for specific interface
    pub fn interface(name: &str) -> String {
        format!("/api/v1/network/interfaces/{}", name)
    }

    /// Build dynamic route for specific route
    pub fn route(id: &str) -> String {
        format!("/api/v1/network/routes/{}", id)
    }

    /// Build dynamic route for specific connection
    pub fn connection(id: &str) -> String {
        format!("/api/v1/network/connections/{}", id)
    }
}