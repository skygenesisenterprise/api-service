// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise CLI
//  Module: VPN Routes
// ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Define API endpoint paths for VPN service operations.
//  NOTICE: This module provides route constants for VPN API endpoints.
//  SECURITY: Route definitions for secure API access
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

/// VPN service API routes
pub struct VpnRoutes;

impl VpnRoutes {
    /// Base path for VPN service
    pub const BASE: &str = "/api/v1/vpn";

    /// Status endpoint
    pub const STATUS: &str = "/api/v1/vpn/status";

    /// Peers endpoint
    pub const PEERS: &str = "/api/v1/vpn/peers";

    /// Connect endpoint
    pub const CONNECT: &str = "/api/v1/vpn/connect";

    /// Disconnect endpoint
    pub const DISCONNECT: &str = "/api/v1/vpn/disconnect";

    /// Configuration endpoint
    pub const CONFIG: &str = "/api/v1/vpn/config";

    /// Keys endpoint
    pub const KEYS: &str = "/api/v1/vpn/keys";

    /// WireGuard status endpoint
    pub const WIREGUARD: &str = "/api/v1/vpn/wireguard";

    /// Tailscale status endpoint
    pub const TAILSCALE: &str = "/api/v1/vpn/tailscale";

    /// Build dynamic route for specific peer
    pub fn peer(name: &str) -> String {
        format!("/api/v1/vpn/peers/{}", name)
    }

    /// Build dynamic route for peer connection
    pub fn peer_connect(name: &str) -> String {
        format!("/api/v1/vpn/peers/{}/connect", name)
    }

    /// Build dynamic route for peer disconnection
    pub fn peer_disconnect(name: &str) -> String {
        format!("/api/v1/vpn/peers/{}/disconnect", name)
    }
}