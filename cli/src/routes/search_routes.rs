// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise CLI
//  Module: Search Routes
// ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Define API endpoint paths for search service operations.
//  NOTICE: This module provides route constants for search API endpoints.
//  SECURITY: Route definitions for secure API access
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

/// Search service API routes
#[allow(dead_code)]
pub struct SearchRoutes;

#[allow(dead_code)]
impl SearchRoutes {
    /// Base path for search service
    pub const BASE: &str = "/api/v1/search";

    /// Global search endpoint
    pub const GLOBAL: &str = "/api/v1/search/global";

    /// Logs search endpoint
    pub const LOGS: &str = "/api/v1/search/logs";

    /// Users search endpoint
    pub const USERS: &str = "/api/v1/search/users";

    /// Devices search endpoint
    pub const DEVICES: &str = "/api/v1/search/devices";

    /// Security events search endpoint
    pub const SECURITY: &str = "/api/v1/search/security";

    /// Audit logs search endpoint
    pub const AUDIT: &str = "/api/v1/search/audit";

    /// Network events search endpoint
    pub const NETWORK: &str = "/api/v1/search/network";

    /// System events search endpoint
    pub const SYSTEM: &str = "/api/v1/search/system";

    /// Build dynamic route for search with filters
    pub fn filtered(search_type: &str, filters: &[(&str, &str)]) -> String {
        let mut query = format!("/api/v1/search/{}?", search_type);
        let filter_str = filters.iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&");
        query.push_str(&filter_str);
        query
    }

    /// Build route for search suggestions
    pub fn suggestions(search_type: &str) -> String {
        format!("/api/v1/search/{}/suggestions", search_type)
    }
}