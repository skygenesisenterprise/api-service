// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise CLI
//  Module: System Routes
// ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Define API endpoint paths for system service operations.
//  NOTICE: This module provides route constants for system API endpoints.
//  SECURITY: Route definitions for secure API access
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

/// System service API routes
pub struct SystemRoutes;

impl SystemRoutes {
    /// Base path for system service
    pub const BASE: &str = "/api/v1/system";

    /// Status endpoint
    pub const STATUS: &str = "/api/v1/system/status";

    /// Information endpoint
    pub const INFO: &str = "/api/v1/system/info";

    /// Metrics endpoint
    pub const METRICS: &str = "/api/v1/system/metrics";

    /// Health check endpoint
    pub const HEALTH: &str = "/api/v1/system/health";

    /// Services endpoint
    pub const SERVICES: &str = "/api/v1/system/services";

    /// Configuration endpoint
    pub const CONFIG: &str = "/api/v1/system/config";

    /// Logs endpoint
    pub const LOGS: &str = "/api/v1/system/logs";

    /// Processes endpoint
    pub const PROCESSES: &str = "/api/v1/system/processes";

    /// Resources endpoint
    pub const RESOURCES: &str = "/api/v1/system/resources";

    /// Build dynamic route for specific service
    pub fn service(name: &str) -> String {
        format!("/api/v1/system/services/{}", name)
    }

    /// Build dynamic route for service control
    pub fn service_control(name: &str, action: &str) -> String {
        format!("/api/v1/system/services/{}/{}", name, action)
    }

    /// Build dynamic route for specific process
    pub fn process(pid: u32) -> String {
        format!("/api/v1/system/processes/{}", pid)
    }
}