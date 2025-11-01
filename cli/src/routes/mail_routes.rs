// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise CLI
//  Module: Mail Routes
// ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Define API endpoint paths for mail service operations.
//  NOTICE: This module provides route constants for mail API endpoints.
//  SECURITY: Route definitions for secure API access
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

/// Mail service API routes
pub struct MailRoutes;

impl MailRoutes {
    /// Base path for mail service
    pub const BASE: &str = "/api/v1/mail";

    /// Status endpoint
    pub const STATUS: &str = "/api/v1/mail/status";

    /// Send email endpoint
    pub const SEND: &str = "/api/v1/mail/send";

    /// Send test email endpoint
    pub const SEND_TEST: &str = "/api/v1/mail/test";

    /// Configuration endpoint
    pub const CONFIG: &str = "/api/v1/mail/config";

    /// Queue status endpoint
    pub const QUEUE: &str = "/api/v1/mail/queue";

    /// Templates endpoint
    pub const TEMPLATES: &str = "/api/v1/mail/templates";

    /// Logs endpoint
    pub const LOGS: &str = "/api/v1/mail/logs";

    /// Build dynamic route for specific template
    pub fn template(name: &str) -> String {
        format!("/api/v1/mail/templates/{}", name)
    }

    /// Build dynamic route for specific email
    pub fn email(id: &str) -> String {
        format!("/api/v1/mail/emails/{}", id)
    }
}