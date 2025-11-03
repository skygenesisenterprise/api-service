// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise CLI
//  Module: Mail Query Builders
// ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Build query parameters for mail service API calls.
//  NOTICE: This module provides structured query builders for mail operations.
//  SECURITY: Query validation and sanitization
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use serde_json::{json, Value};

/// Mail query builders for API requests
#[allow(dead_code)]
pub struct MailQuery;

#[allow(dead_code)]
impl MailQuery {
    /// Build query for mail service status
    #[allow(dead_code)]
    pub fn status() -> Value {
        json!({
            "action": "status"
        })
    }

    /// Build query for sending test email
    #[allow(dead_code)]
    pub fn send_test(to: &str) -> Value {
        json!({
            "action": "send_test",
            "to": to
        })
    }

    /// Build query for sending email
    #[allow(dead_code)]
    pub fn send_email(to: &str, subject: &str, body: &str) -> Value {
        json!({
            "action": "send",
            "to": to,
            "subject": subject,
            "body": body
        })
    }

    /// Build query for mail configuration
    #[allow(dead_code)]
    pub fn get_config() -> Value {
        json!({
            "action": "get_config"
        })
    }

    /// Build query for updating mail configuration
    #[allow(dead_code)]
    pub fn update_config(smtp_host: &str, smtp_port: u16, username: &str) -> Value {
        json!({
            "action": "update_config",
            "smtp_host": smtp_host,
            "smtp_port": smtp_port,
            "username": username
        })
    }
}