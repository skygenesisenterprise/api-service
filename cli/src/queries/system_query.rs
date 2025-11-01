// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise CLI
//  Module: System Query Builders
// ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Build query parameters for system service API calls.
//  NOTICE: This module provides structured query builders for system operations.
//  SECURITY: Query validation and sanitization
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use serde_json::{json, Value};

/// System query builders for API requests
pub struct SystemQuery;

impl SystemQuery {
    /// Build query for system status
    pub fn status() -> Value {
        json!({
            "action": "status"
        })
    }

    /// Build query for system metrics
    pub fn metrics() -> Value {
        json!({
            "action": "metrics"
        })
    }

    /// Build query for system information
    pub fn info() -> Value {
        json!({
            "action": "info"
        })
    }

    /// Build query for service status
    pub fn service_status(service_name: &str) -> Value {
        json!({
            "action": "service_status",
            "service": service_name
        })
    }

    /// Build query for service control (start/stop/restart)
    pub fn service_control(service_name: &str, action: &str) -> Value {
        json!({
            "action": "service_control",
            "service": service_name,
            "control_action": action
        })
    }

    /// Build query for system logs
    pub fn logs(limit: Option<u64>, level: Option<&str>) -> Value {
        let mut params = json!({
            "action": "logs",
            "limit": limit.unwrap_or(100)
        });

        if let Some(lvl) = level {
            params["level"] = json!(lvl);
        }

        params
    }

    /// Build query for system configuration
    pub fn config() -> Value {
        json!({
            "action": "config"
        })
    }

    /// Build query for system health check
    pub fn health() -> Value {
        json!({
            "action": "health"
        })
    }
}