// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise CLI
//  Module: Search Query Builders
// ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Build query parameters for search service API calls.
//  NOTICE: This module provides structured query builders for search operations.
//  SECURITY: Query validation and sanitization
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use serde_json::{json, Value};

/// Search query builders for API requests
#[allow(dead_code)]
pub struct SearchQuery;

#[allow(dead_code)]
impl SearchQuery {
    /// Build query for searching logs
    #[allow(dead_code)]
    pub fn logs(pattern: &str, limit: Option<u64>, level: Option<&str>) -> Value {
        let mut params = json!({
            "pattern": pattern,
            "limit": limit.unwrap_or(100)
        });

        if let Some(lvl) = level {
            params["level"] = json!(lvl);
        }

        params
    }

    /// Build query for searching users
    #[allow(dead_code)]
    pub fn users(query: &str, limit: Option<u64>) -> Value {
        json!({
            "query": query,
            "limit": limit.unwrap_or(50),
            "type": "users"
        })
    }

    /// Build query for searching network devices
    #[allow(dead_code)]
    pub fn devices(query: &str, limit: Option<u64>) -> Value {
        json!({
            "query": query,
            "limit": limit.unwrap_or(50),
            "type": "devices"
        })
    }

    /// Build query for searching security events
    #[allow(dead_code)]
    pub fn security_events(query: &str, limit: Option<u64>, severity: Option<&str>) -> Value {
        let mut params = json!({
            "query": query,
            "limit": limit.unwrap_or(100),
            "type": "security"
        });

        if let Some(sev) = severity {
            params["severity"] = json!(sev);
        }

        params
    }

    /// Build query for global search
    #[allow(dead_code)]
    pub fn global(query: &str, limit: Option<u64>) -> Value {
        json!({
            "query": query,
            "limit": limit.unwrap_or(50),
            "type": "global"
        })
    }
}