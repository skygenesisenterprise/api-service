// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise CLI
//  Module: Search Service
// ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide search business logic for CLI operations.
//  NOTICE: This module encapsulates search operations using the API client.
//  SECURITY: Secure search handling and result filtering
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use crate::core::api_client::SshApiClient;
use crate::queries::search_query::SearchQuery;
use anyhow::Result;
use serde_json::Value;

/// Search service for CLI operations
pub struct SearchService<'a> {
    client: &'a SshApiClient,
}

impl<'a> SearchService<'a> {
    /// Create new search service
    pub fn new(client: &'a SshApiClient) -> Self {
        Self { client }
    }

    /// Search logs
    pub async fn search_logs(&self, pattern: &str, limit: Option<u64>, level: Option<&str>) -> Result<Value> {
        let params = SearchQuery::logs(pattern, limit, level);
        let result = self.client.call_method("search.logs", params)?;
        Ok(result)
    }

    /// Search users
    pub async fn search_users(&self, query: &str, limit: Option<u64>) -> Result<Value> {
        let params = SearchQuery::users(query, limit);
        let result = self.client.call_method("search.users", params)?;
        Ok(result)
    }

    /// Search devices
    pub async fn search_devices(&self, query: &str, limit: Option<u64>) -> Result<Value> {
        let params = SearchQuery::devices(query, limit);
        let result = self.client.call_method("search.devices", params)?;
        Ok(result)
    }

    /// Search security events
    pub async fn search_security_events(&self, query: &str, limit: Option<u64>, severity: Option<&str>) -> Result<Value> {
        let params = SearchQuery::security_events(query, limit, severity);
        let result = self.client.call_method("search.security_events", params)?;
        Ok(result)
    }

    /// Global search
    pub async fn global_search(&self, query: &str, limit: Option<u64>) -> Result<Value> {
        let params = SearchQuery::global(query, limit);
        let result = self.client.call_method("search.global", params)?;
        Ok(result)
    }

    /// Get search suggestions
    pub async fn get_suggestions(&self, query: &str) -> Result<Value> {
        let params = serde_json::json!({
            "query": query
        });
        let result = self.client.call_method("search.suggestions", params)?;
        Ok(result)
    }

    /// Get search statistics
    pub async fn get_statistics(&self) -> Result<Value> {
        let params = serde_json::json!({});
        let result = self.client.call_method("search.statistics", params)?;
        Ok(result)
    }
}