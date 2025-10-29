// ===============================================================
// SKY GENESIS ENTERPRISE :: AETHER SEARCH MODULE - SERVICE
// CLASSIFIED LEVEL: INTERNAL USE ONLY
// MISSION: Provide secure search service layer with authentication
// PROTOCOLS: OAuth2 | FIDO2 | PGP | TLS 1.3 | VPN Tunnel
// AUDIT TRAIL: Vault + OpenTelemetry | Internal Node ID Signed
// ===============================================================

use std::sync::Arc;
use tokio::sync::RwLock;
use crate::search::core::{AetherSearchEngine, DocumentData};
use crate::search::models::*;
use crate::services::auth_service::AuthService;
use crate::core::vault::VaultClient;
use crate::core::opentelemetry::Metrics;
use crate::middlewares::auth_middleware::Claims;

/// Authentication context for search operations
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub user_id: String,
    pub is_authenticated: bool,
    pub permissions: Vec<String>,
    pub fido2_verified: bool,
    pub is_system_token: bool,
    pub email: Option<String>,
}

impl From<&Claims> for AuthContext {
    fn from(claims: &Claims) -> Self {
        Self {
            user_id: claims.sub.clone(),
            is_authenticated: true,
            permissions: claims.scopes.clone(),
            fido2_verified: false, // Would be set by FIDO2 middleware
            is_system_token: false, // Would be determined by token type
            email: claims.email.clone(),
        }
    }
}

/// Sovereign search service with security controls
pub struct SearchService {
    /// Core search engine
    engine: Arc<RwLock<AetherSearchEngine>>,
    /// Authentication service
    auth_service: Arc<AuthService>,
    /// Vault client for secrets
    vault: Arc<VaultClient>,
    /// Metrics collector
    metrics: Arc<Metrics>,
}

impl SearchService {
    /// Initialize search service
    pub async fn new(
        index_path: &std::path::Path,
        auth_service: Arc<AuthService>,
        vault: Arc<VaultClient>,
        metrics: Arc<Metrics>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let engine = AetherSearchEngine::new(index_path, vault.clone(), metrics.clone()).await?;
        engine.init_writer().await?;

        Ok(Self {
            engine: Arc::new(RwLock::new(engine)),
            auth_service,
            vault,
            metrics,
        })
    }

    /// Execute authenticated search query
    pub async fn search(
        &self,
        query: SearchQuery,
        auth_context: &AuthContext,
    ) -> Result<SearchResponse, Box<dyn std::error::Error + Send + Sync>> {
        // Validate authentication and authorization
        self.validate_search_access(auth_context).await?;

        // Log search audit event
        self.audit_search_query(&query, auth_context).await;

        // Execute search
        let engine = self.engine.read().await;
        let response = engine.search(&query).await?;

        // Apply post-processing security filters
        let filtered_response = self.apply_security_filters(response, auth_context).await;

        Ok(filtered_response)
    }

    /// Generate auto-completion suggestions
    pub async fn suggest(
        &self,
        prefix: String,
        limit: Option<usize>,
        auth_context: &AuthContext,
    ) -> Result<SuggestResponse, Box<dyn std::error::Error + Send + Sync>> {
        // Validate authentication
        self.validate_suggest_access(auth_context).await?;

        let limit = limit.unwrap_or(10).min(50); // Cap at 50 suggestions

        let engine = self.engine.read().await;
        let response = engine.suggest(&prefix, limit).await?;

        Ok(response)
    }

    /// Get index status (admin/internal access only)
    pub async fn get_index_status(
        &self,
        auth_context: &AuthContext,
    ) -> Result<IndexStatusResponse, Box<dyn std::error::Error + Send + Sync>> {
        // Validate admin access
        self.validate_admin_access(auth_context).await?;

        let engine = self.engine.read().await;
        let status = engine.get_stats().await?;

        Ok(IndexStatusResponse {
            indices: vec![status],
            system_status: "operational".to_string(),
        })
    }

    /// Trigger reindex operation (admin only)
    pub async fn reindex(
        &self,
        auth_context: &AuthContext,
    ) -> Result<ReindexStatus, Box<dyn std::error::Error + Send + Sync>> {
        // Validate admin access with FIDO2
        self.validate_admin_fido2_access(auth_context).await?;

        // Start reindex operation (simplified for now)
        let operation_id = format!("reindex_{}", chrono::Utc::now().timestamp());

        // In a real implementation, this would spawn a background task
        // For now, just return status
        Ok(ReindexStatus {
            operation_id,
            status: "started".to_string(),
            progress: 0,
            processed_docs: 0,
            total_docs: 0,
            started_at: chrono::Utc::now().to_rfc3339(),
            estimated_completion: None,
        })
    }

    /// Get search metrics (internal access only)
    pub async fn get_metrics(
        &self,
        auth_context: &AuthContext,
        time_range: Option<String>,
    ) -> Result<MetricsResponse, Box<dyn std::error::Error + Send + Sync>> {
        // Validate internal access
        self.validate_internal_access(auth_context).await?;

        // In a real implementation, this would query metrics storage
        // For now, return mock data
        let time_range = time_range.unwrap_or_else(|| "24h".to_string());

        Ok(MetricsResponse {
            metrics: vec![
                MetricData {
                    name: "search_queries_total".to_string(),
                    value: 1250.0,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    labels: std::collections::HashMap::new(),
                },
                MetricData {
                    name: "search_avg_response_time".to_string(),
                    value: 45.2,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    labels: std::collections::HashMap::new(),
                },
            ],
            time_range,
        })
    }

    /// Index a new document (internal use)
    pub async fn index_document(
        &self,
        doc_data: DocumentData,
        auth_context: &AuthContext,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Validate internal/system access
        self.validate_system_access(auth_context).await?;

        // Validate document data
        self.validate_document_data(&doc_data)?;

        // Index document
        let mut engine = self.engine.write().await;
        engine.index_document(&doc_data).await?;
        engine.commit().await?;

        Ok(())
    }

    /// Validate search access permissions
    async fn validate_search_access(
        &self,
        auth_context: &AuthContext,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Check if user is authenticated
        if !auth_context.is_authenticated {
            return Err("Authentication required".into());
        }

        // Check search permissions
        if !auth_context.permissions.contains(&"search:read".to_string()) {
            return Err("Insufficient permissions for search access".into());
        }

        // Additional VPN/tunnel validation would go here
        // For now, assume VPN access is validated at network level

        Ok(())
    }

    /// Validate suggestion access
    async fn validate_suggest_access(
        &self,
        auth_context: &AuthContext,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Suggestions are public but require authentication
        if !auth_context.is_authenticated {
            return Err("Authentication required".into());
        }

        Ok(())
    }

    /// Validate admin access
    async fn validate_admin_access(
        &self,
        auth_context: &AuthContext,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !auth_context.is_authenticated {
            return Err("Authentication required".into());
        }

        if !auth_context.permissions.contains(&"admin:read".to_string()) {
            return Err("Admin access required".into());
        }

        Ok(())
    }

    /// Validate admin access with FIDO2 requirement
    async fn validate_admin_fido2_access(
        &self,
        auth_context: &AuthContext,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.validate_admin_access(auth_context).await?;

        // Check FIDO2 authentication
        if !auth_context.fido2_verified {
            return Err("FIDO2 verification required for admin operations".into());
        }

        Ok(())
    }

    /// Validate internal access
    async fn validate_internal_access(
        &self,
        auth_context: &AuthContext,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !auth_context.is_authenticated {
            return Err("Authentication required".into());
        }

        if !auth_context.permissions.contains(&"internal:read".to_string()) {
            return Err("Internal access required".into());
        }

        Ok(())
    }

    /// Validate system access (for indexing operations)
    async fn validate_system_access(
        &self,
        auth_context: &AuthContext,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // System operations require special system token
        if !auth_context.is_system_token {
            return Err("System access required".into());
        }

        Ok(())
    }

    /// Apply security filters to search results
    async fn apply_security_filters(
        &self,
        mut response: SearchResponse,
        auth_context: &AuthContext,
    ) -> SearchResponse {
        // Filter results based on user permissions
        // Remove results from sources user doesn't have access to
        response.results.retain(|result| {
            self.user_can_access_source(auth_context, &result.source)
        });

        // Update metadata
        response.metadata.total_results = response.results.len() as u64;

        response
    }

    /// Check if user can access a specific source
    fn user_can_access_source(&self, auth_context: &AuthContext, source: &str) -> bool {
        // Check source-specific permissions
        let required_perm = format!("source:{}:read", source);
        auth_context.permissions.contains(&required_perm) ||
        auth_context.permissions.contains(&"source:all:read".to_string())
    }

    /// Validate document data before indexing
    fn validate_document_data(&self, doc_data: &DocumentData) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if doc_data.id.is_empty() {
            return Err("Document ID cannot be empty".into());
        }

        if doc_data.title.is_empty() {
            return Err("Document title cannot be empty".into());
        }

        if doc_data.content.is_empty() {
            return Err("Document content cannot be empty".into());
        }

        if doc_data.source.is_empty() {
            return Err("Document source cannot be empty".into());
        }

        Ok(())
    }

    /// Audit search query for compliance
    async fn audit_search_query(&self, query: &SearchQuery, auth_context: &AuthContext) {
        // Log search query for audit purposes
        // In a real implementation, this would write to audit log
        println!("AUDIT: User {} searched for '{}' from sources {:?}",
                 auth_context.user_id,
                 query.query,
                 query.filters.as_ref().and_then(|f| f.source.as_ref()));
    }
}