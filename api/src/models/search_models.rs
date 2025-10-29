// ===============================================================
// SKY GENESIS ENTERPRISE :: AETHER SEARCH MODULE - MODELS
// CLASSIFIED LEVEL: INTERNAL USE ONLY
// MISSION: Define sovereign search data structures
// PROTOCOLS: OAuth2 | FIDO2 | PGP | TLS 1.3 | VPN Tunnel
// AUDIT TRAIL: Vault + OpenTelemetry | Internal Node ID Signed
// ===============================================================

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Search query filters
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SearchFilters {
    /// Source systems to search in (e.g., ["aether_mail", "aether_office"])
    pub source: Option<Vec<String>>,
    /// Language filter (e.g., "fr", "en")
    pub lang: Option<String>,
    /// Date range filter
    pub date_from: Option<String>,
    pub date_to: Option<String>,
    /// Additional custom filters
    pub custom: Option<HashMap<String, String>>,
}

/// Main search query structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SearchQuery {
    /// Search query string
    pub query: String,
    /// Optional filters
    pub filters: Option<SearchFilters>,
    /// Maximum number of results to return
    pub limit: Option<u32>,
    /// Sort order ("relevance", "date", "score")
    pub sort: Option<String>,
    /// Pagination offset
    pub offset: Option<u32>,
}

/// Individual search result
#[derive(Debug, Clone, Serialize)]
pub struct SearchResult {
    /// Unique identifier for the result
    pub id: String,
    /// Title of the result
    pub title: String,
    /// Snippet/excerpt from the content
    pub snippet: String,
    /// Source system (e.g., "aether_mail", "aether_office")
    pub source: String,
    /// Relevance score (0.0 to 1.0)
    pub score: f32,
    /// URL to access the full content
    pub url: String,
    /// Timestamp of the content
    pub timestamp: Option<String>,
    /// Additional metadata
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

/// Search response metadata
#[derive(Debug, Clone, Serialize)]
pub struct SearchMetadata {
    /// Query processing time in milliseconds
    pub query_time_ms: u64,
    /// Total number of results found
    pub total_results: u64,
    /// Sources that were searched
    pub sources: Vec<String>,
    /// Pagination information
    pub pagination: Option<PaginationInfo>,
}

/// Pagination information
#[derive(Debug, Clone, Serialize)]
pub struct PaginationInfo {
    /// Current page offset
    pub offset: u32,
    /// Number of results per page
    pub limit: u32,
    /// Total number of pages
    pub total_pages: u32,
}

/// Complete search response
#[derive(Debug, Clone, Serialize)]
pub struct SearchResponse {
    /// Array of search results
    pub results: Vec<SearchResult>,
    /// Response metadata
    pub metadata: SearchMetadata,
}

/// Auto-completion suggestion
#[derive(Debug, Clone, Serialize)]
pub struct Suggestion {
    /// Suggested query text
    pub text: String,
    /// Suggestion score/confidence
    pub score: f32,
    /// Type of suggestion
    pub suggestion_type: String,
}

/// Auto-completion response
#[derive(Debug, Clone, Serialize)]
pub struct SuggestResponse {
    /// Array of suggestions
    pub suggestions: Vec<Suggestion>,
    /// Query processing time
    pub query_time_ms: u64,
}

/// Index status information
#[derive(Debug, Clone, Serialize)]
pub struct IndexStatus {
    /// Index name
    pub name: String,
    /// Number of documents indexed
    pub doc_count: u64,
    /// Index size in bytes
    pub size_bytes: u64,
    /// Last update timestamp
    pub last_updated: String,
    /// Index health status
    pub status: String,
}

/// Index status response
#[derive(Debug, Clone, Serialize)]
pub struct IndexStatusResponse {
    /// Array of index statuses
    pub indices: Vec<IndexStatus>,
    /// Overall system status
    pub system_status: String,
}

/// Reindex operation status
#[derive(Debug, Clone, Serialize)]
pub struct ReindexStatus {
    /// Operation ID
    pub operation_id: String,
    /// Current status
    pub status: String,
    /// Progress percentage (0-100)
    pub progress: u8,
    /// Number of documents processed
    pub processed_docs: u64,
    /// Total documents to process
    pub total_docs: u64,
    /// Start timestamp
    pub started_at: String,
    /// Estimated completion time
    pub estimated_completion: Option<String>,
}

/// Metrics data point
#[derive(Debug, Clone, Serialize)]
pub struct MetricData {
    /// Metric name
    pub name: String,
    /// Metric value
    pub value: f64,
    /// Timestamp
    pub timestamp: String,
    /// Additional labels
    pub labels: HashMap<String, String>,
}

/// Search metrics response
#[derive(Debug, Clone, Serialize)]
pub struct MetricsResponse {
    /// Array of metrics
    pub metrics: Vec<MetricData>,
    /// Time range covered
    pub time_range: String,
}

/// Error response structure
#[derive(Debug, Clone, Serialize)]
pub struct SearchError {
    /// Error code
    pub code: String,
    /// Human-readable error message
    pub message: String,
    /// Additional error details
    pub details: Option<HashMap<String, serde_json::Value>>,
}