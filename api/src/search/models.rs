// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Search Data Models
// // ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | SENSITIVE
//  MISSION: Define data models for search functionality.
//  NOTICE: This module contains search-related data structures and validation.
//  INTEGRATION: Search service, API controllers, database models
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use validator::Validate;

/// [SEARCH QUERY MODEL] API Search Request Model
/// @MISSION Define search query structure for API requests.
/// @THREAT Query injection or search manipulation.
/// @COUNTERMEASURE Input validation and query sanitization.
/// @INVARIANT All search parameters are validated and bounded.
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct SearchQuery {
    /// Search query string
    #[validate(length(min = 1, max = 1000), custom(function = "validate_query"))]
    pub q: String,

    /// Content type filters
    #[validate(length(max = 10))]
    pub content_type: Option<Vec<String>>,

    /// Date range filter
    pub date_range: Option<DateRangeFilter>,

    /// Tag filters
    #[validate(length(max = 20))]
    pub tags: Option<Vec<String>>,

    /// Category filters
    #[validate(length(max = 20))]
    pub categories: Option<Vec<String>>,

    /// Author filters
    #[validate(length(max = 10))]
    pub authors: Option<Vec<String>>,

    /// Status filters
    #[validate(length(max = 10))]
    pub status: Option<Vec<String>>,

    /// Pagination offset
    #[validate(range(min = 0, max = 10000))]
    pub offset: Option<usize>,

    /// Pagination limit
    #[validate(range(min = 1, max = 100))]
    pub limit: Option<usize>,

    /// Sort field
    #[validate(length(min = 1, max = 50))]
    pub sort_by: Option<String>,

    /// Sort order
    pub sort_order: Option<SortOrder>,

    /// Enable highlighting
    pub highlight: Option<bool>,

    /// Facet fields
    #[validate(length(max = 10))]
    pub facets: Option<Vec<String>>,
}

/// [DATE RANGE FILTER] Date Filtering Model
/// @MISSION Define date range filtering parameters.
/// @THREAT Date manipulation or unauthorized access.
/// @COUNTERMEASURE Date validation and range limits.
/// @INVARIANT Date ranges are bounded and validated.
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct DateRangeFilter {
    /// Start date (ISO 8601 format)
    #[validate(custom(function = "validate_date"))]
    pub start: Option<String>,

    /// End date (ISO 8601 format)
    #[validate(custom(function = "validate_date"))]
    pub end: Option<String>,

    /// Date field to filter on
    #[validate(length(min = 1, max = 50))]
    pub field: Option<String>,
}

/// [SORT ORDER ENUM] Sorting Direction
/// @MISSION Define sorting direction enumeration.
/// @THREAT Sort manipulation.
/// @COUNTERMEASURE Enum validation and type safety.
/// @INVARIANT Sort order is validated before use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SortOrder {
    #[serde(rename = "asc")]
    Asc,
    #[serde(rename = "desc")]
    Desc,
}

/// [SEARCH RESULT MODEL] API Search Response Model
/// @MISSION Define search response structure for API responses.
/// @THREAT Result manipulation or data leakage.
/// @COUNTERMEASURE Permission filtering and result validation.
/// @INVARIANT All results respect user access permissions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    /// Search result identifier
    pub id: String,

    /// Search relevance score
    pub score: f32,

    /// Document title
    pub title: Option<String>,

    /// Document content snippet
    pub content: Option<String>,

    /// Content type
    pub content_type: Option<String>,

    /// Document author
    pub author: Option<String>,

    /// Creation timestamp
    pub created_at: Option<String>,

    /// Last update timestamp
    pub updated_at: Option<String>,

    /// Document tags
    pub tags: Option<Vec<String>>,

    /// Document categories
    pub categories: Option<Vec<String>>,

    /// Highlighted snippets
    pub highlights: Option<HashMap<String, Vec<String>>>,

    /// Additional metadata
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

/// [SEARCH RESPONSE MODEL] Complete Search Response
/// @MISSION Container for complete search response data.
/// @THREAT Response manipulation or information leakage.
/// @COUNTERMEASURE Response validation and permission checks.
/// @INVARIANT Response respects user permissions and access controls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResponse {
    /// Search results
    pub results: Vec<SearchResult>,

    /// Total number of results
    pub total: usize,

    /// Query execution time in milliseconds
    pub took: u64,

    /// Faceted search results
    pub facets: Option<HashMap<String, HashMap<String, usize>>>,

    /// Search suggestions
    pub suggestions: Option<Vec<SearchSuggestion>>,

    /// Pagination information
    pub pagination: PaginationInfo,

    /// Search query metadata
    pub query_info: QueryInfo,
}

/// [SEARCH SUGGESTION MODEL] Autocomplete Suggestion
/// @MISSION Define search suggestion structure.
/// @THREAT Suggestion manipulation or information leakage.
/// @COUNTERMEASURE Suggestion filtering and access control.
/// @INVARIANT Suggestions respect user permissions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchSuggestion {
    /// Suggestion text
    pub text: String,

    /// Suggestion relevance score
    pub score: f32,

    /// Suggestion source/type
    pub source: String,

    /// Suggestion metadata
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

/// [PAGINATION INFO MODEL] Pagination Metadata
/// @MISSION Define pagination information for search results.
/// @THREAT Pagination manipulation or resource exhaustion.
/// @COUNTERMEASURE Pagination validation and limits.
/// @INVARIANT Pagination parameters are bounded and validated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationInfo {
    /// Current page offset
    pub offset: usize,

    /// Current page limit
    pub limit: usize,

    /// Total number of pages
    pub total_pages: usize,

    /// Current page number (1-based)
    pub current_page: usize,

    /// Has next page
    pub has_next: bool,

    /// Has previous page
    pub has_previous: bool,
}

/// [QUERY INFO MODEL] Search Query Metadata
/// @MISSION Define query execution metadata.
/// @THREAT Information disclosure or system probing.
/// @COUNTERMEASURE Access controls and data filtering.
/// @INVARIANT Query info respects security constraints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryInfo {
    /// Original query string
    pub query: String,

    /// Parsed query terms
    pub terms: Vec<String>,

    /// Applied filters
    pub filters: Vec<String>,

    /// Query execution time breakdown
    pub timing: QueryTiming,

    /// Query optimization info
    pub optimization: Option<QueryOptimization>,
}

/// [QUERY TIMING MODEL] Query Performance Metrics
/// @MISSION Define query execution timing information.
/// @THREAT Performance monitoring or system probing.
/// @COUNTERMEASURE Access controls and metric aggregation.
/// @INVARIANT Timing data is aggregated and sanitized.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryTiming {
    /// Query parsing time (ms)
    pub parse_time: u64,

    /// Query planning time (ms)
    pub plan_time: u64,

    /// Query execution time (ms)
    pub execution_time: u64,

    /// Result processing time (ms)
    pub processing_time: u64,

    /// Total query time (ms)
    pub total_time: u64,
}

/// [QUERY OPTIMIZATION MODEL] Query Optimization Info
/// @MISSION Define query optimization details.
/// @THREAT Information disclosure or system analysis.
/// @COUNTERMEASURE Access controls and data filtering.
/// @INVARIANT Optimization info respects security boundaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryOptimization {
    /// Query optimization level
    pub level: String,

    /// Applied optimizations
    pub optimizations: Vec<String>,

    /// Optimization score
    pub score: f32,

    /// Optimization suggestions
    pub suggestions: Vec<String>,
}

/// [SEARCH INDEX MODEL] Search Index Information
/// @MISSION Define search index metadata and statistics.
/// @THREAT Information disclosure or system probing.
/// @COUNTERMEASURE Access controls and metric filtering.
/// @INVARIANT Index info respects user permissions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchIndex {
    /// Index identifier
    pub id: String,

    /// Index name
    pub name: String,

    /// Index status
    pub status: IndexStatus,

    /// Document count
    pub document_count: usize,

    /// Index size in bytes
    pub size_bytes: u64,

    /// Last update timestamp
    pub last_updated: String,

    /// Index configuration
    pub configuration: IndexConfiguration,

    /// Index statistics
    pub statistics: IndexStatistics,
}

/// [INDEX STATUS ENUM] Index Status Enumeration
/// @MISSION Define index status values.
/// @THREAT Status manipulation or information leakage.
/// @COUNTERMEASURE Enum validation and access controls.
/// @INVARIANT Status values are validated and controlled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IndexStatus {
    #[serde(rename = "active")]
    Active,
    #[serde(rename = "building")]
    Building,
    #[serde(rename = "optimizing")]
    Optimizing,
    #[serde(rename = "error")]
    Error,
    #[serde(rename = "maintenance")]
    Maintenance,
}

/// [INDEX CONFIGURATION MODEL] Index Configuration
/// @MISSION Define index configuration parameters.
/// @THREAT Configuration manipulation or security bypass.
/// @COUNTERMEASURE Configuration validation and access controls.
/// @INVARIANT Configuration respects security policies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexConfiguration {
    /// Index schema version
    pub schema_version: String,

    /// Analyzer configuration
    pub analyzers: HashMap<String, AnalyzerConfig>,

    /// Field mappings
    pub field_mappings: HashMap<String, FieldMapping>,

    /// Index settings
    pub settings: IndexSettings,
}

/// [ANALYZER CONFIG MODEL] Text Analyzer Configuration
/// @MISSION Define text analyzer configuration.
/// @THREAT Analyzer manipulation or search bypass.
/// @COUNTERMEASURE Analyzer validation and security checks.
/// @INVARIANT Analyzer configuration is validated and controlled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzerConfig {
    /// Analyzer type
    pub analyzer_type: String,

    /// Tokenizer configuration
    pub tokenizer: Option<TokenizerConfig>,

    /// Filter configuration
    pub filters: Vec<FilterConfig>,
}

/// [TOKENIZER CONFIG MODEL] Tokenizer Configuration
/// @MISSION Define tokenizer configuration parameters.
/// @THREAT Tokenizer manipulation or search bypass.
/// @COUNTERMEASURE Tokenizer validation and security checks.
/// @INVARIANT Tokenizer configuration is validated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenizerConfig {
    /// Tokenizer type
    pub tokenizer_type: String,

    /// Tokenizer parameters
    pub parameters: HashMap<String, serde_json::Value>,
}

/// [FILTER CONFIG MODEL] Filter Configuration
/// @MISSION Define filter configuration parameters.
/// @THREAT Filter manipulation or search bypass.
/// @COUNTERMEASURE Filter validation and security checks.
/// @INVARIANT Filter configuration is validated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterConfig {
    /// Filter type
    pub filter_type: String,

    /// Filter parameters
    pub parameters: HashMap<String, serde_json::Value>,
}

/// [FIELD MAPPING MODEL] Field Mapping Configuration
/// @MISSION Define field mapping for index schema.
/// @THREAT Field manipulation or data leakage.
/// @COUNTERMEASURE Field validation and access controls.
/// @INVARIANT Field mappings respect security policies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldMapping {
    /// Field type
    pub field_type: String,

    /// Field is indexed
    pub indexed: bool,

    /// Field is stored
    pub stored: bool,

    /// Field analyzer
    pub analyzer: Option<String>,

    /// Field parameters
    pub parameters: HashMap<String, serde_json::Value>,
}

/// [INDEX SETTINGS MODEL] Index Settings Configuration
/// @MISSION Define index-wide settings.
/// @THREAT Settings manipulation or performance issues.
/// @COUNTERMEASURE Settings validation and security checks.
/// @INVARIANT Settings respect system constraints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexSettings {
    /// Number of shards
    pub number_of_shards: u32,

    /// Number of replicas
    pub number_of_replicas: u32,

    /// Refresh interval
    pub refresh_interval: String,

    /// Maximum result window
    pub max_result_window: usize,

    /// Analysis settings
    pub analysis: Option<AnalysisSettings>,
}

/// [ANALYSIS SETTINGS MODEL] Text Analysis Configuration
/// @MISSION Define text analysis settings.
/// @THREAT Analysis manipulation or search bypass.
/// @COUNTERMEASURE Analysis validation and security checks.
/// @INVARIANT Analysis settings are controlled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisSettings {
    /// Character filters
    pub char_filters: HashMap<String, FilterConfig>,

    /// Tokenizers
    pub tokenizers: HashMap<String, TokenizerConfig>,

    /// Token filters
    pub token_filters: HashMap<String, FilterConfig>,

    /// Analyzers
    pub analyzers: HashMap<String, AnalyzerConfig>,
}

/// [INDEX STATISTICS MODEL] Index Performance Statistics
/// @MISSION Define index performance and usage statistics.
/// @THREAT Information disclosure or system probing.
/// @COUNTERMEASURE Access controls and metric aggregation.
/// @INVARIANT Statistics are aggregated and sanitized.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexStatistics {
    /// Query count
    pub query_count: u64,

    /// Average query time
    pub avg_query_time: f64,

    /// Index size growth rate
    pub size_growth_rate: f64,

    /// Document addition rate
    pub doc_addition_rate: f64,

    /// Cache hit ratio
    pub cache_hit_ratio: f64,

    /// Memory usage
    pub memory_usage: MemoryUsage,
}

/// [MEMORY USAGE MODEL] Memory Usage Statistics
/// @MISSION Define memory usage metrics.
/// @THREAT Resource monitoring or system probing.
/// @COUNTERMEASURE Access controls and metric aggregation.
/// @INVARIANT Memory metrics are aggregated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryUsage {
    /// Heap memory usage in bytes
    pub heap_used: u64,

    /// Heap memory committed in bytes
    pub heap_committed: u64,

    /// Non-heap memory usage in bytes
    pub non_heap_used: u64,

    /// Cache memory usage in bytes
    pub cache_used: u64,

    /// Total memory usage in bytes
    pub total_used: u64,
}

// Validation functions
fn validate_query(query: &str) -> Result<(), validator::ValidationError> {
    if query.chars().any(|c| c.is_control() && c != '\t' && c != '\n' && c != '\r') {
        return Err(validator::ValidationError::new("invalid_characters"));
    }
    Ok(())
}

fn validate_date(date: &str) -> Result<(), validator::ValidationError> {
    // Basic ISO 8601 validation
    if date.len() < 10 {
        return Err(validator::ValidationError::new("invalid_format"));
    }
    Ok(())
}

impl Default for SearchQuery {
    fn default() -> Self {
        SearchQuery {
            q: String::new(),
            content_type: None,
            date_range: None,
            tags: None,
            categories: None,
            authors: None,
            status: None,
            offset: Some(0),
            limit: Some(10),
            sort_by: None,
            sort_order: Some(SortOrder::Desc),
            highlight: Some(false),
            facets: None,
        }
    }
}

impl Default for SortOrder {
    fn default() -> Self {
        SortOrder::Desc
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use validator::Validate;

    #[test]
    fn test_search_query_validation() {
        let valid_query = SearchQuery {
            q: "test query".to_string(),
            content_type: Some(vec!["document".to_string()]),
            offset: Some(0),
            limit: Some(10),
            ..Default::default()
        };

        assert!(valid_query.validate().is_ok());

        let invalid_query = SearchQuery {
            q: "".to_string(),
            ..Default::default()
        };

        assert!(invalid_query.validate().is_err());
    }

    #[test]
    fn test_date_range_validation() {
        let valid_range = DateRangeFilter {
            start: Some("2023-01-01T00:00:00Z".to_string()),
            end: Some("2023-12-31T23:59:59Z".to_string()),
            field: Some("created_at".to_string()),
        };

        assert!(valid_range.validate().is_ok());

        let invalid_range = DateRangeFilter {
            start: Some("invalid".to_string()),
            end: None,
            field: None,
        };

        assert!(invalid_range.validate().is_err());
    }

    #[test]
    fn test_sort_order_serialization() {
        let asc = SortOrder::Asc;
        let serialized = serde_json::to_string(&asc).unwrap();
        assert_eq!(serialized, "\"asc\"");

        let desc: SortOrder = serde_json::from_str("\"desc\"").unwrap();
        assert!(matches!(desc, SortOrder::Desc));
    }

    #[test]
    fn test_search_response_structure() {
        let response = SearchResponse {
            results: vec![],
            total: 0,
            took: 10,
            facets: None,
            suggestions: None,
            pagination: PaginationInfo {
                offset: 0,
                limit: 10,
                total_pages: 0,
                current_page: 1,
                has_next: false,
                has_previous: false,
            },
            query_info: QueryInfo {
                query: "test".to_string(),
                terms: vec!["test".to_string()],
                filters: vec![],
                timing: QueryTiming {
                    parse_time: 1,
                    plan_time: 2,
                    execution_time: 5,
                    processing_time: 2,
                    total_time: 10,
                },
                optimization: None,
            },
        };

        let serialized = serde_json::to_string(&response).unwrap();
        assert!(serialized.contains("\"total\":0"));
        assert!(serialized.contains("\"took\":10"));
    }
}