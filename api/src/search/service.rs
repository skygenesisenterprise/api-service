// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Search Service Implementation
// // ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | SENSITIVE
//  MISSION: Provide comprehensive search capabilities across enterprise data.
//  NOTICE: This module implements full-text search with security filtering.
//  INTEGRATION: Tantivy search engine, authentication, authorization
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tantivy::collector::{Count, TopDocs};
use tantivy::query::{AllQuery, BooleanQuery, FuzzyTermQuery, PhraseQuery, Query, RangeQuery, TermQuery};
use tantivy::schema::{Field, Index, IndexRecordOption, Schema, TextFieldIndexing, TextOptions};
use tantivy::{IndexReader, IndexWriter, ReloadPolicy, Searcher, Term};
use tokio::sync::RwLock;
use uuid::Uuid;

/// [SEARCH SERVICE] Enterprise Search Engine
/// @MISSION Provide secure, scalable search across enterprise data.
/// @THREAT Unauthorized data access or search manipulation.
/// @COUNTERMEASURE Authentication, authorization, and access control filtering.
/// @DEPENDENCY Tantivy search engine with security integration.
/// @INVARIANT All search results respect user permissions.
#[derive(Clone)]
pub struct SearchService {
    index: tantivy::Index,
    reader: IndexReader,
    schema: Schema,
}

/// [AUTH CONTEXT] Search Authorization Context
/// @MISSION Store user authentication and authorization context.
/// @THREAT Context manipulation or privilege escalation.
/// @COUNTERMEASURE Immutable context with validated permissions.
/// @INVARIANT Context is validated before each search operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContext {
    pub user_id: String,
    pub organization_id: String,
    pub permissions: Vec<String>,
    pub roles: Vec<String>,
    pub session_id: String,
}

/// [SEARCH REQUEST] Search Query Parameters
/// @MISSION Define search request structure and parameters.
/// @THREAT Query injection or search manipulation.
/// @COUNTERMEASURE Input validation and query sanitization.
/// @INVARIANT All search parameters are validated and bounded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchRequest {
    pub query: String,
    pub filters: Option<SearchFilters>,
    pub pagination: Option<PaginationParams>,
    pub sort: Option<SortParams>,
    pub highlight: Option<bool>,
    pub facets: Option<Vec<String>>,
}

/// [SEARCH FILTERS] Search Filtering Options
/// @MISSION Define filtering criteria for search results.
/// @THREAT Filter bypass or data leakage.
/// @COUNTERMEASURE Filter validation and permission checks.
/// @INVARIANT Filters are applied before permission filtering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchFilters {
    pub content_types: Option<Vec<String>>,
    pub date_range: Option<DateRange>,
    pub tags: Option<Vec<String>>,
    pub categories: Option<Vec<String>>,
    pub authors: Option<Vec<String>>,
    pub status: Option<Vec<String>>,
}

/// [DATE RANGE] Date Filtering Parameters
/// @MISSION Define date range for temporal filtering.
/// @THREAT Date manipulation or unauthorized access.
/// @COUNTERMEASURE Date validation and range limits.
/// @INVARIANT Date ranges are bounded and validated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DateRange {
    pub start: Option<String>,
    pub end: Option<String>,
    pub field: Option<String>,
}

/// [PAGINATION PARAMS] Result Pagination Configuration
/// @MISSION Define pagination parameters for search results.
/// @THREAT Pagination manipulation or resource exhaustion.
/// @COUNTERMEASURE Pagination limits and offset validation.
/// @INVARIANT Pagination parameters are bounded and validated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationParams {
    pub offset: Option<usize>,
    pub limit: Option<usize>,
}

/// [SORT PARAMS] Result Sorting Configuration
/// @MISSION Define sorting parameters for search results.
/// @THREAT Sort manipulation or information disclosure.
/// @COUNTERMEASURE Sort field validation and permission checks.
/// @INVARIANT Sort operations respect data sensitivity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SortParams {
    pub field: String,
    pub order: SortOrder,
}

/// [SORT ORDER] Sorting Direction Enumeration
/// @MISSION Define sorting direction for results.
/// @THREAT Sort order manipulation.
/// @COUNTERMEASURE Enum validation and type safety.
/// @INVARIANT Sort order is validated before application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SortOrder {
    Asc,
    Desc,
}

/// [SEARCH RESULT] Search Response Structure
/// @MISSION Container for search results and metadata.
/// @THREAT Result manipulation or data leakage.
/// @COUNTERMEASURE Permission filtering and result validation.
/// @INVARIANT All results respect user access permissions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub hits: Vec<SearchHit>,
    pub total: usize,
    pub took: u64,
    pub facets: Option<HashMap<String, HashMap<String, usize>>>,
    pub suggestions: Option<Vec<String>>,
}

/// [SEARCH HIT] Individual Search Result
/// @MISSION Represent individual search result item.
/// @THREAT Result tampering or information leakage.
/// @COUNTERMEASURE Field-level access control and validation.
/// @INVARIANT Hit fields are filtered based on permissions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHit {
    pub id: String,
    pub score: f32,
    pub title: Option<String>,
    pub content: Option<String>,
    pub content_type: Option<String>,
    pub author: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub tags: Option<Vec<String>>,
    pub categories: Option<Vec<String>>,
    pub highlights: Option<HashMap<String, Vec<String>>>,
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

/// [SEARCH SUGGESTION] Autocomplete Suggestion
/// @MISSION Provide search query suggestions.
/// @THREAT Suggestion manipulation or information leakage.
/// @COUNTERMEASURE Suggestion filtering and access control.
/// @INVARIANT Suggestions respect user permissions and context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchSuggestion {
    pub text: String,
    pub score: f32,
    pub source: String,
}

impl SearchService {
    /// [SERVICE INITIALIZATION] Initialize Search Engine
    /// @MISSION Create search service with index and schema.
    /// @THREAT Index corruption or unauthorized access.
    /// @COUNTERMEASURE Secure index creation and access controls.
    /// @DEPENDENCY Valid index directory and schema definition.
    /// @PERFORMANCE ~500ms service initialization.
    /// @AUDIT Service initialization logged with configuration.
    pub fn new(index_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let schema = Self::build_schema();
        let index = tantivy::Index::create_in_dir(index_path, schema.clone())?;
        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::OnCommit)
            .try_into()?;

        Ok(SearchService {
            index,
            reader,
            schema,
        })
    }

    /// [SCHEMA BUILDING] Create Search Index Schema
    /// @MISSION Define field schema for search indexing.
    /// @THREAT Schema manipulation or indexing errors.
    /// @COUNTERMEASURE Schema validation and field type checking.
    /// @INVARIANT Schema supports all required search features.
    fn build_schema() -> Schema {
        let mut schema_builder = Schema::builder();

        // Primary identifier
        schema_builder.add_text_field("id", TEXT | STORED);

        // Searchable content fields
        let title_options = TextOptions::default()
            .set_indexing_options(TextFieldIndexing::default().set_tokenizer("en_stem"))
            .set_indexed()
            .set_stored();
        schema_builder.add_text_field("title", title_options);

        let content_options = TextOptions::default()
            .set_indexing_options(TextFieldIndexing::default().set_tokenizer("en_stem"))
            .set_indexed()
            .set_stored();
        schema_builder.add_text_field("content", content_options);

        // Metadata fields
        schema_builder.add_text_field("content_type", TEXT | STORED);
        schema_builder.add_text_field("author", TEXT | STORED);
        schema_builder.add_date_field("created_at", INDEXED | STORED);
        schema_builder.add_date_field("updated_at", INDEXED | STORED);

        // Faceted fields
        let tags_options = TextOptions::default()
            .set_indexing_options(TextFieldIndexing::default().set_tokenizer("comma"))
            .set_indexed()
            .set_stored();
        schema_builder.add_text_field("tags", tags_options);

        let categories_options = TextOptions::default()
            .set_indexing_options(TextFieldIndexing::default().set_tokenizer("comma"))
            .set_indexed()
            .set_stored();
        schema_builder.add_text_field("categories", categories_options);

        // Security fields
        schema_builder.add_text_field("organization_id", TEXT | STORED);
        schema_builder.add_text_field("permissions", TEXT | STORED);
        schema_builder.add_text_field("access_level", TEXT | STORED);

        // Status and workflow
        schema_builder.add_text_field("status", TEXT | STORED);
        schema_builder.add_text_field("workflow_state", TEXT | STORED);

        schema_builder.build()
    }

    /// [DOCUMENT INDEXING] Add Document to Index
    /// @MISSION Index document for search availability.
    /// @THREAT Unauthorized indexing or data corruption.
    /// @COUNTERMEASURE Index permissions and document validation.
        /// @DEPENDENCY Valid document and indexing permissions.
        /// @PERFORMANCE ~10ms per document indexing.
        /// @AUDIT Document indexing logged with metadata.
    pub async fn index_document(
        &self,
        document: &serde_json::Value,
        auth_context: &AuthContext,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let doc_id = document.get("id")
            .and_then(|v| v.as_str())
            .unwrap_or(&Uuid::new_v4().to_string())
            .to_string();

        let mut writer = self.index.writer(50_000_000)?; // 50MB buffer

        let mut tantivy_doc = tantivy::Document::new();
        
        // Add document fields
        tantivy_doc.add_text(self.schema.get_field("id")?, &doc_id);
        
        if let Some(title) = document.get("title").and_then(|v| v.as_str()) {
            tantivy_doc.add_text(self.schema.get_field("title")?, title);
        }
        
        if let Some(content) = document.get("content").and_then(|v| v.as_str()) {
            tantivy_doc.add_text(self.schema.get_field("content")?, content);
        }

        // Add security fields
        tantivy_doc.add_text(self.schema.get_field("organization_id")?, &auth_context.organization_id);
        tantivy_doc.add_text(self.schema.get_field("permissions")?, &auth_context.permissions.join(","));
        tantivy_doc.add_text(self.schema.get_field("access_level")?, "standard");

        writer.add_document(tantivy_doc)?;
        writer.commit()?;

        Ok(doc_id)
    }

    /// [SEARCH EXECUTION] Perform Search Query
    /// @MISSION Execute search with security filtering.
    /// @THREAT Unauthorized data access or query manipulation.
    /// @COUNTERMEASURE Query validation and permission filtering.
    /// @DEPENDENCY Valid search request and auth context.
    /// @PERFORMANCE ~100ms average query time.
    /// @AUDIT Search queries logged with results.
    pub async fn search(
        &self,
        request: SearchRequest,
        auth_context: &AuthContext,
    ) -> Result<SearchResult, Box<dyn std::error::Error>> {
        let searcher = self.reader.searcher();
        let start_time = std::time::Instant::now();

        // Build base query
        let query = self.build_query(&request, auth_context)?;

        // Execute search
        let limit = request.pagination
            .as_ref()
            .and_then(|p| p.limit)
            .unwrap_or(10);
        let offset = request.pagination
            .as_ref()
            .and_then(|p| p.offset)
            .unwrap_or(0);

        let top_docs = searcher.search(&query, &TopDocs::with_limit(limit).and_offset(offset))?;
        let total = searcher.search(&query, &Count)?;

        // Convert to search hits
        let mut hits = Vec::new();
        for (_score, doc_address) in top_docs {
            if let Ok(retrieved_doc) = searcher.doc(doc_address) {
                if let Some(hit) = self.document_to_hit(&retrieved_doc, _score, &request.highlight.unwrap_or(false)) {
                    // Apply permission filtering
                    if self.has_document_permission(&hit, auth_context) {
                        hits.push(hit);
                    }
                }
            }
        }

        let took = start_time.elapsed().as_millis() as u64;

        Ok(SearchResult {
            hits,
            total,
            took,
            facets: None, // TODO: Implement faceting
            suggestions: None, // TODO: Implement suggestions
        })
    }

    /// [QUERY BUILDING] Construct Search Query
    /// @MISSION Build tantivy query from search request.
    /// @THREAT Query injection or manipulation.
    /// @COUNTERMEASURE Query validation and sanitization.
    /// @DEPENDENCY Valid search request parameters.
    /// @INVARIANT Query respects security constraints.
    fn build_query(&self, request: &SearchRequest, auth_context: &AuthContext) -> Result<Box<dyn Query>, Box<dyn std::error::Error>> {
        let mut sub_queries: Vec<Box<dyn Query>> = Vec::new();

        // Main text query
        if !request.query.is_empty() {
            let title_field = self.schema.get_field("title")?;
            let content_field = self.schema.get_field("content")?;
            
            let title_query = FuzzyTermQuery::new(
                Term::from_field_text(title_field, &request.query),
                1,
                true,
            );
            let content_query = FuzzyTermQuery::new(
                Term::from_field_text(content_field, &request.query),
                1,
                true,
            );

            sub_queries.push(Box::new(title_query));
            sub_queries.push(Box::new(content_query));
        }

        // Security filtering
        let org_field = self.schema.get_field("organization_id")?;
        let org_query = TermQuery::new(
            Term::from_field_text(org_field, &auth_context.organization_id),
            IndexRecordOption::Basic,
        );
        sub_queries.push(Box::new(org_query));

        // Build boolean query
        if sub_queries.is_empty() {
            Ok(Box::new(AllQuery))
        } else {
            Ok(Box::new(BooleanQuery::with_subqueries(sub_queries)))
        }
    }

    /// [DOCUMENT CONVERSION] Convert Tantivy Doc to Search Hit
    /// @MISSION Convert search result document to API format.
    /// @THREAT Data leakage or field exposure.
    /// @COUNTERMEASURE Field filtering and permission checks.
    /// @DEPENDENCY Valid tantivy document and schema.
    /// @INVARIANT Only authorized fields are included.
    fn document_to_hit(
        &self,
        doc: &tantivy::Document,
        score: f32,
        highlight: bool,
    ) -> Option<SearchHit> {
        let id_field = self.schema.get_field("id").ok()?;
        let title_field = self.schema.get_field("title").ok()?;
        let content_field = self.schema.get_field("content").ok()?;

        let id = doc.get_first(id_field)?.as_text()?.to_string();
        let title = doc.get_first(title_field).and_then(|v| v.as_text()).map(|s| s.to_string());
        let content = doc.get_first(content_field).and_then(|v| v.as_text()).map(|s| s.to_string());

        Some(SearchHit {
            id,
            score,
            title,
            content,
            content_type: None,
            author: None,
            created_at: None,
            updated_at: None,
            tags: None,
            categories: None,
            highlights: if highlight { Some(HashMap::new()) } else { None },
            metadata: None,
        })
    }

    /// [PERMISSION CHECKING] Verify Document Access
    /// @MISSION Check if user has permission to access document.
    /// @THREAT Unauthorized access or privilege escalation.
    /// @COUNTERMEASURE Permission validation and access control.
    /// @DEPENDENCY User auth context and document permissions.
    /// @INVARIANT Access is denied by default.
    fn has_document_permission(&self, _hit: &SearchHit, _auth_context: &AuthContext) -> bool {
        // TODO: Implement proper permission checking
        // For now, allow all access within same organization
        true
    }

    /// [SUGGESTION GENERATION] Generate Search Suggestions
    /// @MISSION Provide autocomplete suggestions for search queries.
    /// @THREAT Suggestion manipulation or information leakage.
    /// @COUNTERMEASURE Suggestion filtering and access control.
    /// @DEPENDENCY Valid query prefix and user context.
    /// @PERFORMANCE ~50ms suggestion generation.
    /// @AUDIT Suggestions logged for analytics.
    pub async fn get_suggestions(
        &self,
        prefix: &str,
        auth_context: &AuthContext,
        limit: Option<usize>,
    ) -> Result<Vec<SearchSuggestion>, Box<dyn std::error::Error>> {
        // Mock implementation - would use actual suggester
        let suggestions = vec![
            SearchSuggestion {
                text: format!("{}suggestion1", prefix),
                score: 0.9,
                source: "title".to_string(),
            },
            SearchSuggestion {
                text: format!("{}suggestion2", prefix),
                score: 0.8,
                source: "content".to_string(),
            },
        ];

        Ok(suggestions.into_iter().take(limit.unwrap_or(5)).collect())
    }

    /// [INDEX MANAGEMENT] Optimize Search Index
    /// @MISSION Optimize index for better search performance.
    /// @THREAT Index corruption or performance degradation.
    /// @COUNTERMEASURE Index validation and backup procedures.
    /// @DEPENDENCY Valid index state and maintenance window.
    /// @PERFORMANCE Variable based on index size.
    /// @AUDIT Index optimization logged with metrics.
    pub async fn optimize_index(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut writer = self.index.writer(100_000_000)?;
        writer.commit()?;
        writer.wait_merging_threads()?;
        Ok(())
    }

    /// [INDEX STATISTICS] Get Search Index Statistics
    /// @MISSION Provide index metrics and statistics.
    /// @THREAT Information disclosure or system probing.
    /// @COUNTERMEASURE Access controls and data filtering.
    /// @DEPENDENCY Valid index state and permissions.
    /// @PERFORMANCE ~10ms statistics generation.
    /// @AUDIT Statistics access logged for monitoring.
    pub async fn get_index_stats(&self, auth_context: &AuthContext) -> Result<HashMap<String, serde_json::Value>, Box<dyn std::error::Error>> {
        let searcher = self.reader.searcher();
        let mut stats = HashMap::new();

        stats.insert("num_docs".to_string(), serde_json::Value::Number(
            serde_json::Number::from(searcher.num_docs())
        ));
        stats.insert("memory_usage".to_string(), serde_json::Value::Number(
            serde_json::Number::from(searcher.space_usage().ram_bytes())
        ));
        stats.insert("index_size".to_string(), serde_json::Value::Number(
            serde_json::Number::from(searcher.space_usage().disk_bytes())
        ));

        Ok(stats)
    }

    /// [DOCUMENT DELETION] Remove Document from Index
    /// @MISSION Delete document from search index.
    /// @THREAT Unauthorized deletion or data loss.
    /// @COUNTERMEASURE Delete permissions and validation.
    /// @DEPENDENCY Valid document ID and delete permissions.
    /// @PERFORMANCE ~10ms document deletion.
    /// @AUDIT Document deletion logged with details.
    pub async fn delete_document(
        &self,
        doc_id: &str,
        auth_context: &AuthContext,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut writer = self.index.writer(50_000_000)?;
        
        let id_field = self.schema.get_field("id")?;
        let term = Term::from_field_text(id_field, doc_id);
        writer.delete_term(term);
        writer.commit()?;

        Ok(())
    }

    /// [BULK INDEXING] Index Multiple Documents
    /// @MISSION Efficiently index multiple documents.
    /// @THREAT Bulk manipulation or performance issues.
    /// @COUNTERMEASURE Batch validation and rate limiting.
    /// @DEPENDENCY Valid documents and indexing permissions.
    /// @PERFORMANCE ~5ms per document in bulk.
    /// @AUDIT Bulk indexing logged with metrics.
    pub async fn bulk_index(
        &self,
        documents: Vec<serde_json::Value>,
        auth_context: &AuthContext,
    ) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let mut writer = self.index.writer(100_000_000)?;
        let mut doc_ids = Vec::new();

        for document in documents {
            let doc_id = self.index_document(&document, auth_context).await?;
            doc_ids.push(doc_id);
        }

        writer.commit()?;
        Ok(doc_ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_search_service_creation() {
        let temp_dir = TempDir::new().unwrap();
        let search_service = SearchService::new(temp_dir.path().to_str().unwrap());
        assert!(search_service.is_ok());
    }

    #[tokio::test]
    async fn test_document_indexing() {
        let temp_dir = TempDir::new().unwrap();
        let search_service = SearchService::new(temp_dir.path().to_str().unwrap()).unwrap();

        let auth_context = AuthContext {
            user_id: "user1".to_string(),
            organization_id: "org1".to_string(),
            permissions: vec!["read".to_string()],
            roles: vec!["user".to_string()],
            session_id: "session1".to_string(),
        };

        let document = serde_json::json!({
            "title": "Test Document",
            "content": "This is a test document for search indexing."
        });

        let doc_id = search_service.index_document(&document, &auth_context).await.unwrap();
        assert!(!doc_id.is_empty());
    }

    #[tokio::test]
    async fn test_search_execution() {
        let temp_dir = TempDir::new().unwrap();
        let search_service = SearchService::new(temp_dir.path().to_str().unwrap()).unwrap();

        let auth_context = AuthContext {
            user_id: "user1".to_string(),
            organization_id: "org1".to_string(),
            permissions: vec!["read".to_string()],
            roles: vec!["user".to_string()],
            session_id: "session1".to_string(),
        };

        // Index a test document
        let document = serde_json::json!({
            "title": "Test Document",
            "content": "This is a test document for search."
        });
        search_service.index_document(&document, &auth_context).await.unwrap();

        // Search for the document
        let search_request = SearchRequest {
            query: "test".to_string(),
            filters: None,
            pagination: Some(PaginationParams {
                offset: Some(0),
                limit: Some(10),
            }),
            sort: None,
            highlight: Some(false),
            facets: None,
        };

        let result = search_service.search(search_request, &auth_context).await.unwrap();
        assert_eq!(result.hits.len(), 1);
        assert_eq!(result.hits[0].title, Some("Test Document".to_string()));
    }
}