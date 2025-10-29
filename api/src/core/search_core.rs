// ===============================================================
// SKY GENESIS ENTERPRISE :: AETHER SEARCH MODULE - CORE
// CLASSIFIED LEVEL: INTERNAL USE ONLY
// MISSION: Implement sovereign search engine with tantivy
// PROTOCOLS: OAuth2 | FIDO2 | PGP | TLS 1.3 | VPN Tunnel
// AUDIT TRAIL: Vault + OpenTelemetry | Internal Node ID Signed
// ===============================================================

use tantivy::{Index, IndexWriter, Document, Term, schema::*};
use tantivy::query::{QueryParser, BooleanQuery, Occur};
use tantivy::collector::TopDocs;
use tantivy::tokenizer::*;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use crate::search::models::*;
use crate::core::vault::VaultClient;
use crate::core::opentelemetry::Metrics;

/// Sovereign search engine core
pub struct AetherSearchEngine {
    /// Tantivy index
    index: Index,
    /// Index writer for updates
    writer: Arc<RwLock<Option<IndexWriter>>>,
    /// Schema definition
    schema: Schema,
    /// Field mappings
    fields: SearchFields,
    /// Metrics collector
    metrics: Arc<Metrics>,
    /// Vault client for secrets
    vault: Arc<VaultClient>,
}

/// Field definitions for the search index
#[derive(Clone)]
pub struct SearchFields {
    pub id: Field,
    pub title: Field,
    pub content: Field,
    pub source: Field,
    pub timestamp: Field,
    pub url: Field,
    pub metadata: Field,
}

impl AetherSearchEngine {
    /// Initialize the search engine
    pub async fn new(
        index_path: &Path,
        vault: Arc<VaultClient>,
        metrics: Arc<Metrics>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Create schema
        let mut schema_builder = Schema::builder();

        // Define fields
        let id = schema_builder.add_text_field("id", STRING | STORED);
        let title = schema_builder.add_text_field("title", TEXT | STORED);
        let content = schema_builder.add_text_field("content", TEXT | STORED);
        let source = schema_builder.add_text_field("source", STRING | STORED | FAST);
        let timestamp = schema_builder.add_date_field("timestamp", INDEXED | STORED);
        let url = schema_builder.add_text_field("url", STRING | STORED);
        let metadata = schema_builder.add_json_field("metadata", STORED);

        let schema = schema_builder.build();
        let fields = SearchFields {
            id, title, content, source, timestamp, url, metadata,
        };

        // Create or open index
        let index = if index_path.exists() {
            Index::open_in_dir(index_path)?
        } else {
            std::fs::create_dir_all(index_path)?;
            Index::create_in_dir(index_path, schema.clone())?
        };

        // Configure tokenizer for better search
        let tokenizer = TextAnalyzer::from(SimpleTokenizer)
            .filter(RemoveLongFilter::limit(40))
            .filter(LowerCaser)
            .filter(Stemmer::new(Language::English));

        index.tokenizers().register("search_tokenizer", tokenizer);

        Ok(Self {
            index,
            writer: Arc::new(RwLock::new(None)),
            schema,
            fields,
            metrics,
            vault,
        })
    }

    /// Initialize index writer
    pub async fn init_writer(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let writer = self.index.writer(50_000_000)?; // 50MB buffer
        *self.writer.write().await = Some(writer);
        Ok(())
    }

    /// Execute search query
    pub async fn search(&self, query: &SearchQuery) -> Result<SearchResponse, Box<dyn std::error::Error + Send + Sync>> {
        let start_time = std::time::Instant::now();

        // Create reader
        let reader = self.index.reader()?;
        let searcher = reader.searcher();

        // Build tantivy query
        let tantivy_query = self.build_query(query)?;

        // Execute search
        let limit = query.limit.unwrap_or(20) as usize;
        let offset = query.offset.unwrap_or(0) as usize;

        let top_docs = searcher.search(&tantivy_query, &TopDocs::with_limit(limit).and_offset(offset))?;

        // Process results
        let mut results = Vec::new();
        for (score, doc_address) in top_docs {
            let doc = searcher.doc(doc_address)?;
            let result = self.doc_to_result(&doc, score)?;
            results.push(result);
        }

        // Get total count
        let count = searcher.search(&tantivy_query, &tantivy::collector::Count)?;

        let query_time = start_time.elapsed().as_millis() as u64;

        // Record metrics
        self.metrics.record_search_query(query_time, results.len() as u64).await;

        let metadata = SearchMetadata {
            query_time_ms: query_time,
            total_results: count as u64,
            sources: self.extract_sources(query),
            pagination: Some(PaginationInfo {
                offset: offset as u32,
                limit: limit as u32,
                total_pages: ((count as u32 + limit as u32 - 1) / limit as u32),
            }),
        };

        Ok(SearchResponse { results, metadata })
    }

    /// Build tantivy query from SearchQuery
    fn build_query(&self, query: &SearchQuery) -> Result<Box<dyn tantivy::query::Query>, Box<dyn std::error::Error + Send + Sync>> {
        let mut subqueries = Vec::new();

        // Main text query
        let query_parser = QueryParser::for_index(&self.index, vec![self.fields.title, self.fields.content]);
        let text_query = query_parser.parse_query(&query.query)?;
        subqueries.push((Occur::Must, text_query));

        // Source filter
        if let Some(filters) = &query.filters {
            if let Some(sources) = &filters.source {
                let mut source_queries = Vec::new();
                for source in sources {
                    let term = Term::from_field_text(self.fields.source, source);
                    source_queries.push(Box::new(tantivy::query::TermQuery::new(term, tantivy::schema::IndexRecordOption::Basic)) as Box<dyn tantivy::query::Query>);
                }
                if !source_queries.is_empty() {
                    subqueries.push((Occur::Must, Box::new(BooleanQuery::union(source_queries))));
                }
            }

            // Date range filter
            if filters.date_from.is_some() || filters.date_to.is_some() {
                // Implement date range query
                // This would require parsing dates and creating range queries
            }
        }

        Ok(Box::new(BooleanQuery::from(subqueries)))
    }

    /// Convert tantivy document to SearchResult
    fn doc_to_result(&self, doc: &Document, score: f32) -> Result<SearchResult, Box<dyn std::error::Error + Send + Sync>> {
        let id = doc.get_first(self.fields.id)
            .and_then(|v| v.as_text())
            .unwrap_or("")
            .to_string();

        let title = doc.get_first(self.fields.title)
            .and_then(|v| v.as_text())
            .unwrap_or("Untitled")
            .to_string();

        let content = doc.get_first(self.fields.content)
            .and_then(|v| v.as_text())
            .unwrap_or("")
            .to_string();

        let source = doc.get_first(self.fields.source)
            .and_then(|v| v.as_text())
            .unwrap_or("unknown")
            .to_string();

        let url = doc.get_first(self.fields.url)
            .and_then(|v| v.as_text())
            .unwrap_or("")
            .to_string();

        // Create snippet from content
        let snippet = if content.len() > 200 {
            format!("{}...", &content[..200])
        } else {
            content.clone()
        };

        // Extract timestamp
        let timestamp = doc.get_first(self.fields.timestamp)
            .and_then(|v| v.as_date())
            .map(|d| d.to_string());

        // Extract metadata
        let metadata = doc.get_first(self.fields.metadata)
            .and_then(|v| v.as_json())
            .cloned();

        Ok(SearchResult {
            id,
            title,
            snippet,
            source,
            score,
            url,
            timestamp,
            metadata,
        })
    }

    /// Extract sources from query for metadata
    fn extract_sources(&self, query: &SearchQuery) -> Vec<String> {
        if let Some(filters) = &query.filters {
            if let Some(sources) = &filters.source {
                return sources.clone();
            }
        }
        vec!["all".to_string()]
    }

    /// Index a document
    pub async fn index_document(&self, doc_data: &DocumentData) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut doc = Document::default();

        doc.add_text(self.fields.id, &doc_data.id);
        doc.add_text(self.fields.title, &doc_data.title);
        doc.add_text(self.fields.content, &doc_data.content);
        doc.add_text(self.fields.source, &doc_data.source);
        doc.add_text(self.fields.url, &doc_data.url);

        if let Some(ts) = doc_data.timestamp {
            doc.add_date(self.fields.timestamp, tantivy::DateTime::from_timestamp_secs(ts));
        }

        if let Some(metadata) = &doc_data.metadata {
            doc.add_json_object(self.fields.metadata, metadata.clone());
        }

        if let Some(writer) = self.writer.read().await.as_ref() {
            writer.add_document(doc)?;
        }

        Ok(())
    }

    /// Commit pending changes
    pub async fn commit(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(writer) = self.writer.read().await.as_ref() {
            writer.commit()?;
        }
        Ok(())
    }

    /// Get index statistics
    pub async fn get_stats(&self) -> Result<IndexStatus, Box<dyn std::error::Error + Send + Sync>> {
        let reader = self.index.reader()?;
        let searcher = reader.searcher();

        Ok(IndexStatus {
            name: "aether_search".to_string(),
            doc_count: searcher.num_docs() as u64,
            size_bytes: 0, // Would need to calculate directory size
            last_updated: chrono::Utc::now().to_rfc3339(),
            status: "healthy".to_string(),
        })
    }

    /// Generate auto-completion suggestions
    pub async fn suggest(&self, prefix: &str, limit: usize) -> Result<SuggestResponse, Box<dyn std::error::Error + Send + Sync>> {
        let start_time = std::time::Instant::now();

        // Simple prefix-based suggestions for now
        // In a real implementation, this would use a suggestion index
        let suggestions = vec![
            Suggestion {
                text: format!("{} advanced", prefix),
                score: 0.8,
                suggestion_type: "completion".to_string(),
            },
            Suggestion {
                text: format!("{} tutorial", prefix),
                score: 0.6,
                suggestion_type: "completion".to_string(),
            },
        ].into_iter().take(limit).collect();

        let query_time = start_time.elapsed().as_millis() as u64;

        Ok(SuggestResponse {
            suggestions,
            query_time_ms: query_time,
        })
    }
}

/// Data structure for indexing documents
#[derive(Debug, Clone)]
pub struct DocumentData {
    pub id: String,
    pub title: String,
    pub content: String,
    pub source: String,
    pub url: String,
    pub timestamp: Option<i64>,
    pub metadata: Option<serde_json::Map<String, serde_json::Value>>,
}