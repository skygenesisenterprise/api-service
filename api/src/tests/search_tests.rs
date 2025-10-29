// ===============================================================
// SKY GENESIS ENTERPRISE :: AETHER SEARCH MODULE - TESTS
// CLASSIFIED LEVEL: INTERNAL USE ONLY
// MISSION: Test sovereign search functionality
// PROTOCOLS: OAuth2 | FIDO2 | PGP | TLS 1.3 | VPN Tunnel
// AUDIT TRAIL: Vault + OpenTelemetry | Internal Node ID Signed
// ===============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::search::models::*;
    use crate::search::service::{SearchService, AuthContext};
    use std::path::Path;

    #[tokio::test]
    async fn test_search_models() {
        // Test SearchQuery creation
        let query = SearchQuery {
            query: "test query".to_string(),
            filters: Some(SearchFilters {
                source: Some(vec!["aether_mail".to_string()]),
                lang: Some("fr".to_string()),
                date_from: None,
                date_to: None,
                custom: None,
            }),
            limit: Some(10),
            sort: Some("relevance".to_string()),
            offset: Some(0),
        };

        assert_eq!(query.query, "test query");
        assert_eq!(query.filters.as_ref().unwrap().source.as_ref().unwrap()[0], "aether_mail");
    }

    #[tokio::test]
    async fn test_search_result_creation() {
        let result = SearchResult {
            id: "test-123".to_string(),
            title: "Test Document".to_string(),
            snippet: "This is a test snippet".to_string(),
            source: "aether_office".to_string(),
            score: 0.95,
            url: "https://office.skygenesisenterprise.com/doc/123".to_string(),
            timestamp: Some("2024-01-01T00:00:00Z".to_string()),
            metadata: None,
        };

        assert_eq!(result.id, "test-123");
        assert_eq!(result.score, 0.95);
        assert_eq!(result.source, "aether_office");
    }

    #[tokio::test]
    async fn test_auth_context_from_claims() {
        // Mock Claims
        struct MockClaims {
            sub: String,
            scopes: Vec<String>,
            email: Option<String>,
        }

        impl MockClaims {
            fn new(sub: &str, scopes: Vec<String>, email: Option<String>) -> Self {
                Self { sub: sub.to_string(), scopes, email }
            }
        }

        impl From<&MockClaims> for AuthContext {
            fn from(claims: &MockClaims) -> Self {
                Self {
                    user_id: claims.sub.clone(),
                    is_authenticated: true,
                    permissions: claims.scopes.clone(),
                    fido2_verified: false,
                    is_system_token: false,
                    email: claims.email.clone(),
                }
            }
        }

        let claims = MockClaims::new(
            "user123",
            vec!["search:read".to_string(), "source:mail:read".to_string()],
            Some("user@example.com".to_string()),
        );

        let auth_context = AuthContext::from(&claims);

        assert_eq!(auth_context.user_id, "user123");
        assert!(auth_context.is_authenticated);
        assert!(auth_context.permissions.contains(&"search:read".to_string()));
    }

    #[test]
    fn test_search_filters_validation() {
        let filters = SearchFilters {
            source: Some(vec!["aether_mail".to_string(), "aether_office".to_string()]),
            lang: Some("fr".to_string()),
            date_from: Some("2024-01-01".to_string()),
            date_to: Some("2024-12-31".to_string()),
            custom: Some([("priority".to_string(), "high".to_string())].into_iter().collect()),
        };

        assert!(filters.source.is_some());
        assert_eq!(filters.source.as_ref().unwrap().len(), 2);
        assert_eq!(filters.lang.as_ref().unwrap(), "fr");
        assert!(filters.custom.is_some());
    }

    #[test]
    fn test_pagination_info() {
        let pagination = PaginationInfo {
            offset: 20,
            limit: 10,
            total_pages: 5,
        };

        assert_eq!(pagination.offset, 20);
        assert_eq!(pagination.limit, 10);
        assert_eq!(pagination.total_pages, 5);
    }

    #[test]
    fn test_search_response_structure() {
        let results = vec![
            SearchResult {
                id: "doc1".to_string(),
                title: "Document 1".to_string(),
                snippet: "Snippet 1".to_string(),
                source: "mail".to_string(),
                score: 0.9,
                url: "http://example.com/doc1".to_string(),
                timestamp: None,
                metadata: None,
            },
        ];

        let metadata = SearchMetadata {
            query_time_ms: 150,
            total_results: 1,
            sources: vec!["mail".to_string()],
            pagination: Some(PaginationInfo {
                offset: 0,
                limit: 20,
                total_pages: 1,
            }),
        };

        let response = SearchResponse { results, metadata };

        assert_eq!(response.results.len(), 1);
        assert_eq!(response.metadata.query_time_ms, 150);
        assert_eq!(response.metadata.total_results, 1);
    }
}