// ===============================================================
// SKY GENESIS ENTERPRISE :: AETHER SEARCH MODULE - ROUTES
// CLASSIFIED LEVEL: INTERNAL USE ONLY
// MISSION: Define secure search API endpoints with authentication
// PROTOCOLS: OAuth2 | FIDO2 | PGP | TLS 1.3 | VPN Tunnel
// AUDIT TRAIL: Vault + OpenTelemetry | Internal Node ID Signed
// ===============================================================

use warp::{Filter, Reply};
use std::sync::Arc;
use crate::search::service::{SearchService, AuthContext};
use crate::search::models::*;
use crate::services::auth_service::AuthService;
use crate::core::vault::VaultClient;
use crate::core::opentelemetry::Metrics;

/// Create search routes with authentication and security
pub fn search_routes(
    auth_service: Arc<AuthService>,
    vault: Arc<VaultClient>,
    metrics: Arc<Metrics>,
) -> impl Filter<Extract = impl Reply, Error = warp::Rejection> + Clone {
    // Initialize search service
    let search_service = Arc::new(tokio::sync::RwLock::new(None));

    // Clone for closures
    let search_service_clone = search_service.clone();
    let auth_service_clone = auth_service.clone();
    let vault_clone = vault.clone();
    let metrics_clone = metrics.clone();

    // Initialize service on first request
    let init_filter = warp::any().map(move || {
        let search_service = search_service_clone.clone();
        let auth_service = auth_service_clone.clone();
        let vault = vault_clone.clone();
        let metrics = metrics_clone.clone();
        async move {
            let mut service_lock = search_service.write().await;
            if service_lock.is_none() {
                let index_path = std::path::Path::new("./search_index");
                match SearchService::new(index_path, auth_service, vault, metrics).await {
                    Ok(service) => {
                        *service_lock = Some(service);
                    }
                    Err(e) => {
                        eprintln!("Failed to initialize search service: {}", e);
                    }
                }
            }
        }
    });

    // POST /api/v1/search - Main search endpoint
    let search = warp::path!("api" / "v1" / "search")
        .and(warp::post())
        .and(warp::body::json())
        .and(auth_guard(auth_service.clone()))
        .and(with_search_service(search_service.clone()))
        .and_then(search_handler);

    // GET /api/v1/search/suggest - Auto-completion suggestions
    let suggest = warp::path!("api" / "v1" / "search" / "suggest")
        .and(warp::get())
        .and(warp::query::<SuggestQuery>())
        .and(auth_guard(auth_service.clone()))
        .and(with_search_service(search_service.clone()))
        .and_then(suggest_handler);

    // GET /api/v1/search/index/status - Index status (admin)
    let index_status = warp::path!("api" / "v1" / "search" / "index" / "status")
        .and(warp::get())
        .and(auth_guard(auth_service.clone()))
        .and(with_search_service(search_service.clone()))
        .and_then(index_status_handler);

    // POST /api/v1/search/reindex - Trigger reindex (admin + FIDO2)
    let reindex = warp::path!("api" / "v1" / "search" / "reindex")
        .and(warp::post())
        .and(auth_guard(auth_service.clone()))
        .and(with_search_service(search_service.clone()))
        .and_then(reindex_handler);

    // GET /api/v1/search/metrics - Search metrics (internal)
    let metrics_route = warp::path!("api" / "v1" / "search" / "metrics")
        .and(warp::get())
        .and(warp::query::<MetricsQuery>())
        .and(auth_guard(auth_service.clone()))
        .and(with_search_service(search_service.clone()))
        .and_then(metrics_handler);

    // Combine all routes with initialization
    init_filter
        .untuple_one()
        .and(
            search
                .or(suggest)
                .or(index_status)
                .or(reindex)
                .or(metrics_route)
        )
        .recover(handle_rejection)
}

/// Authentication guard that extracts claims and creates AuthContext
fn auth_guard(
    auth_service: Arc<AuthService>,
) -> impl Filter<Extract = (AuthContext,), Error = warp::Rejection> + Clone {
    use crate::middlewares::auth_middleware::jwt_auth;
    use crate::core::keycloak::KeycloakClient;
    use std::sync::Arc;

    // For now, use a dummy Keycloak client
    // In real implementation, this would be passed in
    let keycloak = Arc::new(crate::core::keycloak::KeycloakClient::new(Arc::new(crate::core::vault::VaultClient::new("dummy".to_string(), "dummy".to_string(), "dummy".to_string()).unwrap())).unwrap());

    jwt_auth(keycloak)
        .map(|claims: crate::middlewares::auth_middleware::Claims| {
            AuthContext::from(&claims)
        })
}

/// Extract search service from Arc<RwLock<Option<SearchService>>>
fn with_search_service(
    service: Arc<tokio::sync::RwLock<Option<SearchService>>>,
) -> impl Filter<Extract = (SearchService,), Error = warp::Rejection> + Clone {
    warp::any()
        .map(move || service.clone())
        .and_then(|service: Arc<tokio::sync::RwLock<Option<SearchService>>>| async move {
            let service_lock = service.read().await;
            match &*service_lock {
                Some(svc) => Ok(svc.clone()),
                None => Err(warp::reject::custom(SearchError::ServiceUnavailable)),
            }
        })
}

/// Main search handler
async fn search_handler(
    query: SearchQuery,
    auth_context: AuthContext,
    service: SearchService,
) -> Result<impl Reply, warp::Rejection> {
    match service.search(query, &auth_context).await {
        Ok(response) => Ok(warp::reply::json(&response)),
        Err(e) => {
            eprintln!("Search error: {}", e);
            Err(warp::reject::custom(SearchError::InternalError))
        }
    }
}

/// Auto-completion suggestions handler
async fn suggest_handler(
    query: SuggestQuery,
    auth_context: AuthContext,
    service: SearchService,
) -> Result<impl Reply, warp::Rejection> {
    match service.suggest(query.prefix, query.limit, &auth_context).await {
        Ok(response) => Ok(warp::reply::json(&response)),
        Err(e) => {
            eprintln!("Suggest error: {}", e);
            Err(warp::reject::custom(SearchError::InternalError))
        }
    }
}

/// Index status handler
async fn index_status_handler(
    auth_context: AuthContext,
    service: SearchService,
) -> Result<impl Reply, warp::Rejection> {
    match service.get_index_status(&auth_context).await {
        Ok(response) => Ok(warp::reply::json(&response)),
        Err(e) => {
            eprintln!("Index status error: {}", e);
            Err(warp::reject::custom(SearchError::Forbidden))
        }
    }
}

/// Reindex handler
async fn reindex_handler(
    auth_context: AuthContext,
    service: SearchService,
) -> Result<impl Reply, warp::Rejection> {
    match service.reindex(&auth_context).await {
        Ok(response) => Ok(warp::reply::json(&response)),
        Err(e) => {
            eprintln!("Reindex error: {}", e);
            Err(warp::reject::custom(SearchError::Forbidden))
        }
    }
}

/// Metrics handler
async fn metrics_handler(
    query: MetricsQuery,
    auth_context: AuthContext,
    service: SearchService,
) -> Result<impl Reply, warp::Rejection> {
    match service.get_metrics(&auth_context, query.time_range).await {
        Ok(response) => Ok(warp::reply::json(&response)),
        Err(e) => {
            eprintln!("Metrics error: {}", e);
            Err(warp::reject::custom(SearchError::Forbidden))
        }
    }
}

/// Query parameters for suggestions
#[derive(Debug, serde::Deserialize)]
struct SuggestQuery {
    prefix: String,
    limit: Option<usize>,
}

/// Query parameters for metrics
#[derive(Debug, serde::Deserialize)]
struct MetricsQuery {
    time_range: Option<String>,
}

/// Custom error types for warp rejections
#[derive(Debug)]
enum SearchError {
    ServiceUnavailable,
    InternalError,
    Forbidden,
    BadRequest,
}

impl warp::reject::Reject for SearchError {}

/// Handle rejections and return appropriate HTTP responses
async fn handle_rejection(err: warp::Rejection) -> Result<impl Reply, warp::Rejection> {
    if let Some(search_err) = err.find::<SearchError>() {
        let (code, message) = match search_err {
            SearchError::ServiceUnavailable => (503, "Service Unavailable"),
            SearchError::InternalError => (500, "Internal Server Error"),
            SearchError::Forbidden => (403, "Forbidden"),
            SearchError::BadRequest => (400, "Bad Request"),
        };

        let error_response = SearchErrorResponse {
            code: code.to_string(),
            message: message.to_string(),
            details: None,
        };

        Ok(warp::reply::with_status(
            warp::reply::json(&error_response),
            warp::http::StatusCode::from_u16(code).unwrap(),
        ))
    } else {
        Err(err)
    }
}

/// Error response structure
#[derive(serde::Serialize)]
struct SearchErrorResponse {
    code: String,
    message: String,
    details: Option<std::collections::HashMap<String, serde_json::Value>>,
}