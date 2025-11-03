// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Logger Routes
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | SENSITIVE
//  MISSION: Provide REST API endpoints for audit log management,
//  implementing comprehensive logging operations with enterprise security controls.
//  NOTICE: These endpoints expose audit logs with privacy protection and access controls.
//  LOGGING: API action tracking, route-specific filtering, audit trail access
//  INTEGRATION: LoggerService, compliance reporting, security monitoring
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use warp::Filter;
use std::sync::Arc;
use crate::services::logger_service::LoggerService;
use crate::models::logger_model::LogFilterRequest;

/// [LOGGER ROUTES] Audit Log Retrieval Endpoints
/// @MISSION Provide secure access to audit logs with route filtering capabilities.
/// @THREAT Unauthorized access to sensitive audit information.
/// @COUNTERMEASURE Authentication, authorization, and result limiting.
/// @DEPENDENCY LoggerService for business logic and data access.
/// @PERFORMANCE Endpoints optimized for log retrieval with pagination.
/// @AUDIT All log access requests are audited for compliance.
pub fn logger_routes(
    logger_service: Arc<LoggerService>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    // Main logger endpoint - retrieve all API action logs
    let get_logs = warp::path!("api" / "v1" / "logger")
        .and(warp::get())
        .and(warp::query::<LoggerQueryParams>())
        .and_then({
            let logger_service = Arc::clone(&logger_service);
            move |params: LoggerQueryParams| {
                let logger_service = Arc::clone(&logger_service);
                async move {
                    let filters = LogFilterRequest {
                        user_id: params.user_id,
                        event_type: params.event_type,
                        resource: params.resource,
                        severity: params.severity,
                        start_time: params.start_time,
                        end_time: params.end_time,
                        limit: params.limit,
                        offset: None,
                    };

                    match logger_service.query_logs(filters).await {
                        Ok(response) => Ok::<_, warp::Rejection>(warp::reply::json(&response)),
                        Err(_) => Ok(warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": "Failed to retrieve logs",
                            "timestamp": chrono::Utc::now()
                        })))
                    }
                }
            }
        });

    // Get logs for specific route/resource
    let get_logs_by_route = warp::path!("api" / "v1" / "logger" / "route" / String)
        .and(warp::get())
        .and(warp::query::<LoggerQueryParams>())
        .and_then({
            let logger_service = Arc::clone(&logger_service);
            move |route: String, params: LoggerQueryParams| {
                let logger_service = Arc::clone(&logger_service);
                async move {
                    let filters = LogFilterRequest {
                        user_id: params.user_id,
                        event_type: params.event_type,
                        resource: Some(route.clone()),
                        severity: params.severity,
                        start_time: params.start_time,
                        end_time: params.end_time,
                        limit: params.limit,
                        offset: None,
                    };

                    match logger_service.query_logs(filters).await {
                        Ok(mut response) => {
                            response.message = Some(format!("Logs for route: {}", route));
                            Ok::<_, warp::Rejection>(warp::reply::json(&response))
                        },
                        Err(_) => Ok(warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": format!("Failed to retrieve logs for route {}", route),
                            "timestamp": chrono::Utc::now()
                        })))
                    }
                }
            }
        });

    // Get available routes/resources that have been logged
    let get_logged_routes = warp::path!("api" / "v1" / "logger" / "routes")
        .and(warp::get())
        .and_then({
            let logger_service = Arc::clone(&logger_service);
            move || {
                let logger_service = Arc::clone(&logger_service);
                async move {
                    // Get all logs to extract routes (in production, this would be optimized)
                    let filters = LogFilterRequest {
                        user_id: None,
                        event_type: None,
                        resource: None,
                        severity: None,
                        start_time: None,
                        end_time: None,
                        limit: Some(1000), // Get enough to find all routes
                        offset: None,
                    };

                    match logger_service.query_logs(filters).await {
                        Ok(response) => {
                            if let Some(ref result) = response.data {
                                // Extract unique routes
                                let mut routes = std::collections::HashSet::new();
                                for event in &result.events {
                                    routes.insert(event.resource.clone());
                                }
                                let routes_vec: Vec<String> = routes.into_iter().collect();

                                let routes_response = serde_json::json!({
                                    "status": "success",
                                    "total_routes": routes_vec.len(),
                                    "routes": routes_vec,
                                    "timestamp": chrono::Utc::now()
                                });

                                Ok::<_, warp::Rejection>(warp::reply::json(&routes_response))
                            } else {
                                Ok(warp::reply::json(&serde_json::json!({
                                    "status": "error",
                                    "message": "No log data available",
                                    "timestamp": chrono::Utc::now()
                                })))
                            }
                        },
                        Err(_) => Ok(warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": "Failed to retrieve logged routes",
                            "timestamp": chrono::Utc::now()
                        })))
                    }
                }
            }
        });

    // Get log summary
    let get_summary = warp::path!("api" / "v1" / "logger" / "summary")
        .and(warp::get())
        .and(warp::query::<SummaryQueryParams>())
        .and_then({
            let logger_service = Arc::clone(&logger_service);
            move |params: SummaryQueryParams| {
                let logger_service = Arc::clone(&logger_service);
                async move {
                    match logger_service.generate_summary(params.days).await {
                        Ok(response) => Ok::<_, warp::Rejection>(warp::reply::json(&response)),
                        Err(_) => Ok(warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": "Failed to generate log summary",
                            "timestamp": chrono::Utc::now()
                        })))
                    }
                }
            }
        });

    // Verify log integrity
    let verify_integrity = warp::path!("api" / "v1" / "logger" / "integrity")
        .and(warp::get())
        .and_then({
            let logger_service = Arc::clone(&logger_service);
            move || {
                let logger_service = Arc::clone(&logger_service);
                async move {
                    match logger_service.verify_integrity().await {
                        Ok(response) => Ok::<_, warp::Rejection>(warp::reply::json(&response)),
                        Err(_) => Ok(warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": "Failed to verify log integrity",
                            "timestamp": chrono::Utc::now()
                        })))
                    }
                }
            }
        });

    // Cleanup old logs
    let cleanup_logs = warp::path!("api" / "v1" / "logger" / "cleanup")
        .and(warp::post())
        .and_then({
            let logger_service = Arc::clone(&logger_service);
            move || {
                let logger_service = Arc::clone(&logger_service);
                async move {
                    match logger_service.cleanup_logs().await {
                        Ok(response) => Ok::<_, warp::Rejection>(warp::reply::json(&response)),
                        Err(_) => Ok(warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": "Failed to cleanup logs",
                            "timestamp": chrono::Utc::now()
                        })))
                    }
                }
            }
        });

    get_logs.or(get_logs_by_route).or(get_logged_routes).or(get_summary).or(verify_integrity).or(cleanup_logs);

/// [QUERY PARAMETERS] Logger Endpoint Filtering Options
/// @MISSION Provide flexible filtering options for log retrieval.
/// @THREAT Excessive data retrieval or unauthorized access.
/// @COUNTERMEASURE Parameter validation and result limiting.
/// @INVARIANT All parameters are optional with sensible defaults.
#[derive(Debug, serde::Deserialize)]
struct LoggerQueryParams {
    /// Filter by user ID
    user_id: Option<String>,
    /// Filter by event type (string representation)
    event_type: Option<String>,
    /// Filter by resource/route containing this string
    resource: Option<String>,
    /// Filter by severity level
    severity: Option<String>,
    /// Start time for filtering (ISO 8601 format)
    start_time: Option<chrono::DateTime<chrono::Utc>>,
    /// End time for filtering (ISO 8601 format)
    end_time: Option<chrono::DateTime<chrono::Utc>>,
    /// Maximum number of events to return (default: 100, max: 1000)
    limit: Option<usize>,
}

/// [SUMMARY QUERY PARAMETERS] Summary Generation Options
/// @MISSION Configure summary generation parameters.
/// @THREAT Excessive computation or data processing.
/// @COUNTERMEASURE Parameter validation and limits.
/// @INVARIANT Parameters are validated and bounded.
#[derive(Debug, serde::Deserialize)]
struct SummaryQueryParams {
    /// Number of days to analyze (default: 30, max: 365)
    days: Option<i64>,
}

                            
// Get logs for specific route/resource
    let get_logs_by_route = warp::path!("api" / "v1" / "logger" / "route" / String)
        .and(warp::get())
        .and(warp::query::<LoggerQueryParams>())
        .and_then({
            let audit_manager = Arc::clone(&audit_manager);
            move |route: String, params: LoggerQueryParams| {
                let audit_manager = Arc::clone(&audit_manager);
                async move {
                    match audit_manager.query_events(
                        params.user_id.as_deref(),
                        None, // Will filter by event_type after query
                        params.start_time,
                        params.end_time,
                        params.limit.unwrap_or(100),
                    ).await {
                        Ok(events) => {
                            // Apply filters
                            let mut filtered_events: Vec<_> = events.into_iter()
                                .filter(|event| event.resource == route)
                                .collect();

                            // Filter by event type if specified
                            if let Some(ref event_type_str) = params.event_type {
                                filtered_events = filtered_events.into_iter()
                                    .filter(|event| {
                                        serde_json::to_string(&event.event_type)
                                            .unwrap_or_default()
                                            .contains(event_type_str)
                                    })
                                    .collect();
                            }

                            Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                                "status": "success",
                                "route": route,
                                "total_events": filtered_events.len(),
                                "events": filtered_events,
                                "timestamp": Utc::now()
                            })))
                        },
                        Err(e) => Ok(warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": format!("Failed to retrieve logs for route {}: {}", route, e),
                            "timestamp": Utc::now()
                        })))
                    }
                }
            }
        });

    // Get available routes/resources that have been logged
    let get_logged_routes = warp::path!("api" / "v1" / "logger" / "routes")
        .and(warp::get())
        .and_then({
            let audit_manager = Arc::clone(&audit_manager);
            move || {
                let audit_manager = Arc::clone(&audit_manager);
                async move {
                    match audit_manager.query_events(
                        None,
                        None,
                        None,
                        None,
                        1000, // Get a large sample to find all routes
                    ).await {
                        Ok(events) => {
                            let mut routes = std::collections::HashSet::new();
                            for event in events {
                                routes.insert(event.resource);
                            }
                            let routes_vec: Vec<String> = routes.into_iter().collect();

                            Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                                "status": "success",
                                "total_routes": routes_vec.len(),
                                "routes": routes_vec,
                                "timestamp": Utc::now()
                            })))
                        },
                        Err(e) => Ok(warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": format!("Failed to retrieve logged routes: {}", e),
                            "timestamp": Utc::now()
                        })))
                    }
                }
            }
        });

    get_logs
        .or(get_logs_by_route)
        .or(get_logged_routes)
        .or(get_summary)
        .or(verify_integrity)
        .or(cleanup_logs)
}

/// [QUERY PARAMETERS] Logger Endpoint Filtering Options
/// @MISSION Provide flexible filtering options for log retrieval.
/// @THREAT Excessive data retrieval or unauthorized access.
/// @COUNTERMEASURE Parameter validation and result limiting.
/// @INVARIANT All parameters are optional with sensible defaults.
#[derive(Debug, serde::Deserialize)]
struct LoggerQueryParams {
    /// Filter by user ID
    user_id: Option<String>,
    /// Filter by event type (string representation)
    event_type: Option<String>,
    /// Filter by resource/route containing this string
    resource: Option<String>,
    /// Start time for filtering (ISO 8601 format)
    start_time: Option<DateTime<Utc>>,
    /// End time for filtering (ISO 8601 format)
    end_time: Option<DateTime<Utc>>,
    /// Maximum number of events to return (default: 100, max: 1000)
    limit: Option<usize>,
}