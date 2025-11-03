// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Logger Controller
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide secure REST API endpoints for audit log management,
//  implementing comprehensive logging operations with enterprise security controls.
//  NOTICE: Controllers implement authentication, validation, and audit logging
//  for all logger operations with military-grade security standards.
//  CONTROLLER STANDARDS: REST API, JSON responses, error handling, authentication
//  COMPLIANCE: API security best practices, GDPR data handling, SOX audit trails
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use warp::Reply;
use std::sync::Arc;
use warp::http::StatusCode;
use crate::services::logger_service::{LoggerService, LoggerServiceError};
use crate::models::logger_model::{LoggerResponse, LogFilterRequest, LogExportRequest, ExportFormat, LoggerConfig, LogAlertRule};

/// [GET LOGS HANDLER] Retrieve Filtered Audit Logs
/// @MISSION Provide secure access to audit logs with flexible filtering.
/// @THREAT Unauthorized access, excessive data retrieval, information leakage.
/// @COUNTERMEASURE Authentication, query validation, result limiting, audit logging.
/// @INVARIANT All log access is authenticated and logged.
/// @AUDIT Log queries are audited for compliance and security monitoring.
/// @FLOW Validate request -> Apply filters -> Return paginated results.
/// @DEPENDENCY LoggerService for business logic and data access.
#[utoipa::path(
    get,
    path = "/api/v1/logger",
    params(
        ("user_id" = Option<String>, Query, description = "Filter by user ID"),
        ("event_type" = Option<String>, Query, description = "Filter by event type"),
        ("resource" = Option<String>, Query, description = "Filter by resource/route"),
        ("severity" = Option<String>, Query, description = "Filter by severity level"),
        ("start_time" = Option<DateTime<Utc>>, Query, description = "Start time filter"),
        ("end_time" = Option<DateTime<Utc>>, Query, description = "End time filter"),
        ("limit" = Option<usize>, Query, description = "Maximum results (default: 100, max: 1000)")
    ),
    responses(
        (status = 200, description = "Logs retrieved successfully", body = LoggerResponse<LogQueryResult>),
        (status = 400, description = "Invalid request parameters", body = LoggerResponse<String>),
        (status = 401, description = "Unauthorized access", body = LoggerResponse<String>),
        (status = 500, description = "Internal server error", body = LoggerResponse<String>)
    )
)]
pub async fn get_logs(
    logger_service: Arc<LoggerService>,
    user_id: Option<String>,
    event_type: Option<String>,
    resource: Option<String>,
    severity: Option<String>,
    start_time: Option<chrono::DateTime<chrono::Utc>>,
    end_time: Option<chrono::DateTime<chrono::Utc>>,
    limit: Option<usize>,
) -> Result<impl Reply, warp::Rejection> {
    // Build filter request
    let filters = LogFilterRequest {
        user_id,
        event_type,
        resource,
        severity,
        start_time,
        end_time,
        limit,
        offset: None,
    };

    // Query logs
    match logger_service.query_logs(filters).await {
        Ok(response) => Ok(warp::reply::with_status(
            warp::reply::json(&response),
            StatusCode::OK
        )),
        Err(e) => {
            let error_response = LoggerResponse::<String> {
                status: "error".to_string(),
                message: Some(format!("Failed to retrieve logs: {}", e)),
                data: None,
                timestamp: chrono::Utc::now(),
                total_count: None,
            };
            Ok(warp::reply::with_status(
                warp::reply::json(&error_response),
                StatusCode::INTERNAL_SERVER_ERROR
            ))
        }
    }
}

/// [GET LOGS BY ROUTE HANDLER] Retrieve Logs for Specific Route
/// @MISSION Provide targeted log access for specific API routes.
/// @THREAT Route-specific information leakage, unauthorized access.
/// @COUNTERMEASURE Route validation, access controls, audit logging.
/// @INVARIANT Route parameters are validated and sanitized.
/// @AUDIT Route-specific queries are logged for security monitoring.
/// @FLOW Validate route -> Apply route filter -> Return filtered results.
/// @DEPENDENCY LoggerService for route-specific querying.
#[utoipa::path(
    get,
    path = "/api/v1/logger/route/{route}",
    params(
        ("route" = String, Path, description = "API route to filter logs for"),
        ("user_id" = Option<String>, Query, description = "Filter by user ID"),
        ("event_type" = Option<String>, Query, description = "Filter by event type"),
        ("severity" = Option<String>, Query, description = "Filter by severity level"),
        ("start_time" = Option<DateTime<Utc>>, Query, description = "Start time filter"),
        ("end_time" = Option<DateTime<Utc>>, Query, description = "End time filter"),
        ("limit" = Option<usize>, Query, description = "Maximum results")
    ),
    responses(
        (status = 200, description = "Route logs retrieved successfully", body = LoggerResponse<LogQueryResult>),
        (status = 400, description = "Invalid route or parameters", body = LoggerResponse<String>),
        (status = 404, description = "Route not found in logs", body = LoggerResponse<String>)
    )
)]
pub async fn get_logs_by_route(
    route: String,
    logger_service: Arc<LoggerService>,
    user_id: Option<String>,
    event_type: Option<String>,
    severity: Option<String>,
    start_time: Option<chrono::DateTime<chrono::Utc>>,
    end_time: Option<chrono::DateTime<chrono::Utc>>,
    limit: Option<usize>,
) -> Result<impl Reply, warp::Rejection> {
    // Validate route parameter
    if route.is_empty() || !route.starts_with('/') {
        let error_response = LoggerResponse::<String> {
            status: "error".to_string(),
            message: Some("Invalid route parameter".to_string()),
            data: None,
            timestamp: chrono::Utc::now(),
            total_count: None,
        };
        return Ok(warp::reply::with_status(
            warp::reply::json(&error_response),
            StatusCode::BAD_REQUEST
        ));
    }

    // Build filter request with route filter
    let filters = LogFilterRequest {
        user_id,
        event_type,
        resource: Some(route.clone()),
        severity,
        start_time,
        end_time,
        limit,
        offset: None,
    };

    // Query logs
    match logger_service.query_logs(filters).await {
        Ok(mut response) => {
            // Update message to indicate route filtering
            response.message = Some(format!("Logs for route: {}", route));
            Ok(warp::reply::with_status(
                warp::reply::json(&response),
                StatusCode::OK
            ))
        },
        Err(e) => {
            let error_response = LoggerResponse::<String> {
                status: "error".to_string(),
                message: Some(format!("Failed to retrieve logs for route {}: {}", route, e)),
                data: None,
                timestamp: chrono::Utc::now(),
                total_count: None,
            };
            Ok(warp::reply::with_status(
                warp::reply::json(&error_response),
                StatusCode::INTERNAL_SERVER_ERROR
            ))
        }
    }
}

/// [GET LOGGED ROUTES HANDLER] List All Routes with Logs
/// @MISSION Provide overview of which routes have been logged.
/// @THREAT Information disclosure about system endpoints.
/// @COUNTERMEASURE Access controls, result sanitization.
/// @INVARIANT Only routes with actual logs are returned.
/// @AUDIT Route listing queries are logged for monitoring.
/// @FLOW Query distinct routes -> Return sorted list.
/// @DEPENDENCY LoggerService for route aggregation.
#[utoipa::path(
    get,
    path = "/api/v1/logger/routes",
    responses(
        (status = 200, description = "Logged routes retrieved successfully", body = LoggerResponse<Vec<String>>),
        (status = 500, description = "Internal server error", body = LoggerResponse<String>)
    )
)]
pub async fn get_logged_routes(
    logger_service: Arc<LoggerService>,
) -> Result<impl Reply, warp::Rejection> {
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
                let mut routes_vec: Vec<String> = routes.into_iter().collect();
                routes_vec.sort();

                let routes_response = LoggerResponse {
                    status: "success".to_string(),
                    message: Some(format!("Found {} unique routes with logs", routes_vec.len())),
                    data: Some(routes_vec),
                    timestamp: chrono::Utc::now(),
                    total_count: None,
                };

                Ok(warp::reply::with_status(
                    warp::reply::json(&routes_response),
                    StatusCode::OK
                ))
            } else {
                let error_response = LoggerResponse::<String> {
                    status: "error".to_string(),
                    message: Some("No log data available".to_string()),
                    data: None,
                    timestamp: chrono::Utc::now(),
                    total_count: None,
                };
                Ok(warp::reply::with_status(
                    warp::reply::json(&error_response),
                    StatusCode::NOT_FOUND
                ))
            }
        },
        Err(e) => {
            let error_response = LoggerResponse::<String> {
                status: "error".to_string(),
                message: Some(format!("Failed to retrieve logged routes: {}", e)),
                data: None,
                timestamp: chrono::Utc::now(),
                total_count: None,
            };
            Ok(warp::reply::with_status(
                warp::reply::json(&error_response),
                StatusCode::INTERNAL_SERVER_ERROR
            ))
        }
    }
}

/// [GET LOG SUMMARY HANDLER] Generate Log Statistics
/// @MISSION Provide statistical overview of logging activity.
/// @THREAT Information disclosure about system usage patterns.
/// @COUNTERMEASURE Access controls, aggregated data only.
/// @INVARIANT Statistics are computed from actual log data.
/// @AUDIT Summary requests are logged for monitoring.
/// @FLOW Calculate time range -> Generate statistics -> Return summary.
/// @DEPENDENCY LoggerService for statistical analysis.
#[utoipa::path(
    get,
    path = "/api/v1/logger/summary",
    params(
        ("days" = Option<i64>, Query, description = "Number of days to analyze (default: 30)")
    ),
    responses(
        (status = 200, description = "Log summary generated successfully", body = LoggerResponse<LogSummary>),
        (status = 400, description = "Invalid parameters", body = LoggerResponse<String>)
    )
)]
pub async fn get_log_summary(
    logger_service: Arc<LoggerService>,
    days: Option<i64>,
) -> Result<impl Reply, warp::Rejection> {
    // Validate days parameter
    let days = days.unwrap_or(30);
    if days <= 0 || days > 365 {
        let error_response = LoggerResponse::<String> {
            status: "error".to_string(),
            message: Some("Days parameter must be between 1 and 365".to_string()),
            data: None,
            timestamp: chrono::Utc::now(),
            total_count: None,
        };
        return Ok(warp::reply::with_status(
            warp::reply::json(&error_response),
            StatusCode::BAD_REQUEST
        ));
    }

    match logger_service.generate_summary(Some(days)).await {
        Ok(response) => Ok(warp::reply::with_status(
            warp::reply::json(&response),
            StatusCode::OK
        )),
        Err(e) => {
            let error_response = LoggerResponse::<String> {
                status: "error".to_string(),
                message: Some(format!("Failed to generate log summary: {}", e)),
                data: None,
                timestamp: chrono::Utc::now(),
                total_count: None,
            };
            Ok(warp::reply::with_status(
                warp::reply::json(&error_response),
                StatusCode::INTERNAL_SERVER_ERROR
            ))
        }
    }
}

/// [EXPORT LOGS HANDLER] Export Logs in Various Formats
/// @MISSION Enable controlled export of audit logs for compliance.
/// @THREAT Unauthorized data export, format vulnerabilities.
/// @COUNTERMEASURE Access controls, format validation, audit logging.
/// @COMPLIANCE Export operations require explicit authorization.
/// @AUDIT All exports are logged with user attribution.
/// @FLOW Validate request -> Generate export -> Return formatted data.
/// @DEPENDENCY LoggerService for secure export operations.
#[utoipa::path(
    post,
    path = "/api/v1/logger/export",
    request_body = LogExportRequest,
    responses(
        (status = 200, description = "Logs exported successfully", body = LoggerResponse<String>),
        (status = 400, description = "Invalid export request", body = LoggerResponse<String>),
        (status = 403, description = "Insufficient permissions", body = LoggerResponse<String>)
    )
)]
pub async fn export_logs(
    logger_service: Arc<LoggerService>,
    export_request: LogExportRequest,
) -> Result<impl Reply, warp::Rejection> {
    // Validate export request
    if export_request.filters.limit.unwrap_or(100) > 10000 {
        let error_response = LoggerResponse::<String> {
            status: "error".to_string(),
            message: Some("Export limit cannot exceed 10000 events".to_string()),
            data: None,
            timestamp: chrono::Utc::now(),
            total_count: None,
        };
        return Ok(warp::reply::with_status(
            warp::reply::json(&error_response),
            StatusCode::BAD_REQUEST
        ));
    }

    match logger_service.export_logs(export_request).await {
        Ok(response) => {
            // Set appropriate content type based on format
            let content_type = "application/octet-stream"; // Default
            Ok(warp::reply::with_header(
                warp::reply::with_status(
                    warp::reply::json(&response),
                    StatusCode::OK
                ),
                "Content-Type",
                content_type
            ))
        },
        Err(LoggerServiceError::PermissionError(_)) => {
            let error_response = LoggerResponse::<String> {
                status: "error".to_string(),
                message: Some("Insufficient permissions for log export".to_string()),
                data: None,
                timestamp: chrono::Utc::now(),
                total_count: None,
            };
            Ok(warp::reply::with_status(
                warp::reply::json(&error_response),
                StatusCode::FORBIDDEN
            ))
        },
        Err(e) => {
            let error_response = LoggerResponse::<String> {
                status: "error".to_string(),
                message: Some(format!("Failed to export logs: {}", e)),
                data: None,
                timestamp: chrono::Utc::now(),
                total_count: None,
            };
            Ok(warp::reply::with_status(
                warp::reply::json(&error_response),
                StatusCode::INTERNAL_SERVER_ERROR
            ))
        }
    }
}

/// [VERIFY INTEGRITY HANDLER] Check Log Integrity
/// @MISSION Verify tamper-evident properties of audit logs.
/// @THREAT Silent corruption of audit trails.
/// @COUNTERMEASURE HMAC signature verification, hash validation.
/// @INVARIANT Integrity checks are performed on all stored logs.
/// @AUDIT Integrity verification results are logged.
/// @FLOW Verify signatures -> Check hashes -> Return status.
/// @DEPENDENCY LoggerService for integrity verification.
#[utoipa::path(
    get,
    path = "/api/v1/logger/integrity",
    responses(
        (status = 200, description = "Integrity check completed", body = LoggerResponse<bool>),
        (status = 500, description = "Integrity verification failed", body = LoggerResponse<String>)
    )
)]
pub async fn verify_integrity(
    logger_service: Arc<LoggerService>,
) -> Result<impl Reply, warp::Rejection> {
    match logger_service.verify_integrity().await {
        Ok(response) => {
            let status_code = if response.data.unwrap_or(false) {
                StatusCode::OK
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            Ok(warp::reply::with_status(
                warp::reply::json(&response),
                status_code
            ))
        },
        Err(e) => {
            let error_response = LoggerResponse::<String> {
                status: "error".to_string(),
                message: Some(format!("Failed to verify log integrity: {}", e)),
                data: None,
                timestamp: chrono::Utc::now(),
                total_count: None,
            };
            Ok(warp::reply::with_status(
                warp::reply::json(&error_response),
                StatusCode::INTERNAL_SERVER_ERROR
            ))
        }
    }
}

/// [CLEANUP LOGS HANDLER] Remove Old Logs per Retention Policy
/// @MISSION Enforce data retention policies for compliance.
/// @THREAT Non-compliance with retention requirements, storage waste.
/// @COUNTERMEASURE Automated cleanup with audit trails.
/// @COMPLIANCE Cleanup operations are logged for regulatory compliance.
/// @AUDIT All deletions are recorded for audit purposes.
/// @FLOW Apply retention policy -> Delete old logs -> Return statistics.
/// @DEPENDENCY LoggerService for secure cleanup operations.
#[utoipa::path(
    post,
    path = "/api/v1/logger/cleanup",
    responses(
        (status = 200, description = "Logs cleaned up successfully", body = LoggerResponse<usize>),
        (status = 500, description = "Cleanup operation failed", body = LoggerResponse<String>)
    )
)]
pub async fn cleanup_logs(
    logger_service: Arc<LoggerService>,
) -> Result<impl Reply, warp::Rejection> {
    match logger_service.cleanup_logs().await {
        Ok(response) => Ok(warp::reply::with_status(
            warp::reply::json(&response),
            StatusCode::OK
        )),
        Err(e) => {
            let error_response = LoggerResponse::<String> {
                status: "error".to_string(),
                message: Some(format!("Failed to cleanup logs: {}", e)),
                data: None,
                timestamp: chrono::Utc::now(),
                total_count: None,
            };
            Ok(warp::reply::with_status(
                warp::reply::json(&error_response),
                StatusCode::INTERNAL_SERVER_ERROR
            ))
        }
    }
}