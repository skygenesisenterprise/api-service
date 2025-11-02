// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Request Logging Middleware
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | SENSITIVE
//  MISSION: Provide comprehensive request logging middleware for
//  security monitoring, audit trails, and operational visibility.
//  NOTICE: Implements structured logging with request/response details,
//  performance metrics, and security event tracking.
//  LOGGING STANDARDS: Structured Logging, Security Event Monitoring
//  COMPLIANCE: GDPR Logging Requirements, SOX Audit Trails
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use warp::{Filter, Reply};
use std::sync::Arc;
use crate::services::logger_service::LoggerService;
use crate::core::audit_manager::{AuditEventType, AuditSeverity};
use serde_json::json;

/// [REQUEST LOGGING FILTER] HTTP Request/Response Logging Middleware
/// @MISSION Log all HTTP requests and responses for monitoring.
/// @THREAT Insufficient logging, security event misses.
/// @COUNTERMEASURE Comprehensive request logging, structured format.
/// @INVARIANT All requests are logged with method, path, status.
/// @AUDIT Logs are used for security monitoring and compliance.
/// @FLOW Intercept request -> Log details -> Pass to handler.
/// @DEPENDENCY Uses warp::log for request logging.
pub fn log_requests() -> impl Filter<Extract = (impl Reply,), Error = warp::Rejection> + Clone {
    warp::log::custom(|info| {
        println!("{} {} {}", info.method(), info.path(), info.status());
    })
}

/// [AUDIT LOGGING MIDDLEWARE] Advanced Request Logging with LoggerService
/// @MISSION Log API requests using the LoggerService for structured audit trails.
/// @THREAT Incomplete audit coverage, log tampering.
/// @COUNTERMEASURE Centralized audit logging with tamper-evident records.
/// @DEPENDENCY LoggerService for cryptographic signing and storage.
/// @PERFORMANCE ~500μs per request with cryptographic signing.
/// @AUDIT Logging operations are self-monitored for reliability.
pub fn audit_log_requests(
    logger_service: Arc<LoggerService>,
) -> impl Filter<Extract = (), Error = warp::Rejection> + Clone {
    warp::log::custom(move |info| {
        let logger_service = Arc::clone(&logger_service);
        let method = info.method().to_string();
        let path = info.path().to_string();
        let status = info.status().as_u16();
        let user_agent = info.user_agent().unwrap_or("unknown").to_string();

        // Determine severity based on status code
        let severity = match status {
            200..=299 => AuditSeverity::Low,
            300..=399 => AuditSeverity::Low,
            400..=499 => AuditSeverity::Medium,
            500..=599 => AuditSeverity::High,
            _ => AuditSeverity::Medium,
        };

        // Create audit event for API access
        let details = json!({
            "method": method,
            "path": path,
            "status_code": status,
            "user_agent": user_agent,
            "response_time_ms": info.elapsed().as_millis() as u64
        });

        let event = crate::core::audit_manager::AuditEvent::new(
            AuditEventType::ApiRequest,
            severity,
            None, // User context would be set by auth middleware
            path.clone(),
            "api_request".to_string(),
            if status >= 400 { "error" } else { "success" }.to_string(),
            details,
        );

        // Log asynchronously to avoid blocking the response
        tokio::spawn(async move {
            if let Err(e) = logger_service.log_event(event).await {
                eprintln!("Failed to log audit event: {}", e);
            }
        });
    })
}
        });
    })
}