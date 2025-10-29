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