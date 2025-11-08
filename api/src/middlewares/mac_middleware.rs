// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: MAC Identity Middleware
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide middleware for MAC identity validation, security enforcement,
//  and request processing for MAC-related API endpoints.
//  NOTICE: Implements MAC format validation, ownership verification, and
//  security controls for all MAC identity operations.
//  STANDARDS: Middleware Security, MAC Validation, Request Processing
//  COMPLIANCE: API Security, MAC Identity Standards
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use warp::Filter;
use std::sync::Arc;
use uuid::Uuid;

use serde_json::json;


use crate::core::audit_manager::{AuditManager, AuditEventType, AuditSeverity};
use crate::middlewares::auth_middleware::{Claims, jwt_auth};
use crate::services::mac_service::MacService;

/// [MAC VALIDATION MIDDLEWARE] Validate MAC address format and ownership
/// @MISSION Ensure MAC addresses are properly formatted and owned by organization.
/// @THREAT Malformed MAC addresses or unauthorized access.
/// @COUNTERMEASURE Format validation and ownership verification.
/// @AUDIT All validation attempts logged.
/// @FLOW Validate Format -> Check Ownership -> Audit -> Continue
pub fn validate_mac_address(
    mac_service: Arc<MacService>,
    audit_manager: Arc<AuditManager>,
) -> impl Filter<Extract = (String,), Error = warp::Rejection> + Clone {
    warp::path::param::<String>()
        .and(jwt_auth())
        .and(with_mac_service(mac_service))
        .and(with_audit_manager(audit_manager))
        .and_then(validate_and_check_ownership)
}

/// [MAC FINGERPRINT VALIDATION MIDDLEWARE] Validate hardware fingerprint format
/// @MISSION Ensure hardware fingerprints are properly formatted UUIDs.
/// @THREAT Malformed or spoofed fingerprints.
/// @COUNTERMEASURE UUID format validation.
/// @AUDIT Invalid fingerprint attempts logged.
pub fn validate_fingerprint(
    audit_manager: Arc<AuditManager>,
) -> impl Filter<Extract = (String,), Error = warp::Rejection> + Clone {
    warp::path::param::<String>()
        .and(jwt_auth())
        .and(with_audit_manager(audit_manager))
        .and_then(validate_fingerprint_format)
}

/// [MAC RATE LIMITING MIDDLEWARE] Rate limit MAC operations per organization
/// @MISSION Prevent abuse of MAC registration and lookup operations.
/// @THREAT API abuse or DoS attacks on MAC endpoints.
/// @COUNTERMEASURE Organization-based rate limiting.
/// @AUDIT Rate limit violations logged.
pub fn mac_rate_limit(
    audit_manager: Arc<AuditManager>,
) -> impl Filter<Extract = (), Error = warp::Rejection> + Clone {
    warp::any()
        .and(jwt_auth())
        .and(with_audit_manager(audit_manager))
        .and_then(check_mac_rate_limit)
}

/// [MAC AUDIT MIDDLEWARE] Comprehensive audit logging for MAC operations
/// @MISSION Log all MAC-related operations with full context.
/// @THREAT Undetected MAC operations or security violations.
/// @COUNTERMEASURE Complete audit trail for all MAC activities.
/// @AUDIT All operations logged with user and organization context.
pub fn mac_audit_log(
    audit_manager: Arc<AuditManager>,
) -> impl Filter<Extract = (), Error = warp::Rejection> + Clone {
    warp::any()
        .and(jwt_auth())
        .and(with_audit_manager(audit_manager))
        .and_then(log_mac_operation)
}

/// Validate MAC address and check ownership
async fn validate_and_check_ownership(
    address: String,
    claims: Claims,
    mac_service: Arc<MacService>,
    audit_manager: Arc<AuditManager>,
) -> Result<String, warp::Rejection> {
    let organization_id = claims.organization_id;
    let user_id = claims.sub;

    // Validate MAC format
    if !mac_service.validate_sge_mac(&address) {
        audit_manager.audit_event(
            AuditEventType::Security,
            AuditSeverity::Warning,
            Some(&user_id.to_string()),
            "mac_middleware",
            &format!("Invalid MAC format attempted: {}", address),
            Some(json!({
                "mac_address": address,
                "organization_id": organization_id,
                "user_id": user_id
            })),
        ).await;

        return Err(warp::reject::custom(MacValidationError::InvalidFormat));
    }

    // Check if MAC exists and belongs to organization
    match mac_service.get_mac_by_address(&address, organization_id).await {
        Ok(_) => {
            audit_manager.audit_event(
                AuditEventType::Access,
                AuditSeverity::Info,
                Some(&user_id.to_string()),
                "mac_middleware",
                &format!("MAC ownership validated: {}", address),
                Some(json!({
                    "mac_address": address,
                    "organization_id": organization_id,
                    "user_id": user_id
                })),
            ).await;

            Ok(address)
        }
        Err(_) => {
            audit_manager.audit_event(
                AuditEventType::Security,
                AuditSeverity::Warning,
                Some(&user_id.to_string()),
                "mac_middleware",
                &format!("MAC ownership check failed: {}", address),
                Some(json!({
                    "mac_address": address,
                    "organization_id": organization_id,
                    "user_id": user_id
                })),
            ).await;

            Err(warp::reject::custom(MacValidationError::NotOwned))
        }
    }
}

/// Validate fingerprint format
async fn validate_fingerprint_format(
    fingerprint: String,
    claims: Claims,
    audit_manager: Arc<AuditManager>,
) -> Result<String, warp::Rejection> {
    let user_id = claims.sub;

    // Validate UUID format
    match Uuid::parse_str(&fingerprint) {
        Ok(_) => {
            audit_manager.audit_event(
                AuditEventType::Access,
                AuditSeverity::Info,
                Some(&user_id.to_string()),
                "mac_middleware",
                "Valid fingerprint format",
                Some(json!({
                    "fingerprint": fingerprint,
                    "user_id": user_id
                })),
            ).await;

            Ok(fingerprint)
        }
        Err(_) => {
            audit_manager.audit_event(
                AuditEventType::Security,
                AuditSeverity::Warning,
                Some(&user_id.to_string()),
                "mac_middleware",
                &format!("Invalid fingerprint format: {}", fingerprint),
                Some(json!({
                    "fingerprint": fingerprint,
                    "user_id": user_id
                })),
            ).await;

            Err(warp::reject::custom(MacValidationError::InvalidFingerprint))
        }
    }
}

/// Check rate limits for MAC operations
async fn check_mac_rate_limit(
    claims: Claims,
    audit_manager: Arc<AuditManager>,
) -> Result<(), warp::Rejection> {
    let organization_id = claims.organization_id;
    let user_id = claims.sub;

    // Simple in-memory rate limiting (in production, use Redis or similar)
    // This is a placeholder - implement proper rate limiting
    let rate_ok = true; // Placeholder

    if rate_ok {
        Ok(())
    } else {
        audit_manager.audit_event(
            AuditEventType::Security,
            AuditSeverity::Warning,
            Some(&user_id.to_string()),
            "mac_middleware",
            "MAC operation rate limit exceeded",
            Some(json!({
                "organization_id": organization_id,
                "user_id": user_id
            })),
        ).await;

        Err(warp::reject::custom(MacValidationError::RateLimitExceeded))
    }
}

/// Log MAC operations
async fn log_mac_operation(
    claims: Claims,
    audit_manager: Arc<AuditManager>,
) -> Result<(), warp::Rejection> {
    let organization_id = claims.organization_id;
    let user_id = claims.sub;

    audit_manager.audit_event(
        AuditEventType::Access,
        AuditSeverity::Info,
        Some(&user_id.to_string()),
        "mac_middleware",
        "MAC operation initiated",
        Some(json!({
            "organization_id": organization_id,
            "user_id": user_id
        })),
    ).await;

    Ok(())
}

/// MAC validation errors
#[derive(Debug)]
pub enum MacValidationError {
    InvalidFormat,
    NotOwned,
    InvalidFingerprint,
    RateLimitExceeded,
}

impl warp::reject::Reject for MacValidationError {}

/// Helper functions for dependency injection
fn with_mac_service(
    mac_service: Arc<MacService>,
) -> impl Filter<Extract = (Arc<MacService>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || mac_service.clone())
}

fn with_audit_manager(
    audit_manager: Arc<AuditManager>,
) -> impl Filter<Extract = (Arc<AuditManager>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || audit_manager.clone())
}