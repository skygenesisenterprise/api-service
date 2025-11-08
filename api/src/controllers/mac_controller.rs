// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: MAC Identity Management Controller
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide secure REST API endpoints for MAC identity management,
//  enabling client-server connections for device identity operations.
//  NOTICE: Implements MAC operations via /api/v1/mac endpoints with
//  authentication, authorization, rate limiting, and audit logging.
//  STANDARDS: REST API, JSON Schema, Authentication, Authorization, Auditing
//  COMPLIANCE: MAC Identity Management, Access Control
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use warp::Reply;
use std::sync::Arc;
use uuid::Uuid;

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::models::data_model::{MacIdentity, MacStatus};
use crate::services::mac_service::MacService;
use crate::core::audit_manager::{AuditManager, AuditEventType, AuditSeverity, AuditEvent};
use crate::middlewares::auth_middleware::ApiError;

/// [MAC REGISTER REQUEST] API Request for Registering New MAC Identity
#[derive(Debug, Deserialize, Serialize)]
pub struct RegisterMacRequest {
    pub sge_mac: Option<String>, // Optional, will generate if not provided
    pub standard_mac: Option<String>,
    pub ip_address: Option<String>,
    pub owner: String,
    pub fingerprint: String,
    pub metadata: Option<std::collections::HashMap<String, String>>,
}

/// [MAC UPDATE REQUEST] API Request for Updating MAC Identity
#[derive(Debug, Deserialize, Serialize)]
pub struct UpdateMacRequest {
    pub ip_address: Option<String>,
    pub status: Option<MacStatus>,
    pub metadata: Option<std::collections::HashMap<String, String>>,
}

/// [MAC LIST RESPONSE] API Response for MAC Identity List
#[derive(Debug, Serialize)]
pub struct MacListResponse {
    pub macs: Vec<MacIdentity>,
    pub total_count: i64,
    pub page: u32,
    pub per_page: u32,
}

/// [REGISTER MAC ENDPOINT] Register New MAC Identity
/// @MISSION Create new MAC identity entry in the system.
/// @THREAT Unauthorized MAC registration.
/// @COUNTERMEASURE Authentication and organization validation.
/// @AUDIT MAC registration is logged with user context.
/// @FLOW Authenticate -> Validate -> Generate/Register -> Audit -> Return
pub async fn register_mac(
    mac_service: Arc<MacService>,
    audit_manager: Arc<AuditManager>,
    organization_id: Uuid,
    user_id: Uuid,
    request: RegisterMacRequest,
) -> Result<impl Reply, warp::Rejection> {
    // Generate SGE-MAC if not provided
    let sge_mac = if let Some(mac) = request.sge_mac {
        mac
    } else {
        mac_service.generate_sge_mac(organization_id).await
            .map_err(|e| {
                warp::reject::custom(ApiError::InternalError(e.to_string()))
            })?
    };

    // Register MAC identity
    let mac = mac_service.register_mac(
        sge_mac.clone(),
        request.standard_mac,
        request.ip_address,
        request.owner,
        request.fingerprint,
        organization_id,
        request.metadata.unwrap_or_default(),
    ).await.map_err(|e| {
        warp::reject::custom(ApiError::InternalError(e.to_string()))
    })?;

    // Audit MAC registration
    audit_manager.log_event(AuditEvent {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now(),
        event_type: AuditEventType::Security,
        severity: AuditSeverity::Low,
        user_id: Some(user_id.to_string()),
        tenant_id: None,
        session_id: None,
        ip_address: None,
        user_agent: None,
        resource: "mac_api".to_string(),
        action: format!("MAC '{}' registered with ID {}", mac.sge_mac, mac.id),
        details: json!({
            "mac_id": mac.id,
            "sge_mac": mac.sge_mac,
            "organization_id": organization_id
        }),
        hmac_signature: None,
    }).await;

    Ok(warp::reply::json(&mac))
}

/// [LIST MACS ENDPOINT] Get MAC Identities for Organization
/// @MISSION Retrieve paginated list of MAC identities.
/// @THREAT Unauthorized MAC listing.
/// @COUNTERMEASURE Organization-based filtering.
/// @AUDIT MAC listing is logged.
pub async fn list_macs(
    mac_service: Arc<MacService>,
    audit_manager: Arc<AuditManager>,
    organization_id: Uuid,
    user_id: Uuid,
    page: Option<u32>,
    per_page: Option<u32>,
    status: Option<MacStatus>,
) -> Result<impl Reply, warp::Rejection> {
    let page = page.unwrap_or(1);
    let per_page = per_page.unwrap_or(50);

    let (macs, total_count) = mac_service.list_macs(
        organization_id,
        page,
        per_page,
        status,
    ).await.map_err(|e| {
        warp::reject::custom(ApiError::InternalError(e.to_string()))
    })?;

    // Audit MAC listing
    audit_manager.log_event(AuditEvent {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now(),
        event_type: AuditEventType::Access,
        severity: AuditSeverity::Low,
        user_id: Some(user_id.to_string()),
        tenant_id: None,
        session_id: None,
        ip_address: None,
        user_agent: None,
        resource: "mac_api".to_string(),
        action: format!("Listed {} MAC identities for organization", macs.len()),
        details: json!({
            "organization_id": organization_id,
            "page": page,
            "per_page": per_page,
            "total_count": total_count
        }),
        hmac_signature: None,
    }).await;

    let response = MacListResponse {
        macs,
        total_count,
        page,
        per_page,
    };

    Ok(warp::reply::json(&response))
}

/// [GET MAC ENDPOINT] Get Specific MAC Identity Details
/// @MISSION Retrieve detailed MAC identity information.
/// @THREAT Unauthorized MAC access.
/// @COUNTERMEASURE MAC ownership validation.
/// @AUDIT MAC access is logged.
pub async fn get_mac(
    mac_service: Arc<MacService>,
    audit_manager: Arc<AuditManager>,
    address: String,
    organization_id: Uuid,
    user_id: Uuid,
) -> Result<impl Reply, warp::Rejection> {
    let mac = mac_service.get_mac_by_address(&address, organization_id).await
        .map_err(|e| {
            warp::reject::custom(ApiError::InternalError(e.to_string()))
        })?;

    // Audit MAC access
    audit_manager.log_event(AuditEvent {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now(),
        event_type: AuditEventType::Access,
        severity: AuditSeverity::Low,
        user_id: Some(user_id.to_string()),
        tenant_id: None,
        session_id: None,
        ip_address: None,
        user_agent: None,
        resource: "mac_api".to_string(),
        action: format!("Accessed MAC '{}' details", mac.sge_mac),
        details: json!({
            "mac_id": mac.id,
            "sge_mac": mac.sge_mac,
            "organization_id": organization_id
        }),
        hmac_signature: None,
    }).await;

    Ok(warp::reply::json(&mac))
}

/// [UPDATE MAC ENDPOINT] Update MAC Identity Configuration
/// @MISSION Modify MAC identity settings and metadata.
/// @THREAT Unauthorized MAC modification.
/// @COUNTERMEASURE MAC ownership validation.
/// @AUDIT MAC updates are logged with changes.
pub async fn update_mac(
    mac_service: Arc<MacService>,
    audit_manager: Arc<AuditManager>,
    address: String,
    organization_id: Uuid,
    user_id: Uuid,
    request: UpdateMacRequest,
) -> Result<impl Reply, warp::Rejection> {
    let updated_mac = mac_service.update_mac(
        &address,
        organization_id,
        request.ip_address,
        request.status,
        request.metadata,
    ).await.map_err(|e| {
        warp::reject::custom(ApiError::InternalError(e.to_string()))
    })?;

    // Audit MAC update
    audit_manager.log_event(AuditEvent {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now(),
        event_type: AuditEventType::Security,
        severity: AuditSeverity::Low,
        user_id: Some(user_id.to_string()),
        tenant_id: None,
        session_id: None,
        ip_address: None,
        user_agent: None,
        resource: "mac_api".to_string(),
        action: format!("MAC '{}' updated", updated_mac.sge_mac),
        details: json!({
            "mac_id": updated_mac.id,
            "sge_mac": updated_mac.sge_mac,
            "organization_id": organization_id
        }),
        hmac_signature: None,
    }).await;

    Ok(warp::reply::json(&updated_mac))
}

/// [DELETE MAC ENDPOINT] Remove MAC Identity from Management
/// @MISSION Delete MAC identity entry and associated data.
/// @THREAT Unauthorized MAC deletion.
/// @COUNTERMEASURE MAC ownership validation.
/// @AUDIT MAC deletion is logged.
pub async fn delete_mac(
    mac_service: Arc<MacService>,
    audit_manager: Arc<AuditManager>,
    address: String,
    organization_id: Uuid,
    user_id: Uuid,
) -> Result<impl Reply, warp::Rejection> {
    let mac_name = mac_service.get_mac_by_address(&address, organization_id).await
        .map(|m| m.sge_mac)
        .unwrap_or_else(|_| "unknown".to_string());

    mac_service.delete_mac(&address, organization_id).await
        .map_err(|e| {
            warp::reject::custom(ApiError::InternalError(e.to_string()))
        })?;

    // Audit MAC deletion
    audit_manager.log_event(AuditEvent {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now(),
        event_type: AuditEventType::Security,
        severity: AuditSeverity::Medium,
        user_id: Some(user_id.to_string()),
        tenant_id: None,
        session_id: None,
        ip_address: None,
        user_agent: None,
        resource: "mac_api".to_string(),
        action: format!("MAC '{}' deleted", mac_name),
        details: json!({
            "sge_mac": address,
            "organization_id": organization_id
        }),
        hmac_signature: None,
    }).await;

    Ok(warp::reply::json(&json!({"status": "mac_deleted"})))
}

/// [RESOLVE IP ENDPOINT] Resolve IP Address to MAC Identity
/// @MISSION Find MAC identity associated with an IP address.
/// @THREAT Unauthorized IP resolution.
/// @COUNTERMEASURE Organization-based filtering.
/// @AUDIT IP resolution is logged.
pub async fn resolve_ip(
    mac_service: Arc<MacService>,
    audit_manager: Arc<AuditManager>,
    ip: String,
    organization_id: Uuid,
    user_id: Uuid,
) -> Result<impl Reply, warp::Rejection> {
    let mac = mac_service.resolve_ip_to_mac(&ip, organization_id).await
        .map_err(|e| {
            warp::reject::custom(ApiError::InternalError(e.to_string()))
        })?;

    // Audit IP resolution
    audit_manager.log_event(AuditEvent {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now(),
        event_type: AuditEventType::Access,
        severity: AuditSeverity::Low,
        user_id: Some(user_id.to_string()),
        tenant_id: None,
        session_id: None,
        ip_address: None,
        user_agent: None,
        resource: "mac_api".to_string(),
        action: format!("Resolved IP {} to MAC {}", ip, mac.sge_mac),
        details: json!({
            "ip_address": ip,
            "mac_id": mac.id,
            "sge_mac": mac.sge_mac,
            "organization_id": organization_id
        }),
        hmac_signature: None,
    }).await;

    Ok(warp::reply::json(&mac))
}

/// [GET MAC BY FINGERPRINT ENDPOINT] Get MAC Identity by Hardware Fingerprint
/// @MISSION Retrieve MAC identity using hardware fingerprint.
/// @THREAT Unauthorized fingerprint access.
/// @COUNTERMEASURE Organization-based filtering.
/// @AUDIT Fingerprint lookup is logged.
pub async fn get_mac_by_fingerprint(
    mac_service: Arc<MacService>,
    audit_manager: Arc<AuditManager>,
    fingerprint: String,
    organization_id: Uuid,
    user_id: Uuid,
) -> Result<impl Reply, warp::Rejection> {
    let mac = mac_service.get_mac_by_fingerprint(&fingerprint, organization_id).await
        .map_err(|e| {
            warp::reject::custom(ApiError::InternalError(e.to_string()))
        })?;

    // Audit fingerprint lookup
    audit_manager.log_event(AuditEvent {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now(),
        event_type: AuditEventType::Access,
        severity: AuditSeverity::Low,
        user_id: Some(user_id.to_string()),
        tenant_id: None,
        session_id: None,
        ip_address: None,
        user_agent: None,
        resource: "mac_api".to_string(),
        action: format!("Accessed MAC '{}' via fingerprint", mac.sge_mac),
        details: json!({
            "fingerprint": fingerprint,
            "mac_id": mac.id,
            "sge_mac": mac.sge_mac,
            "organization_id": organization_id
        }),
        hmac_signature: None,
    }).await;

    Ok(warp::reply::json(&mac))
}

/// [REGISTER MAC WITH CERTIFICATE ENDPOINT] Register New MAC Identity with Certificate
/// @MISSION Create new MAC identity with cryptographic certificate.
/// @THREAT Unauthorized MAC registration without security.
/// @COUNTERMEASURE Certificate-based authentication and validation.
/// @AUDIT Certificate-backed MAC registration is logged.
/// @FLOW Authenticate -> Generate Certificate -> Register -> Audit -> Return
pub async fn register_mac_with_certificate(
    mac_service: Arc<MacService>,
    audit_manager: Arc<AuditManager>,
    organization_id: Uuid,
    user_id: Uuid,
    request: RegisterMacRequest,
    organization_name: String,
) -> Result<impl Reply, warp::Rejection> {
    // Generate SGE-MAC if not provided
    let sge_mac = if let Some(mac) = request.sge_mac {
        mac
    } else {
        mac_service.generate_sge_mac(organization_id).await
            .map_err(|e| {
                warp::reject::custom(ApiError::InternalError(e.to_string()))
            })?
    };

    // Register MAC with certificate
    let mac = mac_service.register_mac_with_certificate(
        sge_mac.clone(),
        request.standard_mac,
        request.ip_address,
        request.owner,
        request.fingerprint,
        organization_id,
        &organization_name,
        request.metadata.unwrap_or_default(),
    ).await.map_err(|e| {
        warp::reject::custom(ApiError::InternalError(e.to_string()))
    })?;

    // Audit certificate-backed registration
    audit_manager.log_event(AuditEvent {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now(),
        event_type: AuditEventType::Security,
        severity: AuditSeverity::Low,
        user_id: Some(user_id.to_string()),
        tenant_id: None,
        session_id: None,
        ip_address: None,
        user_agent: None,
        resource: "mac_api".to_string(),
        action: format!("MAC '{}' registered with certificate", mac.sge_mac),
        details: json!({
            "mac_id": mac.id,
            "sge_mac": mac.sge_mac,
            "has_certificate": mac.certificate.is_some(),
            "has_signature": mac.signature.is_some(),
            "organization_id": organization_id
        }),
        hmac_signature: None,
    }).await;

    Ok(warp::reply::json(&mac))
}

/// [VERIFY MAC INTEGRITY ENDPOINT] Verify MAC Certificate and Signature
/// @MISSION Validate cryptographic integrity of MAC identity.
/// @THREAT Compromised or tampered MAC identities.
/// @COUNTERMEASURE Certificate and signature verification.
/// @AUDIT Integrity verification is logged.
pub async fn verify_mac_integrity(
    mac_service: Arc<MacService>,
    audit_manager: Arc<AuditManager>,
    address: String,
    organization_id: Uuid,
    user_id: Uuid,
) -> Result<impl Reply, warp::Rejection> {
    let mac = mac_service.get_mac_by_address(&address, organization_id).await
        .map_err(|e| {
            warp::reject::custom(ApiError::InternalError(e.to_string()))
        })?;

    let is_valid = mac_service.verify_mac_integrity(&mac).await
        .map_err(|e| {
            warp::reject::custom(ApiError::InternalError(e.to_string()))
        })?;

    // Audit integrity verification
    audit_manager.log_event(AuditEvent {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now(),
        event_type: AuditEventType::Security,
        severity: AuditSeverity::Low,
        user_id: Some(user_id.to_string()),
        tenant_id: None,
        session_id: None,
        ip_address: None,
        user_agent: None,
        resource: "mac_api".to_string(),
        action: format!("MAC integrity verification: {} - {}", mac.sge_mac, if is_valid { "VALID" } else { "INVALID" }),
        details: json!({
            "mac_id": mac.id,
            "sge_mac": mac.sge_mac,
            "is_valid": is_valid,
            "organization_id": organization_id
        }),
        hmac_signature: None,
    }).await;

    Ok(warp::reply::json(&json!({
        "mac_address": address,
        "is_valid": is_valid,
        "certificate_valid": mac.certificate.as_ref().map(|_| true).unwrap_or(false),
        "signature_valid": mac.signature.as_ref().map(|_| true).unwrap_or(false)
    })))
}

/// [RENEW MAC CERTIFICATE ENDPOINT] Renew MAC Certificate
/// @MISSION Extend certificate validity before expiration.
/// @THREAT Certificate expiration causing service disruption.
/// @COUNTERMEASURE Proactive certificate renewal.
/// @AUDIT Certificate renewal is logged.
pub async fn renew_mac_certificate(
    mac_service: Arc<MacService>,
    audit_manager: Arc<AuditManager>,
    address: String,
    organization_id: Uuid,
    user_id: Uuid,
    validity_days: u32,
    organization_name: String,
) -> Result<impl Reply, warp::Rejection> {
    let updated_mac = mac_service.renew_mac_certificate(
        &address,
        organization_id,
        &organization_name,
        validity_days as i64,
        &user_id,
    ).await.map_err(|e| {
        warp::reject::custom(ApiError::InternalError(e.to_string()))
    })?;

    // Audit certificate renewal
    audit_manager.log_event(AuditEvent {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now(),
        event_type: AuditEventType::Security,
        severity: AuditSeverity::Low,
        user_id: Some(user_id.to_string()),
        tenant_id: None,
        session_id: None,
        ip_address: None,
        user_agent: None,
        resource: "mac_api".to_string(),
        action: format!("MAC certificate renewed: {}", updated_mac.sge_mac),
        details: json!({
            "mac_id": updated_mac.id,
            "sge_mac": updated_mac.sge_mac,
            "validity_days": validity_days,
            "organization_id": organization_id
        }),
        hmac_signature: None,
    }).await;

    Ok(warp::reply::json(&updated_mac))
}

/// [REVOKE MAC CERTIFICATE ENDPOINT] Revoke MAC Certificate
/// @MISSION Revoke compromised certificates.
/// @THREAT Continued use of compromised certificates.
/// @COUNTERMEASURE Certificate revocation.
/// @AUDIT Certificate revocation is logged.
pub async fn revoke_mac_certificate(
    mac_service: Arc<MacService>,
    audit_manager: Arc<AuditManager>,
    address: String,
    organization_id: Uuid,
    user_id: Uuid,
    reason: String,
) -> Result<impl Reply, warp::Rejection> {
    mac_service.revoke_mac_certificate(&address, organization_id, &reason, &user_id).await
        .map_err(|e| {
            warp::reject::custom(ApiError::InternalError(e.to_string()))
        })?;

    // Audit certificate revocation
    audit_manager.log_event(AuditEvent {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now(),
        event_type: AuditEventType::Security,
        severity: AuditSeverity::Medium,
        user_id: Some(user_id.to_string()),
        tenant_id: None,
        session_id: None,
        ip_address: None,
        user_agent: None,
        resource: "mac_api".to_string(),
        action: format!("MAC certificate revoked: {}", address),
        details: json!({
            "sge_mac": address,
            "revocation_reason": reason,
            "organization_id": organization_id
        }),
        hmac_signature: None,
    }).await;

    Ok(warp::reply::json(&json!({"status": "certificate_revoked"})))
}

/// [GET MAC CERTIFICATE CHAIN ENDPOINT] Get Certificate Chain for MAC
/// @MISSION Provide complete certificate chain for validation.
/// @THREAT Incomplete certificate chains.
/// @COUNTERMEASURE Full chain construction.
/// @AUDIT Certificate chain access is logged.
pub async fn get_mac_certificate_chain(
    mac_service: Arc<MacService>,
    audit_manager: Arc<AuditManager>,
    address: String,
    organization_id: Uuid,
    user_id: Uuid,
) -> Result<impl Reply, warp::Rejection> {
    let mac = mac_service.get_mac_by_address(&address, organization_id).await
        .map_err(|e| {
            warp::reject::custom(ApiError::InternalError(e.to_string()))
        })?;

    let chain = mac_service.get_mac_certificate_chain(&mac)
        .map_err(|e| {
            warp::reject::custom(ApiError::InternalError(e.to_string()))
        })?;

    // Audit certificate chain access
    audit_manager.log_event(AuditEvent {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now(),
        event_type: AuditEventType::Access,
        severity: AuditSeverity::Low,
        user_id: Some(user_id.to_string()),
        tenant_id: None,
        session_id: None,
        ip_address: None,
        user_agent: None,
        resource: "mac_api".to_string(),
        action: format!("MAC certificate chain retrieved: {}", mac.sge_mac),
        details: json!({
            "mac_id": mac.id,
            "sge_mac": mac.sge_mac,
            "chain_length": chain.len(),
            "organization_id": organization_id
        }),
        hmac_signature: None,
    }).await;

    Ok(warp::reply::json(&json!({
        "mac_address": address,
        "certificate_chain": chain
    })))
}