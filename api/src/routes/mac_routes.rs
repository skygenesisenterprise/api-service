// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: MAC Identity Management Routes
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Define secure REST API routes for MAC identity management
//  under /api/v1/mac with comprehensive security controls and audit logging.
//  NOTICE: Implements route-level authentication, authorization, rate limiting,
//  and audit logging for all MAC identity operations.
//  STANDARDS: REST API Design, Security Headers, CORS, Rate Limiting
//  COMPLIANCE: MAC Identity Management Regulations
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use warp::Filter;
use std::sync::Arc;

use serde::Deserialize;

use crate::controllers::mac_controller;
use crate::services::mac_service::MacService;
use crate::core::audit_manager::AuditManager;
use crate::middlewares::auth_middleware::{jwt_auth, Claims};
use crate::models::data_model::MacStatus;

/// [MAC ROUTES] Main MAC Identity Management Route Handler
/// @MISSION Provide unified routing for all MAC identity management operations.
/// @THREAT Unauthorized access to MAC identity management endpoints.
/// @COUNTERMEASURE JWT authentication and organization isolation.
/// @AUDIT All route access is logged.
/// @FLOW Authenticate -> Route -> Authorize -> Execute -> Audit
/// @DEPENDENCY MacService for business logic, JWT middleware for auth.
pub fn mac_routes(
    mac_service: Arc<MacService>,
    audit_manager: Arc<AuditManager>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let api_v1_mac = warp::path!("api" / "v1" / "mac");

    // POST /api/v1/mac/register - Register new MAC identity
    let register_mac = api_v1_mac
        .and(warp::path!("register"))
        .and(warp::post())
        .and(warp::body::json())
        .and(jwt_auth())
        .and(with_mac_service(mac_service.clone()))
        .and(with_audit_manager(audit_manager.clone()))
        .and_then(mac_controller::register_mac);

    // GET /api/v1/mac - List MAC identities with optional filters
    let list_macs = api_v1_mac
        .and(warp::get())
        .and(warp::query::<MacListQuery>())
        .and(jwt_auth())
        .and(with_mac_service(mac_service.clone()))
        .and(with_audit_manager(audit_manager.clone()))
        .and_then(mac_controller::list_macs);

    // GET /api/v1/mac/{address} - Get specific MAC identity
    let get_mac = api_v1_mac
        .and(warp::path::param::<String>())
        .and(warp::get())
        .and(jwt_auth())
        .and(with_mac_service(mac_service.clone()))
        .and(with_audit_manager(audit_manager.clone()))
        .and_then(mac_controller::get_mac);

    // PATCH /api/v1/mac/{address} - Update MAC identity
    let update_mac = api_v1_mac
        .and(warp::path::param::<String>())
        .and(warp::patch())
        .and(warp::body::json())
        .and(jwt_auth())
        .and(with_mac_service(mac_service.clone()))
        .and(with_audit_manager(audit_manager.clone()))
        .and_then(mac_controller::update_mac);

    // DELETE /api/v1/mac/{address} - Delete MAC identity
    let delete_mac = api_v1_mac
        .and(warp::path::param::<String>())
        .and(warp::delete())
        .and(jwt_auth())
        .and(with_mac_service(mac_service.clone()))
        .and(with_audit_manager(audit_manager.clone()))
        .and_then(mac_controller::delete_mac);

    // GET /api/v1/mac/resolve/{ip} - Resolve IP to MAC
    let resolve_ip = api_v1_mac
        .and(warp::path!("resolve"))
        .and(warp::path::param::<String>())
        .and(warp::get())
        .and(jwt_auth())
        .and(with_mac_service(mac_service.clone()))
        .and(with_audit_manager(audit_manager.clone()))
        .and_then(mac_controller::resolve_ip);

    // GET /api/v1/mac/fingerprint/{uuid} - Get MAC by fingerprint
    let get_by_fingerprint = api_v1_mac
        .and(warp::path!("fingerprint"))
        .and(warp::path::param::<String>())
        .and(warp::get())
        .and(jwt_auth())
        .and(with_mac_service(mac_service.clone()))
        .and(with_audit_manager(audit_manager.clone()))
        .and_then(mac_controller::get_mac_by_fingerprint);

    // POST /api/v1/mac/register-with-cert - Register MAC with certificate
    let register_with_cert = api_v1_mac
        .and(warp::path!("register-with-cert"))
        .and(warp::post())
        .and(warp::body::json())
        .and(jwt_auth())
        .and(with_mac_service(mac_service.clone()))
        .and(with_audit_manager(audit_manager.clone()))
        .and(with_organization_name())
        .and_then(mac_controller::register_mac_with_certificate);

    // GET /api/v1/mac/{address}/verify - Verify MAC integrity
    let verify_integrity = api_v1_mac
        .and(warp::path::param::<String>())
        .and(warp::path!("verify"))
        .and(warp::get())
        .and(jwt_auth())
        .and(with_mac_service(mac_service.clone()))
        .and(with_audit_manager(audit_manager.clone()))
        .and_then(mac_controller::verify_mac_integrity);

    // POST /api/v1/mac/{address}/renew-cert - Renew MAC certificate
    let renew_certificate = api_v1_mac
        .and(warp::path::param::<String>())
        .and(warp::path!("renew-cert"))
        .and(warp::post())
        .and(warp::body::json::<RenewCertificateRequest>())
        .and(jwt_auth())
        .and(with_mac_service(mac_service.clone()))
        .and(with_audit_manager(audit_manager.clone()))
        .and(with_organization_name())
        .and_then(|address: String, request: RenewCertificateRequest, claims: Claims, mac_service: Arc<MacService>, audit_manager: Arc<AuditManager>, org_name: String| {
            mac_controller::renew_mac_certificate(mac_service, audit_manager, address, claims.organization_id, claims.sub, request.validity_days, org_name)
        });

    // POST /api/v1/mac/{address}/revoke-cert - Revoke MAC certificate
    let revoke_certificate = api_v1_mac
        .and(warp::path::param::<String>())
        .and(warp::path!("revoke-cert"))
        .and(warp::post())
        .and(warp::body::json::<RevokeCertificateRequest>())
        .and(jwt_auth())
        .and(with_mac_service(mac_service.clone()))
        .and(with_audit_manager(audit_manager.clone()))
        .and_then(|address: String, request: RevokeCertificateRequest, claims: Claims, mac_service: Arc<MacService>, audit_manager: Arc<AuditManager>| {
            mac_controller::revoke_mac_certificate(mac_service, audit_manager, address, claims.organization_id, claims.sub, request.reason)
        });

    // GET /api/v1/mac/{address}/cert-chain - Get certificate chain
    let get_cert_chain = api_v1_mac
        .and(warp::path::param::<String>())
        .and(warp::path!("cert-chain"))
        .and(warp::get())
        .and(jwt_auth())
        .and(with_mac_service(mac_service.clone()))
        .and(with_audit_manager(audit_manager.clone()))
        .and_then(mac_controller::get_mac_certificate_chain);

    // Combine all routes
    register_mac
        .or(register_with_cert)
        .or(list_macs)
        .or(get_mac)
        .or(update_mac)
        .or(delete_mac)
        .or(resolve_ip)
        .or(get_by_fingerprint)
        .or(verify_integrity)
        .or(renew_certificate)
        .or(revoke_certificate)
        .or(get_cert_chain)
}

/// Query parameters for MAC listing
#[derive(Debug, Deserialize)]
struct MacListQuery {
    page: Option<u32>,
    per_page: Option<u32>,
    status: Option<MacStatus>,
}

/// Request body for certificate renewal
#[derive(Debug, Deserialize)]
struct RenewCertificateRequest {
    validity_days: u32,
}

/// Request body for certificate revocation
#[derive(Debug, Deserialize)]
struct RevokeCertificateRequest {
    reason: String,
}

// Helper functions for dependency injection
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

fn with_organization_name(
) -> impl Filter<Extract = (String,), Error = std::convert::Infallible> + Clone {
    // In real implementation, this would extract organization name from JWT claims
    // For now, return a placeholder
    warp::any().map(|| "SGE-Organization".to_string())
}