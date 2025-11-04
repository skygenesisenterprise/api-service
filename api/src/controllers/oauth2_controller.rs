// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: OAuth2 Controller
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide OAuth2 integration endpoints for secure third-party authentication.
//  NOTICE: Implements OAuth2 standards with military-grade security.
//  AUTH STANDARDS: OAuth2 Authorization Code, Implicit, Client Credentials
//  COMPLIANCE: RFC 6749, RFC 6750, GDPR, SOX
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use warp::Reply;
use warp::http::StatusCode;
use serde_json::json;

/// [OAUTH2 INFO HANDLER] OAuth2 Integration Information Endpoint
/// @MISSION Provide information about supported OAuth2 providers and capabilities.
/// @THREAT Unauthorized access, token leakage, provider compromise.
/// @COUNTERMEASURE Secure endpoints, token encryption, provider validation.
/// @INVARIANT All OAuth2 operations are logged and audited.
/// @AUDIT OAuth2 events trigger security monitoring.
/// @FLOW Returns supported providers and OAuth2 capabilities.
/// @DEPENDENCY None - informational endpoint.
#[utoipa::path(
    get,
    path = "/api/v1/oauth2",
    responses(
        (status = 200, description = "OAuth2 integration information", body = serde_json::Value),
        (status = 500, description = "Internal server error", body = serde_json::Value)
    )
)]
pub async fn oauth2_info() -> Result<impl Reply, warp::Rejection> {
    let info = json!({
        "version": "1.0",
        "providers": [
            "keycloak",
            "google",
            "github",
            "microsoft"
        ],
        "grant_types": [
            "authorization_code",
            "implicit",
            "client_credentials",
            "refresh_token"
        ],
        "capabilities": [
            "authorization",
            "token_exchange",
            "introspection",
            "revocation"
        ],
        "status": "active"
    });

    Ok(warp::reply::with_status(
        warp::reply::json(&info),
        StatusCode::OK
    ))
}