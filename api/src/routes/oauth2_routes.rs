// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: OAuth2 Routes
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Define OAuth2 integration routes for secure third-party authentication.
//  NOTICE: Routes implement OAuth2 standards with military-grade security.
//  ROUTE STANDARDS: REST API, OAuth2 RFC compliance
//  COMPLIANCE: RFC 6749, RFC 6750, GDPR, SOX
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use warp::Filter;

pub fn oauth2_routes() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let oauth2_info = warp::path!("api" / "v1" / "oauth2")
        .and(warp::get())
        .and_then(|| async {
            crate::controllers::oauth2_controller::oauth2_info().await
        });

    oauth2_info
}