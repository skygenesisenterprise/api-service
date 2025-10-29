// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Authentication Guard Middleware
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide JWT token validation middleware for protecting
//  authenticated endpoints with role-based access control.
//  NOTICE: Implements Bearer token authentication with JWT validation,
//  claims extraction, and secure session management.
//  AUTH STANDARDS: JWT Bearer Tokens, Role-Based Access Control
//  COMPLIANCE: RFC 6750, GDPR token handling requirements
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use warp::{Filter, Rejection};
use crate::utils::tokens;
use crate::middlewares::auth_middleware::Claims;

/// [AUTH GUARD FILTER] JWT Bearer Token Authentication Middleware
/// @MISSION Validate JWT tokens and extract user claims for authorization.
/// @THREAT Token forgery, expired tokens, invalid signatures.
/// @COUNTERMEASURE JWT validation, signature verification, expiration checks.
/// @INVARIANT Only valid tokens with proper claims are accepted.
/// @AUDIT Token validation attempts are logged.
/// @FLOW Extract Bearer token -> Validate JWT -> Return claims.
/// @DEPENDENCY Requires tokens utility for JWT validation.
pub fn auth_guard() -> impl Filter<Extract = (Claims,), Error = Rejection> + Clone {
    warp::header::<String>("authorization")
        .and_then(|auth: String| async move {
            if !auth.starts_with("Bearer ") {
                return Err(warp::reject::custom(crate::middlewares::auth::AuthError::InvalidToken));
            }
            let token = auth.trim_start_matches("Bearer ");
            match tokens::validate_jwt(token) {
                Ok(claims) => Ok(Claims {
                    sub: claims.sub,
                    email: claims.email,
                    roles: claims.roles,
                    exp: claims.exp,
                    iat: claims.iat,
                }),
                Err(_) => Err(warp::reject::custom(crate::middlewares::auth::AuthError::InvalidToken)),
            }
        })
}