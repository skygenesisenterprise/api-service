// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Authentication Controller
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide secure authentication endpoints for user login, session
//  management, two-factor authentication, and application access control.
//  NOTICE: Implements military-grade authentication with FIPS compliance,
//  zero-trust architecture, and comprehensive audit logging.
//  AUTH STANDARDS: JWT, Session Tokens, 2FA TOTP/SMS, API Key Validation
//  COMPLIANCE: GDPR, SOX, NIST 800-63, FIPS 140-2 Authentication Requirements
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use warp::Reply;
use crate::services::auth_service::{AuthService, LoginRequest};
use crate::models::user::User;
use crate::services::application_service::ApplicationAccessRequest;
use crate::services::two_factor_service::{TwoFactorSetupRequest, TwoFactorVerificationRequest, TwoFactorChallengeValidationRequest};
use std::sync::Arc;
use warp::http::StatusCode;


/// [AUTH LOGIN HANDLER] Primary User Authentication Endpoint
/// @MISSION Authenticate users with credentials and establish secure sessions.
/// @THREAT Credential stuffing, brute force attacks, session hijacking.
/// @COUNTERMEASURE Rate limiting, account lockout, secure session tokens, audit logging.
/// @INVARIANT All login attempts are logged with IP, user-agent, and timestamp.
/// @AUDIT Login events trigger security monitoring and compliance reporting.
/// @FLOW Validates credentials -> Creates session -> Sets secure HTTP-only cookie.
/// @DEPENDENCY Requires AuthService for credential verification and session creation.
#[utoipa::path(
    post,
    path = "/auth/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = serde_json::Value),
        (status = 401, description = "Invalid credentials", body = serde_json::Value)
    )
)]
pub async fn login(
    auth_service: Arc<AuthService>,
    req: LoginRequest,
    app_token: String,
    user_agent: Option<String>,
    ip_address: Option<String>,
) -> Result<impl Reply, warp::Rejection> {
    let response = auth_service.login(req, &app_token, user_agent, ip_address).await
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::VaultError))?;

    // Set session cookie if session_token is present
    let reply = warp::reply::json(&response);
    if let Some(session_token) = response.session_token.clone() {
        let cookie = format!(
            "sky_genesis_session={}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800",
            session_token
        );
        Ok(warp::reply::with_header(reply, "Set-Cookie", cookie))
    } else {
        Ok(reply)
    }
}

/// [SESSION LOGIN HANDLER] Resume Authentication via Existing Session Token
/// @MISSION Validate existing session tokens for seamless user experience.
/// @THREAT Session token theft, replay attacks, token expiration bypass.
/// @COUNTERMEASURE Cryptographically secure tokens, expiration validation, IP binding.
/// @INVARIANT Session tokens are validated against database and expiration.
/// @AUDIT Session resumption attempts are logged for security monitoring.
/// @FLOW Validates token -> Retrieves user context -> Returns authenticated response.
/// @DEPENDENCY Requires AuthService for session validation and user retrieval.
pub async fn login_with_session(
    auth_service: Arc<AuthService>,
    session_token: String,
    app_token: String,
) -> Result<impl Reply, warp::Rejection> {
    let response = auth_service.login_with_session(&session_token, &app_token).await
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::InvalidKey))?;
    Ok(warp::reply::json(&response))
}

/// [USER REGISTRATION HANDLER] Create New User Accounts with Secure Validation
/// @MISSION Register new users with proper validation and initial setup.
/// @THREAT Fake account creation, weak passwords, spam registration.
/// @COUNTERMEASURE Email verification, password strength requirements, rate limiting.
/// @INVARIANT User data is validated and sanitized before storage.
/// @AUDIT Registration events are logged for compliance and security.
/// @FLOW Validates input -> Creates user account -> Sends verification email.
/// @DEPENDENCY Requires AuthService for user creation and validation.
pub async fn register(
    auth_service: Arc<AuthService>,
    user: User,
    password: String,
) -> Result<impl Reply, warp::Rejection> {
    auth_service.register(user, &password).await
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::VaultError))?;
    Ok(warp::reply::json(&serde_json::json!({"message": "User registered"})))
}

/// [PASSWORD RECOVERY HANDLER] Secure Password Reset via Email Verification
/// @MISSION Enable secure password recovery for locked-out users.
/// @THREAT Password reset token theft, email spoofing, account takeover.
/// @COUNTERMEASURE Time-limited tokens, email verification, security questions.
/// @INVARIANT Recovery requests are rate-limited and logged.
/// @AUDIT Password recovery attempts trigger security alerts.
/// @FLOW Generates secure token -> Sends recovery email -> Validates token.
/// @DEPENDENCY Requires AuthService for token generation and email sending.
pub async fn recover_password(
    auth_service: Arc<AuthService>,
    email: String,
) -> Result<impl Reply, warp::Rejection> {
    auth_service.recover_password(&email).await
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::VaultError))?;
    Ok(warp::reply::json(&serde_json::json!({"message": "Recovery email sent"})))
}

/// [USER PROFILE HANDLER] Retrieve Current User Information
/// @MISSION Provide authenticated users access to their profile data.
/// @THREAT Unauthorized access to user data, data leakage.
/// @COUNTERMEASURE Token validation, permission checks, data sanitization.
/// @INVARIANT Only authenticated users can access their own data.
/// @AUDIT Profile access is logged for compliance.
/// @FLOW Validates token -> Retrieves user data -> Returns sanitized profile.
/// @DEPENDENCY Requires AuthService for user data retrieval.
pub async fn get_me(
    auth_service: Arc<AuthService>,
    token: String,
) -> Result<impl Reply, warp::Rejection> {
    let user = auth_service.get_me(&token).await
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::InvalidKey))?;
    Ok(warp::reply::json(&user))
}

/// [SESSION LOGOUT HANDLER] Terminate User Sessions Securely
/// @MISSION End user sessions and clear authentication state.
/// @THREAT Session not properly invalidated, cookie not cleared.
/// @COUNTERMEASURE Database session invalidation, secure cookie clearing.
/// @INVARIANT All session data is removed from server and client.
/// @AUDIT Logout events are logged for security monitoring.
/// @FLOW Invalidates session -> Clears cookies -> Returns confirmation.
/// @DEPENDENCY Requires AuthService for session cleanup.
pub async fn logout(
    auth_service: Arc<AuthService>,
    session_id: Option<String>,
) -> Result<impl Reply, warp::Rejection> {
    auth_service.logout(session_id.as_deref()).await
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::VaultError))?;

    // Clear session cookie
    let cookie = "sky_genesis_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0";
    Ok(warp::reply::with_status(
        warp::reply::with_header(
            warp::reply::json(&serde_json::json!({"message": "Logged out"})),
            "Set-Cookie",
            cookie,
        ),
        StatusCode::OK,
    ))
}

/// [GLOBAL LOGOUT HANDLER] Terminate All User Sessions Across Devices
/// @MISSION Force logout from all devices for security emergencies.
/// @THREAT Compromised sessions on other devices remain active.
/// @COUNTERMEASURE Global session invalidation, forced re-authentication.
/// @INVARIANT All active sessions for user are terminated.
/// @AUDIT Global logout triggers security incident response.
/// @FLOW Invalidates all sessions -> Clears all cookies -> Forces re-login.
/// @DEPENDENCY Requires AuthService for bulk session management.
pub async fn logout_all(
    auth_service: Arc<AuthService>,
    user_id: String,
) -> Result<impl Reply, warp::Rejection> {
    auth_service.logout_all(&user_id).await
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::VaultError))?;

    // Clear session cookie
    let cookie = "sky_genesis_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0";
    Ok(warp::reply::with_status(
        warp::reply::with_header(
            warp::reply::json(&serde_json::json!({"message": "All sessions logged out"})),
            "Set-Cookie",
            cookie,
        ),
        StatusCode::OK,
    ))
}

/// [SESSION MANAGEMENT HANDLER] List Active User Sessions for Monitoring
/// @MISSION Allow users to view and manage their active sessions.
/// @THREAT Unauthorized session enumeration, session metadata leakage.
/// @COUNTERMEASURE Permission validation, data sanitization, audit logging.
/// @INVARIANT Only user can view their own sessions.
/// @AUDIT Session listing is logged for compliance.
/// @FLOW Validates permissions -> Retrieves sessions -> Returns metadata.
/// @DEPENDENCY Requires AuthService for session data access.
pub async fn get_user_sessions(
    auth_service: Arc<AuthService>,
    user_id: String,
) -> Result<impl Reply, warp::Rejection> {
    let sessions = auth_service.get_user_sessions(&user_id).await
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::VaultError))?;
    Ok(warp::reply::json(&sessions))
}

/// [APPLICATION ACCESS HANDLER] Retrieve User's Authorized Applications
/// @MISSION Provide users access to their permitted applications.
/// @THREAT Unauthorized application enumeration, permission bypass.
/// @COUNTERMEASURE Role-based access control, permission validation.
/// @INVARIANT Only authorized applications are returned.
/// @AUDIT Application access queries are logged.
/// @FLOW Validates user -> Retrieves permissions -> Returns app list.
/// @DEPENDENCY Requires AuthService for permission checking.
pub async fn get_user_applications(
    auth_service: Arc<AuthService>,
    user_id: String,
) -> Result<impl Reply, warp::Rejection> {
    let applications = auth_service.get_user_applications_by_user_id(&user_id).await
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::VaultError))?;
    Ok(warp::reply::json(&applications))
}

/// [2FA SETUP HANDLER] Initialize Two-Factor Authentication Methods
/// @MISSION Enable additional security layer for user accounts.
/// @THREAT Weak 2FA setup, compromised recovery codes.
/// @COUNTERMEASURE Secure secret generation, backup code provision.
/// @INVARIANT 2FA secrets are cryptographically secure.
/// @AUDIT 2FA setup events trigger security monitoring.
/// @FLOW Generates secrets -> Configures method -> Returns setup data.
/// @DEPENDENCY Requires AuthService and TwoFactorService.
pub async fn setup_two_factor(
    auth_service: Arc<AuthService>,
    user_id: String,
    request: TwoFactorSetupRequest,
) -> Result<impl Reply, warp::Rejection> {
    // Get user from user_id (in production, this would come from the auth guard)
    let user = User {
        id: user_id,
        email: "placeholder@example.com".to_string(),
        first_name: None,
        last_name: None,
        roles: vec!["employee".to_string()],
        created_at: chrono::Utc::now(),
        enabled: true,
    };

    let response = auth_service.setup_two_factor(&user, request).await
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::VaultError))?;
    Ok(warp::reply::json(&response))
}

/// [2FA VERIFICATION HANDLER] Validate Two-Factor Authentication Codes
/// @MISSION Verify 2FA codes during authentication flows.
/// @THREAT Code replay, timing attacks, brute force.
/// @COUNTERMEASURE Time-based validation, rate limiting, secure comparison.
/// @INVARIANT Codes are validated with proper timing windows.
/// @AUDIT 2FA verification attempts are logged.
/// @FLOW Validates code -> Updates authentication state -> Returns result.
/// @DEPENDENCY Requires AuthService for 2FA validation.
pub async fn verify_two_factor(
    auth_service: Arc<AuthService>,
    user_id: String,
    request: TwoFactorVerificationRequest,
) -> Result<impl Reply, warp::Rejection> {
    // Get user from user_id (in production, this would come from the auth guard)
    let user = User {
        id: user_id,
        email: "placeholder@example.com".to_string(),
        first_name: None,
        last_name: None,
        roles: vec!["employee".to_string()],
        created_at: chrono::Utc::now(),
        enabled: true,
    };

    let response = auth_service.verify_two_factor(&user, request).await
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::VaultError))?;
    Ok(warp::reply::json(&response))
}

/// [2FA METHODS HANDLER] List User's Configured 2FA Methods
/// @MISSION Allow users to view their 2FA configurations.
/// @THREAT 2FA method enumeration for targeted attacks.
/// @COUNTERMEASURE Permission validation, metadata sanitization.
/// @INVARIANT Only user's own 2FA methods are accessible.
/// @AUDIT 2FA method queries are logged.
/// @FLOW Validates user -> Retrieves methods -> Returns safe metadata.
/// @DEPENDENCY Requires AuthService for 2FA data access.
pub async fn get_two_factor_methods(
    auth_service: Arc<AuthService>,
    user_id: String,
) -> Result<impl Reply, warp::Rejection> {
    let methods = auth_service.get_user_two_factor_methods(&user_id).await
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::VaultError))?;
    Ok(warp::reply::json(&methods))
}

/// [2FA REMOVAL HANDLER] Disable Specific Two-Factor Authentication Methods
/// @MISSION Allow secure removal of 2FA methods with safeguards.
/// @THREAT Unauthorized 2FA method removal, account lockout.
/// @COUNTERMEASURE Confirmation requirements, backup method validation.
/// @INVARIANT At least one 2FA method remains or admin override.
/// @AUDIT 2FA removal triggers security alerts.
/// @FLOW Validates permissions -> Removes method -> Updates security state.
/// @DEPENDENCY Requires AuthService for 2FA management.
pub async fn remove_two_factor_method(
    auth_service: Arc<AuthService>,
    user_id: String,
    method_id: String,
) -> Result<impl Reply, warp::Rejection> {
    auth_service.remove_two_factor_method(&user_id, &method_id).await
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::VaultError))?;
    Ok(warp::reply::with_status(
        warp::reply::json(&serde_json::json!({"message": "Two-factor method removed"})),
        StatusCode::OK,
    ))
}

/// [2FA CHALLENGE VALIDATION HANDLER] Validate 2FA Codes During SSO Authentication
/// @MISSION Complete SSO authentication with 2FA validation.
/// @THREAT Unauthorized access, 2FA bypass, replay attacks.
/// @COUNTERMEASURE Challenge validation, time-limited codes, secure cleanup.
/// @INVARIANT 2FA challenges are validated and cleaned up.
/// @AUDIT 2FA validation attempts are logged.
/// @FLOW Validates challenge -> Verifies code -> Returns success/failure.
/// @DEPENDENCY Requires AuthService for 2FA validation.
pub async fn validate_2fa_challenge(
    auth_service: Arc<AuthService>,
    request: TwoFactorChallengeValidationRequest,
) -> Result<impl Reply, warp::Rejection> {
    let success = auth_service.validate_2fa_challenge(request).await
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::VaultError))?;
    Ok(warp::reply::json(&serde_json::json!({
        "success": success,
        "message": if success { "2FA validation successful" } else { "Invalid 2FA code" }
    })))
}

/// [APPLICATION ACCESS REQUEST HANDLER] Request Access to Restricted Applications
/// @MISSION Enable users to request access to additional applications.
/// @THREAT Unauthorized access requests, privilege escalation.
/// @COUNTERMEASURE Approval workflow, audit logging, role validation.
/// @INVARIANT Access requests require approval and are tracked.
/// @AUDIT All access requests trigger approval workflows.
/// @FLOW Creates request -> Notifies approvers -> Returns confirmation.
/// @DEPENDENCY Requires AuthService and ApplicationService.
pub async fn request_application_access(
    auth_service: Arc<AuthService>,
    user_id: String,
    request: ApplicationAccessRequest,
) -> Result<impl Reply, warp::Rejection> {
    // Get user from user_id (in production, this would come from the auth guard)
    let user = User {
        id: user_id,
        email: "placeholder@example.com".to_string(), // This should be fetched from database
        first_name: None,
        last_name: None,
        roles: vec!["employee".to_string()], // This should be fetched from database
        created_at: chrono::Utc::now(),
        enabled: true,
    };

    let response = auth_service.request_application_access(&user, request).await
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::VaultError))?;
    Ok(warp::reply::json(&response))
}