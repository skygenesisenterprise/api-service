use warp::Reply;
use crate::services::auth_service::{AuthService, LoginRequest};
use crate::models::user::User;
use crate::services::application_service::ApplicationAccessRequest;
use crate::services::two_factor_service::{TwoFactorSetupRequest, TwoFactorVerificationRequest};
use std::sync::Arc;
use warp::http::StatusCode;

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
    if let Some(session_token) = response.session_token.clone() {
        let cookie = format!(
            "sky_genesis_session={}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800",
            session_token
        );
        Ok(warp::reply::with_header(
            warp::reply::json(&response),
            "Set-Cookie",
            cookie,
        ))
    } else {
        Ok(warp::reply::json(&response))
    }
}

pub async fn login_with_session(
    auth_service: Arc<AuthService>,
    session_token: String,
    app_token: String,
) -> Result<impl Reply, warp::Rejection> {
    let response = auth_service.login_with_session(&session_token, &app_token).await
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::InvalidToken))?;
    Ok(warp::reply::json(&response))
}

pub async fn register(
    auth_service: Arc<AuthService>,
    user: User,
    password: String,
) -> Result<impl Reply, warp::Rejection> {
    auth_service.register(user, &password).await
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::VaultError))?;
    Ok(warp::reply::json(&serde_json::json!({"message": "User registered"})))
}

pub async fn recover_password(
    auth_service: Arc<AuthService>,
    email: String,
) -> Result<impl Reply, warp::Rejection> {
    auth_service.recover_password(&email).await
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::VaultError))?;
    Ok(warp::reply::json(&serde_json::json!({"message": "Recovery email sent"})))
}

pub async fn get_me(
    auth_service: Arc<AuthService>,
    token: String,
) -> Result<impl Reply, warp::Rejection> {
    let user = auth_service.get_me(&token).await
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::InvalidToken))?;
    Ok(warp::reply::json(&user))
}

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

pub async fn get_user_sessions(
    auth_service: Arc<AuthService>,
    user_id: String,
) -> Result<impl Reply, warp::Rejection> {
    let sessions = auth_service.get_user_sessions(&user_id).await
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::VaultError))?;
    Ok(warp::reply::json(&sessions))
}

pub async fn get_user_applications(
    auth_service: Arc<AuthService>,
    user_id: String,
) -> Result<impl Reply, warp::Rejection> {
    let applications = auth_service.get_user_applications_by_user_id(&user_id).await
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::VaultError))?;
    Ok(warp::reply::json(&applications))
}

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

pub async fn get_two_factor_methods(
    auth_service: Arc<AuthService>,
    user_id: String,
) -> Result<impl Reply, warp::Rejection> {
    let methods = auth_service.get_user_two_factor_methods(&user_id).await
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::VaultError))?;
    Ok(warp::reply::json(&methods))
}

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