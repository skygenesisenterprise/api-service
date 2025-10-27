use warp::Reply;
use crate::services::auth_service::{AuthService, LoginRequest};
use crate::models::user::User;
use std::sync::Arc;

pub async fn login(
    auth_service: Arc<AuthService>,
    req: LoginRequest,
    app_token: String,
) -> Result<impl Reply, warp::Rejection> {
    let response = auth_service.login(req, &app_token).await
        .map_err(|_| warp::reject::custom(crate::middlewares::auth::AuthError::VaultError))?;
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