use warp::Filter;
use std::sync::Arc;
use crate::controllers::auth_controller;
use crate::services::auth_service::{AuthService, LoginRequest};
use crate::models::user::User;
use crate::middlewares::auth_guard::auth_guard;

pub fn auth_routes(auth_service: Arc<AuthService>) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let login = warp::path!("auth" / "login")
        .and(warp::post())
        .and(warp::header::<String>("x-app-token"))
        .and(warp::body::json())
        .and(warp::any().map(move || auth_service.clone()))
        .and_then(|app_token, req, as_| async move {
            auth_controller::login(as_, req, app_token).await
        });

    let register = warp::path!("auth" / "register")
        .and(warp::post())
        .and(warp::body::json::<(User, String)>()) // (user, password)
        .and(warp::any().map(move || auth_service.clone()))
        .and_then(|(user, password), as_| async move {
            auth_controller::register(as_, user, password).await
        });

    let recover = warp::path!("auth" / "recover")
        .and(warp::post())
        .and(warp::body::json::<serde_json::Value>())
        .and(warp::any().map(move || auth_service.clone()))
        .and_then(|body, as_| async move {
            let email = body["email"].as_str().unwrap_or("").to_string();
            auth_controller::recover_password(as_, email).await
        });

    let me = warp::path!("auth" / "me")
        .and(warp::get())
        .and(auth_guard())
        .and(warp::any().map(move || auth_service.clone()))
        .and_then(|claims, as_| async move {
            // Assume token from header
            let token = "".to_string(); // From auth_guard
            auth_controller::get_me(as_, token).await
        });

    login.or(register).or(recover).or(me)
}