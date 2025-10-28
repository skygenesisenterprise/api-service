use warp::Filter;
use std::sync::Arc;
use crate::controllers::auth_controller;
use crate::services::auth_service::{AuthService, LoginRequest};
use crate::models::user::User;
use crate::middlewares::auth_guard::auth_guard;
use crate::services::session_service::SessionService;
use crate::services::application_service::ApplicationAccessRequest;
use crate::services::two_factor_service::{TwoFactorSetupRequest, TwoFactorVerificationRequest};

pub fn auth_routes(
    auth_service: Arc<AuthService>,
    session_service: Arc<SessionService>,
    application_service: Arc<ApplicationService>,
    two_factor_service: Arc<TwoFactorService>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let login = warp::path!("auth" / "login")
        .and(warp::post())
        .and(warp::header::<String>("x-app-token"))
        .and(warp::header::optional::<String>("user-agent"))
        .and(warp::header::optional::<String>("x-forwarded-for"))
        .and(warp::body::json())
        .and(warp::any().map(move || auth_service.clone()))
        .and_then(|app_token, user_agent, ip_address, req, as_| async move {
            auth_controller::login(as_, req, app_token, user_agent, ip_address).await
        });

    let session_login = warp::path!("auth" / "session" / "login")
        .and(warp::post())
        .and(warp::header::<String>("x-app-token"))
        .and(warp::header::<String>("x-session-token"))
        .and(warp::any().map(move || auth_service.clone()))
        .and_then(|app_token, session_token, as_| async move {
            auth_controller::login_with_session(as_, session_token, app_token).await
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

    let logout = warp::path!("auth" / "logout")
        .and(warp::post())
        .and(warp::cookie::optional(session_service.get_cookie_name()))
        .and(auth_guard())
        .and(warp::any().map(move || auth_service.clone()))
        .and_then(|session_id, claims, as_| async move {
            auth_controller::logout(as_, session_id).await
        });

    let logout_all = warp::path!("auth" / "logout" / "all")
        .and(warp::post())
        .and(auth_guard())
        .and(warp::any().map(move || auth_service.clone()))
        .and_then(|claims, as_| async move {
            auth_controller::logout_all(as_, claims.sub).await
        });

    let sessions = warp::path!("auth" / "sessions")
        .and(warp::get())
        .and(auth_guard())
        .and(warp::any().map(move || auth_service.clone()))
        .and_then(|claims, as_| async move {
            auth_controller::get_user_sessions(as_, claims.sub).await
        });

    let applications = warp::path!("auth" / "applications")
        .and(warp::get())
        .and(auth_guard())
        .and(warp::any().map(move || auth_service.clone()))
        .and_then(|claims, as_| async move {
            auth_controller::get_user_applications(as_, claims.sub).await
        });

    let application_access = warp::path!("auth" / "applications" / "access")
        .and(warp::post())
        .and(auth_guard())
        .and(warp::body::json::<ApplicationAccessRequest>())
        .and(warp::any().map(move || auth_service.clone()))
        .and_then(|claims, request, as_| async move {
            auth_controller::request_application_access(as_, claims.sub, request).await
        });

    // Two-Factor Authentication routes
    let two_factor_setup = warp::path!("auth" / "2fa" / "setup")
        .and(warp::post())
        .and(auth_guard())
        .and(warp::body::json::<TwoFactorSetupRequest>())
        .and(warp::any().map(move || auth_service.clone()))
        .and_then(|claims, request, as_| async move {
            auth_controller::setup_two_factor(as_, claims.sub, request).await
        });

    let two_factor_verify = warp::path!("auth" / "2fa" / "verify")
        .and(warp::post())
        .and(auth_guard())
        .and(warp::body::json::<TwoFactorVerificationRequest>())
        .and(warp::any().map(move || auth_service.clone()))
        .and_then(|claims, request, as_| async move {
            auth_controller::verify_two_factor(as_, claims.sub, request).await
        });

    let two_factor_methods = warp::path!("auth" / "2fa" / "methods")
        .and(warp::get())
        .and(auth_guard())
        .and(warp::any().map(move || auth_service.clone()))
        .and_then(|claims, as_| async move {
            auth_controller::get_two_factor_methods(as_, claims.sub).await
        });

    let two_factor_remove = warp::path!("auth" / "2fa" / "methods" / String)
        .and(warp::delete())
        .and(auth_guard())
        .and(warp::any().map(move || auth_service.clone()))
        .and_then(|method_id, claims, as_| async move {
            auth_controller::remove_two_factor_method(as_, claims.sub, method_id).await
        });

    login.or(session_login).or(register).or(recover).or(me).or(logout).or(logout_all).or(sessions).or(applications).or(application_access).or(two_factor_setup).or(two_factor_verify).or(two_factor_methods).or(two_factor_remove)
}