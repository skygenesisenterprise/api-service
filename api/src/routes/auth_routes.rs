use warp::Filter;
use std::sync::Arc;
use crate::controllers::auth_controller;
use urlencoding;
use crate::services::auth_service::{AuthService, LoginRequest};
use crate::models::user::User;
use crate::middlewares::auth_guard::auth_guard;
use crate::services::session_service::SessionService;
use crate::services::application_service::ApplicationAccessRequest;
use crate::services::two_factor_service::{TwoFactorSetupRequest, TwoFactorVerificationRequest};
use crate::core::keycloak::KeycloakClient;
use crate::core::fido2::{Fido2Manager, Fido2RegistrationRequest, Fido2AuthenticationRequest};

pub fn auth_routes(
    auth_service: Arc<AuthService>,
    session_service: Arc<SessionService>,
    application_service: Arc<ApplicationService>,
    two_factor_service: Arc<TwoFactorService>,
    keycloak_client: Arc<KeycloakClient>,
    fido2_manager: Arc<Fido2Manager>,
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

    // Login page redirect to Keycloak
    let login_page = warp::path!("auth" / "login" / "page")
        .and(warp::get())
        .and(warp::query::<std::collections::HashMap<String, String>>())
        .and(warp::any().map(move || keycloak_client.clone()))
        .and_then(|query: std::collections::HashMap<String, String>, kc: Arc<KeycloakClient>| async move {
            let redirect_uri = query.get("redirect_uri").unwrap_or(&"http://localhost:8080/auth/oidc/callback".to_string()).clone();
            let state = query.get("state").unwrap_or(&"".to_string()).clone();
            match kc.get_authorization_url(&redirect_uri, &state).await {
                Ok(url) => Ok(warp::reply::with_status(
                    warp::reply::with_header(
                        warp::reply::html("Redirecting to login..."),
                        "Location",
                        url
                    ),
                    warp::http::StatusCode::FOUND
                )),
                Err(e) => Ok(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"error": e.to_string()})),
                    warp::http::StatusCode::INTERNAL_SERVER_ERROR
                )),
            }
        });

    // SSO Login page - serves Keycloak login under API domain
    let sso_login = warp::path!("sso" / "login")
        .and(warp::get())
        .and(warp::query::<std::collections::HashMap<String, String>>())
        .and(warp::any().map(move || keycloak_client.clone()))
        .and_then(|query: std::collections::HashMap<String, String>, kc: Arc<KeycloakClient>| async move {
            let redirect_uri = query.get("redirect_uri").unwrap_or(&"http://localhost:8080/sso/callback".to_string()).clone();
            let state = query.get("state").unwrap_or(&"".to_string()).clone();
            let client_id = query.get("client_id").unwrap_or(&kc.client_id.clone()).clone();

            // Read the login.ftl content and serve as HTML with API endpoints
            match std::fs::read_to_string("keycloak-theme/login/login.ftl") {
                Ok(content) => {
                    // Replace Keycloak variables with API endpoints
                    let html = content
                        .replace("${url.loginAction}", "/sso/auth")
                        .replace("${realm.name}", "Sky Genesis Enterprise SSO")
                        .replace("${url.resourcesPath}", "/sso/resources")
                        .replace("http://localhost:8080/auth/oidc/callback", &redirect_uri)
                        .replace("http://localhost:3000/callback", &redirect_uri);

                    // Add hidden fields for state management
                    let state_field = if !state.is_empty() {
                        format!("<input type=\"hidden\" name=\"state\" value=\"{}\">", state)
                    } else {
                        "".to_string()
                    };

                    let client_field = format!("<input type=\"hidden\" name=\"client_id\" value=\"{}\">", client_id);

                    // Insert hidden fields before the submit button
                    let html = html.replace(
                        "<button",
                        &format!("{}\n{}", state_field, client_field)
                    );

                    Ok(warp::reply::with_header(
                        warp::reply::html(html),
                        "Content-Type",
                        "text/html"
                    ))
                },
                Err(_) => Ok(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"error": "SSO login template not found"})),
                    warp::http::StatusCode::INTERNAL_SERVER_ERROR
                )),
            }
        });

    // SSO Authentication endpoint - proxies to Keycloak
    let sso_auth = warp::path!("sso" / "auth")
        .and(warp::post())
        .and(warp::body::form::<std::collections::HashMap<String, String>>())
        .and(warp::any().map(move || keycloak_client.clone()))
        .and_then(|form: std::collections::HashMap<String, String>, kc: Arc<KeycloakClient>| async move {
            let username = form.get("username").ok_or("No username")?;
            let password = form.get("password").ok_or("No password")?;
            let state = form.get("state").unwrap_or(&"".to_string()).clone();
            let client_id = form.get("client_id").unwrap_or(&kc.client_id).clone();

            // Authenticate with Keycloak
            match kc.login(username, password).await {
                Ok(tokens) => {
                    // Create redirect URL with tokens
                    let redirect_uri = form.get("redirect_uri").unwrap_or(&"http://localhost:8080/sso/callback".to_string());
                    let redirect_url = format!(
                        "{}?access_token={}&refresh_token={}&expires_in={}&state={}&client_id={}",
                        redirect_uri, tokens.access_token, tokens.refresh_token, tokens.expires_in, state, client_id
                    );

                    Ok(warp::reply::with_status(
                        warp::reply::with_header(
                            warp::reply::html("Authentication successful, redirecting..."),
                            "Location",
                            redirect_url
                        ),
                        warp::http::StatusCode::FOUND
                    ))
                },
                Err(e) => {
                    // Redirect back to login with error
                    let error_url = format!("/sso/login?error={}&state={}&client_id={}", urlencoding::encode(&e.to_string()), state, client_id);
                    Ok(warp::reply::with_status(
                        warp::reply::with_header(
                            warp::reply::html("Authentication failed, redirecting..."),
                            "Location",
                            error_url
                        ),
                        warp::http::StatusCode::FOUND
                    ))
                }
            }
        });

    // SSO Resources endpoint
    let sso_resources = warp::path!("sso" / "resources" / "css" / "login.css")
        .and(warp::get())
        .and_then(|| async {
            match std::fs::read_to_string("keycloak-theme/login/resources/css/login.css") {
                Ok(content) => Ok(warp::reply::with_header(
                    content,
                    "Content-Type",
                    "text/css"
                )),
                Err(_) => Ok(warp::reply::with_status(
                    "CSS not found",
                    warp::http::StatusCode::NOT_FOUND
                )),
            }
        });

    // SSO Callback endpoint for applications
    let sso_callback = warp::path!("sso" / "callback")
        .and(warp::get())
        .and(warp::query::<std::collections::HashMap<String, String>>())
        .and_then(|query: std::collections::HashMap<String, String>| async move {
            // This endpoint receives tokens from the SSO auth flow
            // Applications can implement their own logic here
            let access_token = query.get("access_token");
            let refresh_token = query.get("refresh_token");
            let expires_in = query.get("expires_in");
            let state = query.get("state");
            let client_id = query.get("client_id");

            // Return the tokens to the application
            Ok(warp::reply::json(&serde_json::json!({
                "access_token": access_token,
                "refresh_token": refresh_token,
                "expires_in": expires_in,
                "state": state,
                "client_id": client_id,
                "message": "SSO authentication successful"
            })))
        });

    // Serve CSS resources
    let login_css = warp::path!("auth" / "login" / "resources" / "css" / "login.css")
        .and(warp::get())
        .and_then(|| async {
            match std::fs::read_to_string("keycloak-theme/login/resources/css/login.css") {
                Ok(content) => Ok(warp::reply::with_header(
                    content,
                    "Content-Type",
                    "text/css"
                )),
                Err(_) => Ok(warp::reply::with_status(
                    "CSS not found",
                    warp::http::StatusCode::NOT_FOUND
                )),
            }
        });

    // OIDC routes
    let oidc_login = warp::path!("auth" / "oidc" / "login")
        .and(warp::get())
        .and(warp::query::<std::collections::HashMap<String, String>>())
        .and(warp::any().map(move || keycloak_client.clone()))
        .and_then(|query: std::collections::HashMap<String, String>, kc: Arc<KeycloakClient>| async move {
            let redirect_uri = query.get("redirect_uri").unwrap_or(&"http://localhost:8080/auth/oidc/callback".to_string()).clone();
            let state = query.get("state").unwrap_or(&"".to_string()).clone();
            match kc.get_authorization_url(&redirect_uri, &state).await {
                Ok(url) => Ok(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"authorization_url": url})),
                    warp::http::StatusCode::OK
                )),
                Err(e) => Ok(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"error": e.to_string()})),
                    warp::http::StatusCode::INTERNAL_SERVER_ERROR
                )),
            }
        });

    let oidc_callback = warp::path!("auth" / "oidc" / "callback")
        .and(warp::get())
        .and(warp::query::<std::collections::HashMap<String, String>>())
        .and(warp::any().map(move || keycloak_client.clone()))
        .and_then(|query: std::collections::HashMap<String, String>, kc: Arc<KeycloakClient>| async move {
            let code = query.get("code").ok_or("No code provided")?;
            let state = query.get("state").unwrap_or(&"".to_string()).clone();
            let redirect_uri = "http://localhost:8080/auth/oidc/callback"; // API callback URI

            match kc.exchange_code_for_token(code, redirect_uri).await {
                Ok(token_response) => {
                    // If state contains a redirect URL, redirect there with tokens
                    if !state.is_empty() {
                        let redirect_url = format!("{}?access_token={}&refresh_token={}&expires_in={}",
                            state, token_response.access_token, token_response.refresh_token, token_response.expires_in);
                        Ok(warp::reply::with_status(
                            warp::reply::with_header(
                                warp::reply::html("Authentication successful, redirecting..."),
                                "Location",
                                redirect_url
                            ),
                            warp::http::StatusCode::FOUND
                        ))
                    } else {
                        Ok(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({
                                "access_token": token_response.access_token,
                                "refresh_token": token_response.refresh_token,
                                "expires_in": token_response.expires_in,
                                "state": state
                            })),
                            warp::http::StatusCode::OK
                        ))
                    }
                },
                Err(e) => Ok(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"error": e.to_string()})),
                    warp::http::StatusCode::INTERNAL_SERVER_ERROR
                )),
            }
        });

    // FIDO2 routes
    let fido2_register_start = warp::path!("auth" / "fido2" / "register" / "start")
        .and(warp::post())
        .and(warp::body::json::<Fido2RegistrationRequest>())
        .and(warp::any().map(move || fido2_manager.clone()))
        .and_then(|request, fm| async move {
            match fm.start_registration(request).await {
                Ok(response) => Ok(warp::reply::with_status(
                    warp::reply::json(&response),
                    warp::http::StatusCode::OK
                )),
                Err(e) => Ok(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"error": e.to_string()})),
                    warp::http::StatusCode::INTERNAL_SERVER_ERROR
                )),
            }
        });

    let fido2_register_finish = warp::path!("auth" / "fido2" / "register" / "finish")
        .and(warp::post())
        .and(warp::body::json::<serde_json::Value>())
        .and(warp::any().map(move || fido2_manager.clone()))
        .and_then(|body: serde_json::Value, fm| async move {
            let user_id = body["user_id"].as_str().ok_or("No user_id")?;
            let challenge = body["challenge"].as_str().ok_or("No challenge")?;
            let response = body["response"].as_str().ok_or("No response")?;

            match fm.finish_registration(user_id, challenge, response).await {
                Ok(_) => Ok(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"status": "success"})),
                    warp::http::StatusCode::OK
                )),
                Err(e) => Ok(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"error": e.to_string()})),
                    warp::http::StatusCode::INTERNAL_SERVER_ERROR
                )),
            }
        });

    let fido2_auth_start = warp::path!("auth" / "fido2" / "auth" / "start")
        .and(warp::post())
        .and(warp::body::json::<Fido2AuthenticationRequest>())
        .and(warp::any().map(move || fido2_manager.clone()))
        .and_then(|request, fm| async move {
            match fm.start_authentication(&request.username).await {
                Ok(response) => Ok(warp::reply::with_status(
                    warp::reply::json(&response),
                    warp::http::StatusCode::OK
                )),
                Err(e) => Ok(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"error": e.to_string()})),
                    warp::http::StatusCode::INTERNAL_SERVER_ERROR
                )),
            }
        });

    let fido2_auth_finish = warp::path!("auth" / "fido2" / "auth" / "finish")
        .and(warp::post())
        .and(warp::body::json::<serde_json::Value>())
        .and(warp::any().map(move || fido2_manager.clone()))
        .and_then(|body: serde_json::Value, fm| async move {
            let username = body["username"].as_str().ok_or("No username")?;
            let challenge = body["challenge"].as_str().ok_or("No challenge")?;
            let response = body["response"].as_str().ok_or("No response")?;

            match fm.finish_authentication(username, challenge, response).await {
                Ok(_) => Ok(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"status": "authenticated"})),
                    warp::http::StatusCode::OK
                )),
                Err(e) => Ok(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"error": e.to_string()})),
                    warp::http::StatusCode::INTERNAL_SERVER_ERROR
                )),
            }
        });

    login.or(session_login).or(register).or(recover).or(me).or(logout).or(logout_all).or(sessions).or(applications).or(application_access).or(two_factor_setup).or(two_factor_verify).or(two_factor_methods).or(two_factor_remove).or(login_page).or(login_html).or(login_css).or(oidc_login).or(oidc_callback).or(sso_login).or(sso_auth).or(sso_resources).or(sso_callback).or(fido2_register_start).or(fido2_register_finish).or(fido2_auth_start).or(fido2_auth_finish)
}