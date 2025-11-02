use warp::Filter;
use std::sync::Arc;
use crate::controllers::auth_controller;
use urlencoding;
use crate::services::auth_service::{AuthService, LoginRequest};
use crate::models::user::User;
use crate::middlewares::auth_guard::auth_guard;
use crate::services::session_service::SessionService;
use crate::services::application_service::ApplicationAccessRequest;
use crate::services::two_factor_service::{TwoFactorSetupRequest, TwoFactorVerificationRequest, TwoFactorChallengeValidationRequest};
use crate::core::keycloak::KeycloakClient;
use crate::core::fido2::{Fido2Manager, Fido2RegistrationRequest, Fido2AuthenticationRequest};
use crate::core::opentelemetry::Metrics;

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
        .and(auth_guard)
        .and(warp::any().map(move || as_.clone()))
        .and_then(|method_id: String, claims: crate::middlewares::auth::Claims, as_: Arc<AuthService>| async move {
            auth_controller::remove_two_factor_method(as_, claims.sub, method_id).await
        });

    let validate_2fa_challenge = warp::path!("auth" / "2fa" / "validate-challenge")
        .and(warp::post())
        .and(warp::body::json::<TwoFactorChallengeValidationRequest>())
        .and(warp::any().map(move || as_.clone()))
        .and_then(|request: TwoFactorChallengeValidationRequest, as_: Arc<AuthService>| async move {
            auth_controller::validate_2fa_challenge(as_, request).await
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
        .and(warp::any().map(move || kc_.clone()))
        .and(warp::any().map(move || tfs_.clone()))
        .and(warp::any().map(move || apps_.clone()))
        .and_then(|form: std::collections::HashMap<String, String>, kc: Arc<KeycloakClient>, tfs: Arc<TwoFactorService>, apps: Arc<crate::services::application_service::ApplicationService>| async move {
            let username = form.get("username").ok_or("No username")?;
            let password = form.get("password").ok_or("No password")?;
            let state = form.get("state").unwrap_or(&"".to_string()).clone();
            let client_id = form.get("client_id").unwrap_or(&kc.client_id).clone();

            // Authenticate with Keycloak
            match kc.login(username, password).await {
                Ok(tokens) => {
                    // Get user info to check 2FA requirement
                    match kc.get_user_info(&tokens.access_token).await {
                        Ok(user_info) => {
                            let user_id = user_info["sub"].as_str().unwrap_or("");

                            // Check if 2FA is required for this application
                            let requires_2fa = apps.is_two_factor_required_for_application(&client_id).await.unwrap_or(false);

                            if requires_2fa {
                                // Check if user has 2FA enabled
                                let has_2fa = tfs.user_has_two_factor_enabled(user_id).await.unwrap_or(false);

                                if has_2fa {
                                    // Create 2FA challenge
                                    match tfs.create_2fa_challenge(user_id).await {
                                        Ok(challenge) => {
                                            // Return 2FA challenge instead of redirecting
                                            Ok(warp::reply::json(&serde_json::json!({
                                                "requires_2fa": true,
                                                "challenge": challenge,
                                                "state": state,
                                                "client_id": client_id,
                                                "temp_token": tokens.access_token // Temporary token for completing auth
                                            })))
                                        },
                                        Err(_) => {
                                            // Fallback: redirect without 2FA
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
                                        }
                                    }
                                } else {
                                    // 2FA required but not configured - redirect with error
                                    let error_url = format!("/sso/login?error=2fa_required&state={}&client_id={}", state, client_id);
                                    Ok(warp::reply::with_status(
                                        warp::reply::with_header(
                                            warp::reply::html("2FA required but not configured, redirecting..."),
                                            "Location",
                                            error_url
                                        ),
                                        warp::http::StatusCode::FOUND
                                    ))
                                }
                            } else {
                                // No 2FA required - proceed with normal redirect
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
                            }
                        },
                        Err(_) => {
                            // Fallback on user info error
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
                        }
                    }
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

    // API SSO endpoint - serves login page for frontend
    let api_sso = warp::path!("sso")
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
                        .replace("${url.loginAction}", "/api/v1/sso/auth")
                        .replace("${realm.name}", "Sky Genesis Enterprise SSO")
                        .replace("${url.resourcesPath}", "/api/v1/sso/resources")
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
    let api_sso_auth = warp::path!("sso" / "auth")
        .and(warp::post())
        .and(warp::body::form::<std::collections::HashMap<String, String>>())
        .and(warp::any().map(move || kc_.clone()))
        .and(warp::any().map(move || tfs_.clone()))
        .and(warp::any().map(move || apps_.clone()))
        .and_then(|form: std::collections::HashMap<String, String>, kc: Arc<KeycloakClient>, tfs: Arc<TwoFactorService>, apps: Arc<crate::services::application_service::ApplicationService>| async move {
            let username = form.get("username").ok_or("No username")?;
            let password = form.get("password").ok_or("No password")?;
            let state = form.get("state").unwrap_or(&"".to_string()).clone();
            let client_id = form.get("client_id").unwrap_or(&kc.client_id).clone();

            // Authenticate with Keycloak
            match kc.login(username, password).await {
                Ok(tokens) => {
                    // Get user info to check 2FA requirement
                    match kc.get_user_info(&tokens.access_token).await {
                        Ok(user_info) => {
                            let user_id = user_info["sub"].as_str().unwrap_or("");

                            // Check if 2FA is required for this application
                            let requires_2fa = apps.is_two_factor_required_for_application(&client_id).await.unwrap_or(false);

                            if requires_2fa {
                                // Check if user has 2FA enabled
                                let has_2fa = tfs.user_has_two_factor_enabled(user_id).await.unwrap_or(false);

                                if has_2fa {
                                    // Create 2FA challenge
                                    match tfs.create_2fa_challenge(user_id).await {
                                        Ok(challenge) => {
                                            // Return 2FA challenge instead of redirecting
                                            Ok(warp::reply::json(&serde_json::json!({
                                                "requires_2fa": true,
                                                "challenge": challenge,
                                                "state": state,
                                                "client_id": client_id,
                                                "temp_token": tokens.access_token // Temporary token for completing auth
                                            })))
                                        },
                                        Err(_) => {
                                            // Fallback: redirect without 2FA
                                            let redirect_uri = form.get("redirect_uri").unwrap_or(&"http://localhost:8080/api/v1/sso/callback".to_string());
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
                                        }
                                    }
                                } else {
                                    // 2FA required but not configured - redirect with error
                                    let error_url = format!("/api/v1/sso?error=2fa_required&state={}&client_id={}", state, client_id);
                                    Ok(warp::reply::with_status(
                                        warp::reply::with_header(
                                            warp::reply::html("2FA required but not configured, redirecting..."),
                                            "Location",
                                            error_url
                                        ),
                                        warp::http::StatusCode::FOUND
                                    ))
                                }
                            } else {
                                // No 2FA required - proceed with normal redirect
                                let redirect_uri = form.get("redirect_uri").unwrap_or(&"http://localhost:8080/api/v1/sso/callback".to_string());
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
                            }
                        },
                        Err(_) => {
                            // Fallback on user info error
                            let redirect_uri = form.get("redirect_uri").unwrap_or(&"http://localhost:8080/api/v1/sso/callback".to_string());
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
                        }
                    }
                },
                Err(e) => {
                    // Redirect back to login with error
                    let error_url = format!("/api/v1/sso?error={}&state={}&client_id={}", urlencoding::encode(&e.to_string()), state, client_id);
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
    let api_sso_resources = warp::path!("sso" / "resources" / "css" / "login.css")
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
    let api_sso_callback = warp::path!("sso" / "callback")
        .and(warp::get())
        .and(warp::query::<std::collections::HashMap<String, String>>())
        .and_then(|query: std::collections::HashMap<String, String>| async move {
            let access_token = query.get("access_token").unwrap_or(&"".to_string()).clone();
            let refresh_token = query.get("refresh_token").unwrap_or(&"".to_string()).clone();
            let expires_in = query.get("expires_in").unwrap_or(&"3600".to_string()).clone();
            let state = query.get("state").unwrap_or(&"".to_string()).clone();
            let client_id = query.get("client_id").unwrap_or(&"".to_string()).clone();

            Ok(warp::reply::json(&serde_json::json!({
                "access_token": access_token,
                "refresh_token": refresh_token,
                "expires_in": expires_in,
                "state": state,
                "client_id": client_id,
                "message": "SSO authentication successful"
            })))
        });

    let complete_sso_auth = warp::path!("sso" / "complete")
        .and(warp::post())
        .and(warp::body::json::<serde_json::Value>())
        .and(warp::any().map(move || kc_.clone()))
        .and_then(|body: serde_json::Value, kc: Arc<KeycloakClient>| async move {
            // Extract data from the 2FA completion request
            let challenge_id = body.get("challenge_id").and_then(|v| v.as_str()).ok_or("No challenge_id")?;
            let temp_token = body.get("temp_token").and_then(|v| v.as_str()).ok_or("No temp_token")?;
            let state = body.get("state").and_then(|v| v.as_str()).unwrap_or("");
            let client_id = body.get("client_id").and_then(|v| v.as_str()).unwrap_or(&kc.client_id);

            // Get user info from temp token
            match kc.get_user_info(temp_token).await {
                Ok(user_info) => {
                    let user_id = user_info["sub"].as_str().unwrap_or("");

                    // Get tokens again (or refresh) - for now, assume temp_token is still valid
                    // In production, you might want to refresh or store the original tokens

                    Ok(warp::reply::json(&serde_json::json!({
                        "access_token": temp_token,
                        "refresh_token": "", // Would need to be retrieved/stored
                        "expires_in": 3600,
                        "state": state,
                        "client_id": client_id,
                        "user_id": user_id,
                        "message": "SSO authentication with 2FA completed"
                    })))
                },
                Err(e) => {
                    Ok(warp::reply::json(&serde_json::json!({
                        "error": "Failed to complete authentication",
                        "details": e.to_string()
                    })))
                }
            }
        });

    // ============================================================================
    //  CENTRALIZED OAUTH2 AUTHENTICATION ENDPOINTS (/api/v1/auth/*)
    // ============================================================================

    // POST /api/v1/auth/login - Initiate OAuth2 Authorization Code flow
    let api_v1_auth_login = warp::path!("api" / "v1" / "auth" / "login")
        .and(warp::post())
        .and(warp::body::json::<serde_json::Value>())
        .and(warp::any().map(move || keycloak_client.clone()))
        .and_then(|body: serde_json::Value, kc: Arc<KeycloakClient>| async move {
            // Log OAuth2 login initiation
            let _span = crate::core::opentelemetry::trace_request("oauth2_login_initiate");

            let redirect_uri = body.get("redirect_uri")
                .and_then(|v| v.as_str())
                .unwrap_or("http://localhost:8080/api/v1/auth/callback");
            let state = body.get("state")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let client_id = body.get("client_id")
                .and_then(|v| v.as_str())
                .unwrap_or(&kc.client_id);

            match kc.get_authorization_url(redirect_uri, state).await {
                Ok(auth_url) => {
                    // Log successful authorization URL generation
                    crate::core::opentelemetry::log_event("oauth2_login_url_generated", &serde_json::json!({
                        "client_id": client_id,
                        "has_state": !state.is_empty()
                    }));
                    Ok(warp::reply::json(&serde_json::json!({
                        "authorization_url": auth_url,
                        "state": state,
                        "client_id": client_id
                    })))
                },
                Err(e) => {
                    // Log authorization URL generation failure
                    crate::core::opentelemetry::log_error("oauth2_login_url_failed", &e.to_string());
                    Ok(warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({"error": e.to_string()})),
                        warp::http::StatusCode::INTERNAL_SERVER_ERROR
                    ))
                },
            }
        });

    // GET /api/v1/auth/callback - OAuth2 Authorization Code callback
    let api_v1_auth_callback = warp::path!("api" / "v1" / "auth" / "callback")
        .and(warp::get())
        .and(warp::query::<std::collections::HashMap<String, String>>())
        .and(warp::any().map(move || keycloak_client.clone()))
        .and_then(|query: std::collections::HashMap<String, String>, kc: Arc<KeycloakClient>| async move {
            let code = query.get("code").ok_or("No authorization code")?;
            let state = query.get("state").unwrap_or(&"".to_string()).clone();
            let redirect_uri = "http://localhost:8080/api/v1/auth/callback";

            match kc.exchange_code_for_token(code, redirect_uri).await {
                Ok(token_response) => Ok(warp::reply::json(&serde_json::json!({
                    "access_token": token_response.access_token,
                    "refresh_token": token_response.refresh_token,
                    "expires_in": token_response.expires_in,
                    "token_type": "Bearer",
                    "state": state
                }))),
                Err(e) => Ok(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"error": e.to_string()})),
                    warp::http::StatusCode::INTERNAL_SERVER_ERROR
                )),
            }
        });

    // POST /api/v1/auth/refresh - Refresh OAuth2 access token
    let api_v1_auth_refresh = warp::path!("api" / "v1" / "auth" / "refresh")
        .and(warp::post())
        .and(warp::body::json::<serde_json::Value>())
        .and(warp::any().map(move || keycloak_client.clone()))
        .and_then(|body: serde_json::Value, kc: Arc<KeycloakClient>| async move {
            let refresh_token = body.get("refresh_token")
                .and_then(|v| v.as_str())
                .ok_or("No refresh_token provided")?;

            // Use Keycloak's token refresh endpoint
            let url = format!("{}/realms/{}/protocol/openid-connect/token",
                kc.base_url, kc.realm);

            let params = [
                ("grant_type", "refresh_token"),
                ("client_id", &kc.client_id),
                ("client_secret", &kc.client_secret),
                ("refresh_token", refresh_token),
            ];

            let client = reqwest::Client::new();
            match client.post(&url).form(&params).send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        match response.json::<serde_json::Value>().await {
                            Ok(token_data) => Ok(warp::reply::json(&serde_json::json!({
                                "access_token": token_data["access_token"],
                                "refresh_token": token_data["refresh_token"],
                                "expires_in": token_data["expires_in"],
                                "token_type": "Bearer"
                            }))),
                            Err(e) => Ok(warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({"error": format!("Failed to parse token response: {}", e)})),
                                warp::http::StatusCode::INTERNAL_SERVER_ERROR
                            )),
                        }
                    } else {
                        Ok(warp::reply::with_status(
                            warp::reply::json(&serde_json::json!({"error": "Token refresh failed"})),
                            warp::http::StatusCode::UNAUTHORIZED
                        ))
                    }
                },
                Err(e) => Ok(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"error": format!("Request failed: {}", e)})),
                    warp::http::StatusCode::INTERNAL_SERVER_ERROR
                )),
            }
        });

    // GET /api/v1/auth/userinfo - Get authenticated user information
    let api_v1_auth_userinfo = warp::path!("api" / "v1" / "auth" / "userinfo")
        .and(warp::get())
        .and(warp::header::<String>("authorization"))
        .and(warp::any().map(move || keycloak_client.clone()))
        .and_then(|auth_header: String, kc: Arc<KeycloakClient>| async move {
            if !auth_header.starts_with("Bearer ") {
                return Ok(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"error": "Invalid authorization header"})),
                    warp::http::StatusCode::UNAUTHORIZED
                ));
            }

            let access_token = auth_header.trim_start_matches("Bearer ");

            match kc.get_user_info(access_token).await {
                Ok(user_info) => Ok(warp::reply::json(&user_info)),
                Err(e) => Ok(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"error": format!("Failed to get user info: {}", e)})),
                    warp::http::StatusCode::UNAUTHORIZED
                )),
            }
        });

    // POST /api/v1/auth/logout - Logout and invalidate tokens
    let api_v1_auth_logout = warp::path!("api" / "v1" / "auth" / "logout")
        .and(warp::post())
        .and(warp::body::json::<serde_json::Value>())
        .and(warp::any().map(move || keycloak_client.clone()))
        .and_then(|body: serde_json::Value, kc: Arc<KeycloakClient>| async move {
            let refresh_token = body.get("refresh_token")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            // Call Keycloak logout endpoint
            let url = format!("{}/realms/{}/protocol/openid-connect/logout",
                kc.base_url, kc.realm);

            let params = [
                ("client_id", &kc.client_id),
                ("client_secret", &kc.client_secret),
                ("refresh_token", refresh_token),
            ];

            let client = reqwest::Client::new();
            match client.post(&url).form(&params).send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        Ok(warp::reply::json(&serde_json::json!({
                            "message": "Successfully logged out"
                        })))
                    } else {
                        // Even if Keycloak logout fails, we consider it successful from client perspective
                        Ok(warp::reply::json(&serde_json::json!({
                            "message": "Logged out (local session cleared)"
                        })))
                    }
                },
                Err(_) => Ok(warp::reply::json(&serde_json::json!({
                    "message": "Logged out (local session cleared)"
                }))),
            }
        });

    // POST /api/v1/auth/client-credentials - Client Credentials flow for services
    let api_v1_auth_client_credentials = warp::path!("api" / "v1" / "auth" / "client-credentials")
        .and(warp::post())
        .and(warp::body::json::<serde_json::Value>())
        .and(warp::any().map(move || keycloak_client.clone()))
        .and_then(|body: serde_json::Value, kc: Arc<KeycloakClient>| async move {
            let scope = body.get("scope")
                .and_then(|v| v.as_str());

            match kc.client_credentials_token(scope).await {
                Ok(token_response) => Ok(warp::reply::json(&serde_json::json!({
                    "access_token": token_response.access_token,
                    "expires_in": token_response.expires_in,
                    "token_type": "Bearer",
                    "scope": scope.unwrap_or("")
                }))),
                Err(e) => Ok(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"error": e.to_string()})),
                    warp::http::StatusCode::INTERNAL_SERVER_ERROR
                )),
            }
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

    login.or(session_login).or(register).or(recover).or(me).or(logout).or(logout_all).or(sessions).or(applications).or(application_access).or(two_factor_setup).or(two_factor_verify).or(two_factor_methods).or(two_factor_remove).or(validate_2fa_challenge).or(complete_sso_auth).or(login_page).or(login_html).or(login_css).or(oidc_login).or(oidc_callback).or(api_sso).or(api_sso_auth).or(api_sso_resources).or(api_sso_callback).or(sso_login).or(sso_auth).or(sso_resources).or(sso_callback).or(fido2_register_start).or(fido2_register_finish).or(fido2_auth_start).or(fido2_auth_finish).or(api_v1_auth_login).or(api_v1_auth_callback).or(api_v1_auth_refresh).or(api_v1_auth_userinfo).or(api_v1_auth_logout).or(api_v1_auth_client_credentials)
}