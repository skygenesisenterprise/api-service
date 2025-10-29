// Routes Rust module

pub mod key_routes;
pub mod auth_routes;
pub mod websocket_routes;
pub mod security_routes;

use warp::Filter;
use std::sync::Arc;
use crate::services::vault_manager::VaultManager;
use crate::services::key_service::KeyService;
use crate::services::auth_service::AuthService;
use crate::services::session_service::SessionService;
use crate::services::application_service::ApplicationService;
use crate::services::two_factor_service::TwoFactorService;
use crate::websocket::WebSocketServer;

pub fn routes(
    vault_manager: Arc<VaultManager>,
    key_service: Arc<KeyService>,
    auth_service: Arc<AuthService>,
    session_service: Arc<SessionService>,
    application_service: Arc<ApplicationService>,
    two_factor_service: Arc<TwoFactorService>,
    ws_server: Arc<WebSocketServer>
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let hello = warp::path!("hello")
        .map(|| "Hello, World!");

    let key_routes = crate::routes::key_routes::key_routes(key_service);
    let auth_routes = crate::routes::auth_routes::auth_routes(auth_service, session_service, application_service, two_factor_service);
    let websocket_routes = crate::routes::websocket_routes::websocket_routes(ws_server);
    let security_routes = crate::routes::security_routes::security_routes();

    // OpenAPI JSON endpoint
    let openapi_json = warp::path!("api-docs" / "openapi.json")
        .map(|| warp::reply::json(&crate::openapi::ApiDoc::openapi()));

    // Swagger UI HTML page
    let swagger_ui = warp::path!("swagger-ui" / ..)
        .map(|| {
            warp::reply::html(r#"
<!DOCTYPE html>
<html>
<head>
    <title>Sky Genesis Enterprise API Documentation</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5.10.3/swagger-ui.css" />
    <style>
        html { box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }
        *, *:before, *:after { box-sizing: inherit; }
        body { margin:0; background: #fafafa; }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5.10.3/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@5.10.3/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {
            const ui = SwaggerUIBundle({
                url: '/api-docs/openapi.json',
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout"
            });
        };
    </script>
</body>
</html>
            "#)
        });

    hello.or(key_routes).or(auth_routes).or(websocket_routes).or(security_routes).or(openapi_json).or(swagger_ui)
}