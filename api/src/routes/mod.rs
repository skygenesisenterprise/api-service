// Routes Rust module

pub mod key_routes;
pub mod auth_routes;
pub mod websocket_routes;
pub mod security_routes;
pub mod snmp_routes;
pub mod vpn_routes;
pub mod grpc_routes;
pub mod webdav_routes;
pub mod opentelemetry_routes;
pub mod monitoring_routes;
pub mod grafana_routes;
pub mod search_routes;
pub mod ssh_routes;
pub mod data_routes;
pub mod openpgp_routes;
pub mod device_routes;
pub mod mac_routes;
pub mod voip_routes;
pub mod discord_routes;
pub mod git_routes;
pub mod logger_routes;
pub mod poweradmin_routes;
pub mod oauth2_routes;

use warp::Filter;
use std::sync::Arc;
use crate::services::vault_manager::VaultManager;
use crate::services::key_service::KeyService;
use crate::services::auth_service::AuthService;
use crate::services::session_service::SessionService;
use crate::services::application_service::ApplicationService;
use crate::services::two_factor_service::TwoFactorService;
use crate::services::data_service::DataService;
use crate::services::openpgp_service::OpenPGPService;
use crate::services::device_service::DeviceService;
use crate::services::mac_service::MacService;
use crate::websocket::WebSocketServer;
use crate::core::snmp_manager::SnmpManager;
use crate::core::snmp_agent::SnmpAgent;
use crate::core::snmp_trap_listener::SnmpTrapListener;
use crate::core::audit_manager::AuditManager;
use crate::core::vault::VaultClient;
use crate::core::keycloak::KeycloakClient;
use crate::core::fido2::Fido2Manager;
use crate::core::vpn::{VpnManager, TailscaleManager};
use crate::core::grpc::GrpcClient;
use crate::core::webdav::{WebDavHandler, CalDavHandler, CardDavHandler};
use crate::core::opentelemetry::Metrics;
use crate::ssh::SshServer;
use crate::services::poweradmin_service::PowerAdminService;
use crate::services::voip_service::VoipService;
use crate::core::asterisk_client::AsteriskClient;
use crate::services::discord_service::DiscordService;
use tokio::sync::Mutex;
use crate::middlewares::logging;
use crate::middlewares::auth_middleware;

pub fn routes(
    vault_manager: Arc<VaultManager>,
    vault_client: Arc<VaultClient>,
    key_service: Arc<KeyService>,
    auth_service: Arc<AuthService>,
    session_service: Arc<SessionService>,
    application_service: Arc<ApplicationService>,
    two_factor_service: Arc<TwoFactorService>,
    data_service: Arc<DataService>,
    openpgp_service: Arc<OpenPGPService>,
    device_service: Arc<DeviceService>,
    mac_service: Arc<MacService>,
    ws_server: Arc<WebSocketServer>,
    snmp_manager: Arc<SnmpManager>,
    snmp_agent: Arc<SnmpAgent>,
    trap_listener: Arc<SnmpTrapListener>,
    audit_manager: Arc<AuditManager>,
    keycloak_client: Arc<KeycloakClient>,
    fido2_manager: Arc<Fido2Manager>,
    vpn_manager: Arc<VpnManager>,
    tailscale_manager: Arc<TailscaleManager>,
    grpc_client: Arc<Mutex<GrpcClient>>,
    webdav_handler: Arc<WebDavHandler>,
    caldav_handler: Arc<CalDavHandler>,
    carddav_handler: Arc<CardDavHandler>,
    metrics: Arc<Metrics>,
    monitoring_service: Arc<crate::services::monitoring_service::MonitoringService>,
    grafana_service: Arc<crate::services::grafana_service::GrafanaService>,
    poweradmin_service: Arc<PowerAdminService>,
    ssh_server: Arc<SshServer>,
    voip_service: Arc<VoipService>,
    asterisk_client: Arc<AsteriskClient>,
    discord_service: Arc<DiscordService>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let hello = warp::path!("hello")
        .map(|| "Hello, World!");

    let key_routes = crate::routes::key_routes::key_routes(key_service);
    let auth_routes = crate::routes::auth_routes::auth_routes(auth_service, session_service, application_service, two_factor_service, keycloak_client, fido2_manager);
    let data_routes = crate::routes::data_routes::data_routes(data_service);
    let openpgp_routes = crate::routes::openpgp_routes::openpgp_routes(openpgp_service, keycloak_client.clone());
    let device_routes = crate::routes::device_routes::device_routes(device_service, audit_manager.clone());
    let mac_routes = crate::routes::mac_routes::mac_routes(mac_service, audit_manager.clone());
    let websocket_routes = crate::routes::websocket_routes::websocket_routes(ws_server, keycloak_client);
    let security_routes = crate::routes::security_routes::security_routes();
    let snmp_routes = crate::routes::snmp_routes::snmp_routes(snmp_manager, snmp_agent, trap_listener, audit_manager);
    let vpn_routes = crate::routes::vpn_routes::vpn_routes(vpn_manager, tailscale_manager);
    let grpc_routes = crate::routes::grpc_routes::grpc_routes(grpc_client);
    let webdav_routes = crate::routes::webdav_routes::webdav_routes(webdav_handler, caldav_handler, carddav_handler);
    let opentelemetry_routes = crate::routes::opentelemetry_routes::opentelemetry_routes(metrics, monitoring_service.clone());
    let monitoring_routes = crate::routes::monitoring_routes::monitoring_routes(monitoring_service);
    let grafana_routes = crate::routes::grafana_routes::grafana_routes(grafana_service);
    let poweradmin_routes = crate::routes::poweradmin_routes::poweradmin_routes(poweradmin_service, vault_manager.clone());
    let logger_service = Arc::new(crate::services::logger_service::LoggerService::new(audit_manager.clone(), vault_client.clone()));
    let logger_routes = crate::routes::logger_routes::logger_routes(logger_service);
    let search_routes = crate::routes::search_routes::search_routes(auth_service.clone(), vault_client.clone(), metrics.clone());
    let ssh_routes = crate::routes::ssh_routes::ssh_routes(ssh_server, audit_manager.clone());
    let voip_routes = crate::routes::voip_routes::voip_routes(voip_service, asterisk_client);
    let discord_routes = crate::routes::discord_routes::discord_routes(discord_service);
    let git_routes = crate::routes::git_routes::git_routes();
    let oauth2_routes = crate::routes::oauth2_routes::oauth2_routes();

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

    // ============================================================================
    //  OAUTH2-PROTECTED API V1 ROUTES
    // ============================================================================

    // Combine all routes that should be protected under /api/v1/
    let combined_protected_routes = data_routes
        .or(openpgp_routes)
        .or(device_routes)
        .or(mac_routes)
        .or(security_routes)
        .or(snmp_routes)
        .or(vpn_routes)
        .or(grpc_routes)
        .or(webdav_routes)
        .or(opentelemetry_routes)
        .or(monitoring_routes)
        .or(grafana_routes)
        .or(poweradmin_routes)
        .or(logger_routes)
        .or(search_routes)
        .or(ssh_routes)
        .or(voip_routes)
        .or(discord_routes)
        .or(git_routes)
        .or(oauth2_routes);

    // Apply OAuth2 authentication to /api/v1/* routes (except auth endpoints)
    let api_v1_protected_routes = warp::path("api" / "v1" / ..)
        .and(auth_middleware::oauth2_auth(keycloak_client.clone(), vec!["api".to_string()]))
        .and(combined_protected_routes)
        .map(|_claims, reply| reply); // Ignore claims for now, just pass through

    let all_routes = hello.or(key_routes).or(auth_routes).or(data_routes).or(openpgp_routes).or(device_routes).or(mac_routes).or(websocket_routes).or(security_routes).or(snmp_routes).or(vpn_routes).or(grpc_routes).or(webdav_routes).or(opentelemetry_routes).or(monitoring_routes).or(grafana_routes).or(poweradmin_routes).or(logger_routes).or(search_routes).or(ssh_routes).or(voip_routes).or(discord_routes).or(git_routes).or(oauth2_routes).or(openapi_json).or(swagger_ui).or(api_v1_protected_routes);

    // Apply audit logging to all routes
    let logger_service_for_middleware = Arc::new(crate::services::logger_service::LoggerService::new(audit_manager.clone(), vault_client.clone()));
    all_routes.with(logging::audit_log_requests(logger_service_for_middleware))
}