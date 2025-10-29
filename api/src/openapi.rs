use utoipa::OpenApi;
use crate::services::auth_service::LoginRequest;
use crate::models::user::User;
use crate::services::application_service::ApplicationAccessRequest;
use crate::services::two_factor_service::{TwoFactorSetupRequest, TwoFactorVerificationRequest};
use crate::core::fido2::{Fido2RegistrationRequest, Fido2AuthenticationRequest};
use crate::core::webdav::DavResource;
use crate::websocket::PresenceStatus;

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::controllers::auth_controller::login,
        // OIDC endpoints
        // FIDO2 endpoints
        // WebSocket endpoints
        // WebDAV endpoints
        // gRPC proxy endpoints
        // VPN endpoints
        // OpenTelemetry endpoints
    ),
    components(
        schemas(
            LoginRequest,
            User,
            ApplicationAccessRequest,
            TwoFactorSetupRequest,
            TwoFactorVerificationRequest,
            LoginResponse,
            ErrorResponse,
            // New schemas
            Fido2RegistrationRequest,
            Fido2AuthenticationRequest,
            DavResource,
            PresenceStatus,
            OidcLoginRequest,
            OidcCallbackRequest,
            VpnPeer,
            VpnConfig,
            GrpcSendEmailRequest,
            GrpcSearchRequest,
            MetricsResponse,
            TelemetryHealthResponse
        )
    ),
    info(
        title = "Sky Genesis Enterprise API",
        version = "1.0.0",
        description = "Sovereign European API service with native protocol integrations including XMPP, WebDAV, gRPC, OpenTelemetry, and more."
    ),
    servers(
        (url = "http://localhost:8080", description = "Local development server"),
        (url = "https://api.skygenesisenterprise.com", description = "Production server")
    )
)]
pub struct ApiDoc;

#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct LoginResponse {
    pub token: String,
    pub user: User,
}

#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

// OIDC schemas
#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct OidcLoginRequest {
    pub redirect_uri: String,
    pub state: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct OidcCallbackRequest {
    pub code: String,
    pub state: Option<String>,
}

// VPN schemas
#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct VpnPeer {
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<String>,
    pub persistent_keepalive: Option<u16>,
}

#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct VpnConfig {
    pub interface: String,
    pub listen_port: u16,
    pub address: String,
    pub peers: std::collections::HashMap<String, VpnPeer>,
}

// gRPC proxy schemas
#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct GrpcSendEmailRequest {
    pub to: Vec<String>,
    pub subject: String,
    pub body: String,
}

#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct GrpcSearchRequest {
    pub query: String,
    pub limit: Option<i32>,
    pub offset: Option<i32>,
}

// OpenTelemetry schemas
#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct MetricsResponse {
    pub status: String,
    pub format: String,
}

#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct TelemetryHealthResponse {
    pub status: String,
    pub components: serde_json::Value,
}