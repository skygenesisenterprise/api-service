// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: OpenAPI Specification
// ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | SECURITY-CRITICAL
//  MISSION: Generate accurate API documentation for defense-grade operations.
//  NOTICE: This code is part of the SGE Sovereign Cloud Framework.
//  Unauthorized modification of production systems is strictly prohibited.
//  All operations are cryptographically auditable via OpenTelemetry.
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use utoipa::OpenApi;
use crate::services::auth_service::LoginRequest;
use crate::models::user::User;
use crate::services::application_service::ApplicationAccessRequest;
use crate::services::two_factor_service::{TwoFactorSetupRequest, TwoFactorVerificationRequest};
use crate::core::fido2::{Fido2RegistrationRequest, Fido2AuthenticationRequest};
use crate::core::webdav::DavResource;
use crate::websocket::PresenceStatus;

/// [API DOCUMENTATION] OpenAPI Specification Generator
/// @MISSION Provide accurate, security-aware API documentation.
/// @THREAT Documentation exposure revealing attack vectors.
/// @COUNTERMEASURE Redact sensitive information and audit documentation access.
/// @DEPENDENCY utoipa crate for OpenAPI generation.
/// @AUDIT API documentation changes logged with version control.
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

/// [API RESPONSE] Authentication Success Payload
/// @MISSION Provide secure token and user information.
/// @THREAT Token exposure in API responses.
/// @COUNTERMEASURE Use short-lived tokens and redact sensitive data.
#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct LoginResponse {
    pub token: String,
    pub user: User,
}

/// [API RESPONSE] Error Information Structure
/// @MISSION Communicate errors without revealing system details.
/// @THREAT Information disclosure through error messages.
/// @COUNTERMEASURE Use generic error codes and audit all error responses.
#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

// OIDC schemas
/// [OIDC PROTOCOL] Authorization Request Parameters
/// @MISSION Initiate secure OIDC authentication flow.
/// @THREAT Authorization code interception.
/// @COUNTERMEASURE Use PKCE and state parameter validation.
#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct OidcLoginRequest {
    pub redirect_uri: String,
    pub state: Option<String>,
}

/// [OIDC PROTOCOL] Callback Request Parameters
/// @MISSION Complete OIDC authentication with authorization code.
/// @THREAT Code replay or injection attacks.
/// @COUNTERMEASURE Validate state and use code only once.
#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct OidcCallbackRequest {
    pub code: String,
    pub state: Option<String>,
}

// VPN schemas
/// [VPN CONFIGURATION] WireGuard Peer Definition
/// @MISSION Define secure VPN peer connections.
/// @THREAT Peer key compromise or IP spoofing.
/// @COUNTERMEASURE Use strong cryptography and validate peer identities.
#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct VpnPeer {
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<String>,
    pub persistent_keepalive: Option<u16>,
}

/// [VPN CONFIGURATION] WireGuard Interface Configuration
/// @MISSION Establish encrypted network perimeter.
/// @THREAT Network configuration compromise.
/// @COUNTERMEASURE Validate all network parameters and audit changes.
#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct VpnConfig {
    pub interface: String,
    pub listen_port: u16,
    pub address: String,
    pub peers: std::collections::HashMap<String, VpnPeer>,
}

// gRPC proxy schemas
/// [GRPC PROXY] Email Transmission Request
/// @MISSION Send encrypted emails via gRPC services.
/// @THREAT Email content interception.
/// @COUNTERMEASURE Use TLS 1.3 and validate recipient addresses.
#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct GrpcSendEmailRequest {
    pub to: Vec<String>,
    pub subject: String,
    pub body: String,
}

/// [GRPC PROXY] Search Query Request
/// @MISSION Perform secure search operations.
/// @THREAT Query injection or result manipulation.
/// @COUNTERMEASURE Sanitize inputs and validate result integrity.
#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct GrpcSearchRequest {
    pub query: String,
    pub limit: Option<i32>,
    pub offset: Option<i32>,
}

// OpenTelemetry schemas
/// [OBSERVABILITY] Metrics Export Response
/// @MISSION Provide monitoring data for system health.
/// @THREAT Metrics manipulation or exposure.
/// @COUNTERMEASURE Use authenticated access and data integrity checks.
#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct MetricsResponse {
    pub status: String,
    pub format: String,
}

/// [OBSERVABILITY] Telemetry System Health
/// @MISSION Report observability component status.
/// @THREAT False health reporting.
/// @COUNTERMEASURE Implement independent health checks.
#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct TelemetryHealthResponse {
    pub status: String,
    pub components: serde_json::Value,
}