use utoipa::OpenApi;
use crate::services::auth_service::LoginRequest;
use crate::models::user::User;
use crate::services::application_service::ApplicationAccessRequest;
use crate::services::two_factor_service::{TwoFactorSetupRequest, TwoFactorVerificationRequest};

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::controllers::auth_controller::login
    ),
    components(
        schemas(
            LoginRequest,
            User,
            ApplicationAccessRequest,
            TwoFactorSetupRequest,
            TwoFactorVerificationRequest,
            LoginResponse,
            ErrorResponse
        )
    ),
    info(
        title = "Sky Genesis Enterprise API",
        version = "1.0.0",
        description = "API for Sky Genesis Enterprise services including authentication, key management, and more."
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