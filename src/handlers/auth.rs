use actix_web::{web, HttpResponse, Result};
use serde::{Deserialize, Serialize};

use crate::services::auth::AuthService;

#[derive(Deserialize)]
pub struct AuthRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub message: String,
    pub data: serde_json::Value,
}

pub async fn authenticate(auth_req: web::Json<AuthRequest>) -> Result<HttpResponse> {
    match AuthService::authenticate(&auth_req.username, &auth_req.password).await {
        Ok(data) => {
            let response = AuthResponse {
                message: "Authentication successful".to_string(),
                data,
            };
            Ok(HttpResponse::Ok().json(response))
        }
        Err(_) => Ok(HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Authentication failed"
        }))),
    }
}

pub async fn auth_get() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().body("This is the auth route"))
}

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .route("", web::post().to(authenticate))
            .route("", web::get().to(auth_get))
    );
}