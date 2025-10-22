use actix_web::{web, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::middleware::auth::{AuthenticatedUser, require_role};
use crate::models::user::UpdateUser;
use crate::services::user::UserService;
use crate::utils::db::DbPool;

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub organization_id: Option<Uuid>,
    pub email: String,
    pub full_name: Option<String>,
    pub password_hash: String,
    pub role: Option<String>,
    pub status: Option<String>,
}

pub async fn create_user(
    pool: web::Data<DbPool>,
    user: web::ReqData<AuthenticatedUser>,
    req: web::Json<CreateUserRequest>,
) -> Result<HttpResponse> {
    // Require admin role or same org
    let user_org = user.organization_id.as_ref().and_then(|id| Uuid::parse_str(id).ok());
    if !user.roles.contains(&"admin".to_string()) && user_org != req.organization_id {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Insufficient permissions"
        })));
    }

    let mut conn = pool.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
    })?;

    match UserService::create_user(
        &mut conn,
        req.organization_id,
        &req.email,
        req.full_name.as_deref(),
        &req.password_hash,
        req.role.as_deref().unwrap_or("user"),
        req.status.as_deref().unwrap_or("active"),
    ) {
        Ok(u) => Ok(HttpResponse::Created().json(serde_json::json!({
            "message": "User created successfully",
            "data": u
        }))),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to create user: {}", e)
        }))),
    }
}

pub async fn get_user(
    pool: web::Data<DbPool>,
    user_id: web::Path<Uuid>,
    user: web::ReqData<AuthenticatedUser>,
) -> Result<HttpResponse> {
    let user_sub = Uuid::parse_str(&user.sub).unwrap();
    if user_sub != *user_id && !user.roles.contains(&"admin".to_string()) {
        let user_org = user.organization_id.as_ref().and_then(|id| Uuid::parse_str(id).ok());
        // Check if same org
        let mut conn = pool.get().map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
        })?;
        if let Ok(target_user) = UserService::get_user(&mut conn, *user_id) {
            if user_org != target_user.organization_id {
                return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Insufficient permissions"
                })));
            }
        }
    }

    let mut conn = pool.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
    })?;

    match UserService::get_user(&mut conn, *user_id) {
        Ok(u) => Ok(HttpResponse::Ok().json(serde_json::json!({ "data": u }))),
        Err(_) => Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "User not found"}))),
    }
}

pub async fn get_users_by_organization(
    pool: web::Data<DbPool>,
    organization_id: web::Path<Uuid>,
    user: web::ReqData<AuthenticatedUser>,
) -> Result<HttpResponse> {
    let user_org = user.organization_id.as_ref().and_then(|id| Uuid::parse_str(id).ok());
    if user_org != Some(*organization_id) && !user.roles.contains(&"admin".to_string()) {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Insufficient permissions"
        })));
    }

    let mut conn = pool.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
    })?;

    match UserService::get_users_by_organization(&mut conn, *organization_id) {
        Ok(users) => Ok(HttpResponse::Ok().json(serde_json::json!({ "data": users }))),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to get users: {}", e)
        }))),
    }
}

pub async fn update_user(
    pool: web::Data<DbPool>,
    user_id: web::Path<Uuid>,
    user: web::ReqData<AuthenticatedUser>,
    req: web::Json<UpdateUser>,
) -> Result<HttpResponse> {
    let user_sub = Uuid::parse_str(&user.sub).unwrap();
    if user_sub != *user_id && !user.roles.contains(&"admin".to_string()) {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Insufficient permissions"
        })));
    }

    let mut conn = pool.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
    })?;

    match UserService::update_user(&mut conn, *user_id, req.into_inner()) {
        Ok(u) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "User updated successfully",
            "data": u
        }))),
        Err(_) => Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "User not found"}))),
    }
}

pub async fn delete_user(
    pool: web::Data<DbPool>,
    user_id: web::Path<Uuid>,
    user: web::ReqData<AuthenticatedUser>,
) -> Result<HttpResponse> {
    if let Err(resp) = require_role(&user, "admin") {
        return Ok(resp);
    }

    let mut conn = pool.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
    })?;

    match UserService::delete_user(&mut conn, *user_id) {
        Ok(_) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "User deleted successfully"
        }))),
        Err(_) => Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "User not found"}))),
    }
}

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/users")
            .route("", web::post().to(create_user))
            .route("/{user_id}", web::get().to(get_user))
            .route("/{user_id}", web::put().to(update_user))
            .route("/{user_id}", web::delete().to(delete_user))
            .route("/organization/{organization_id}", web::get().to(get_users_by_organization))
    );
}