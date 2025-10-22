use actix_web::{web, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::middleware::auth::{AuthenticatedUser, require_role};
use crate::models::organization::{NewOrganization, UpdateOrganization};
use crate::services::organization::OrganizationService;
use crate::utils::db::DbPool;

#[derive(Deserialize)]
pub struct CreateOrganizationRequest {
    pub name: String,
    pub country_code: Option<String>,
}

pub async fn create_organization(
    pool: web::Data<DbPool>,
    user: web::ReqData<AuthenticatedUser>,
    req: web::Json<CreateOrganizationRequest>,
) -> Result<HttpResponse> {
    // Require admin role
    if let Err(resp) = require_role(&user, "admin") {
        return Ok(resp);
    }

    let mut conn = pool.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
    })?;

    match OrganizationService::create_organization(&mut conn, &req.name, req.country_code.as_deref()) {
        Ok(org) => Ok(HttpResponse::Created().json(serde_json::json!({
            "message": "Organization created successfully",
            "data": org
        }))),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to create organization: {}", e)
        }))),
    }
}

pub async fn get_organization(
    pool: web::Data<DbPool>,
    organization_id: web::Path<Uuid>,
    user: web::ReqData<AuthenticatedUser>,
) -> Result<HttpResponse> {
    let user_org = Uuid::parse_str(user.organization_id.as_ref().unwrap()).unwrap();
    if user_org != *organization_id && !user.roles.contains(&"admin".to_string()) {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Insufficient permissions"
        })));
    }

    let mut conn = pool.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
    })?;

    match OrganizationService::get_organization(&mut conn, *organization_id) {
        Ok(org) => Ok(HttpResponse::Ok().json(serde_json::json!({ "data": org }))),
        Err(_) => Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "Organization not found"}))),
    }
}

pub async fn get_all_organizations(
    pool: web::Data<DbPool>,
    user: web::ReqData<AuthenticatedUser>,
) -> Result<HttpResponse> {
    if let Err(resp) = require_role(&user, "admin") {
        return Ok(resp);
    }

    let mut conn = pool.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
    })?;

    match OrganizationService::get_all_organizations(&mut conn) {
        Ok(orgs) => Ok(HttpResponse::Ok().json(serde_json::json!({ "data": orgs }))),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to get organizations: {}", e)
        }))),
    }
}

pub async fn update_organization(
    pool: web::Data<DbPool>,
    organization_id: web::Path<Uuid>,
    user: web::ReqData<AuthenticatedUser>,
    req: web::Json<UpdateOrganization>,
) -> Result<HttpResponse> {
    if let Err(resp) = require_role(&user, "admin") {
        return Ok(resp);
    }

    let mut conn = pool.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
    })?;

    match OrganizationService::update_organization(&mut conn, *organization_id, req.into_inner()) {
        Ok(org) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Organization updated successfully",
            "data": org
        }))),
        Err(_) => Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "Organization not found"}))),
    }
}

pub async fn delete_organization(
    pool: web::Data<DbPool>,
    organization_id: web::Path<Uuid>,
    user: web::ReqData<AuthenticatedUser>,
) -> Result<HttpResponse> {
    if let Err(resp) = require_role(&user, "admin") {
        return Ok(resp);
    }

    let mut conn = pool.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
    })?;

    match OrganizationService::delete_organization(&mut conn, *organization_id) {
        Ok(_) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Organization deleted successfully"
        }))),
        Err(_) => Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "Organization not found"}))),
    }
}

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/organizations")
            .route("", web::post().to(create_organization))
            .route("", web::get().to(get_all_organizations))
            .route("/{organization_id}", web::get().to(get_organization))
            .route("/{organization_id}", web::put().to(update_organization))
            .route("/{organization_id}", web::delete().to(delete_organization))
    );
}