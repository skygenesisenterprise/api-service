use actix_web::{web, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::middleware::auth::{AuthenticatedUser, require_role};
use crate::models::data_source::{NewDataSource, UpdateDataSource};
use crate::services::data_source::DataSourceService;
use crate::utils::db::DbPool;

#[derive(Deserialize)]
pub struct CreateDataSourceRequest {
    pub name: String,
    pub db_type: String,
    pub host: String,
    pub port: Option<i32>,
    pub database_name: String,
    pub username: String,
    pub password: String,
    pub status: Option<String>,
}

#[derive(Deserialize)]
pub struct ExecuteQueryRequest {
    pub query: String,
    pub params: Option<Vec<String>>,
}

pub async fn create_data_source(
    pool: web::Data<DbPool>,
    user: web::ReqData<AuthenticatedUser>,
    req: web::Json<CreateDataSourceRequest>,
) -> Result<HttpResponse> {
    let user_org = user.organization_id.as_ref().and_then(|id| Uuid::parse_str(id).ok());
    if user_org.is_none() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({"error": "User not in organization"})));
    }
    let org_id = user_org.unwrap();

    let mut conn = pool.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
    })?;

    match DataSourceService::create_data_source(
        &mut conn,
        &req.name,
        &req.db_type,
        &req.host,
        req.port.unwrap_or(5432),
        &req.database_name,
        &req.username,
        &req.password,
        org_id,
        req.status.as_deref().unwrap_or("active"),
    ) {
        Ok(ds) => Ok(HttpResponse::Created().json(serde_json::json!({
            "message": "Data source created successfully",
            "data": ds
        }))),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to create data source: {}", e)
        }))),
    }
}

pub async fn get_data_sources(
    pool: web::Data<DbPool>,
    user: web::ReqData<AuthenticatedUser>,
) -> Result<HttpResponse> {
    let user_org = user.organization_id.as_ref().and_then(|id| Uuid::parse_str(id).ok());
    if user_org.is_none() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({"error": "User not in organization"})));
    }
    let org_id = user_org.unwrap();

    let mut conn = pool.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
    })?;

    match DataSourceService::get_data_sources_by_organization(&mut conn, org_id) {
        Ok(dss) => Ok(HttpResponse::Ok().json(serde_json::json!({ "data": dss }))),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to get data sources: {}", e)
        }))),
    }
}

pub async fn execute_query(
    pool: web::Data<DbPool>,
    path: web::Path<Uuid>,
    user: web::ReqData<AuthenticatedUser>,
    req: web::Json<ExecuteQueryRequest>,
) -> Result<HttpResponse> {
    let ds_id = path.into_inner();

    let mut conn = pool.get().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Database error: {}", e))
    })?;

    let ds = match DataSourceService::get_data_source(&mut conn, ds_id) {
        Ok(ds) => ds,
        Err(_) => return Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "Data source not found"}))),
    };

    // Vérifier accès
    let user_org = user.organization_id.as_ref().and_then(|id| Uuid::parse_str(id).ok());
    if user_org != Some(ds.organization_id) {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({"error": "Access denied"})));
    }

    match DataSourceService::execute_query(&ds, &req.query, req.params.clone().unwrap_or_default()).await {
        Ok(result) => Ok(HttpResponse::Ok().json(serde_json::json!({ "message": result }))),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Query failed: {}", e)
        }))),
    }
}

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/data-sources")
            .route("", web::post().to(create_data_source))
            .route("", web::get().to(get_data_sources))
            .route("/{data_source_id}/query", web::post().to(execute_query))
    );
}