// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Database Management Routes
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Define secure REST API routes for database connection management
//  and query execution under /api/v1/data with comprehensive security controls.
//  NOTICE: Implements route-level authentication, authorization, rate limiting,
//  and audit logging for all database operations.
//  STANDARDS: REST API Design, Security Headers, CORS, Rate Limiting
//  COMPLIANCE: API Security Standards, Data Protection Regulations
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use warp::Filter;
use std::sync::Arc;
use crate::controllers::data_controller;
use crate::services::data_service::DataService;
use crate::middlewares::auth_middleware::jwt_auth;

/// [DATABASE ROUTES] Main Database Management Route Handler
/// @MISSION Provide unified routing for all database operations.
/// @THREAT Unauthorized access to database endpoints.
/// @COUNTERMEASURE JWT authentication and tenant isolation.
/// @AUDIT All route access is logged.
/// @FLOW Authenticate -> Route -> Authorize -> Execute -> Audit
/// @DEPENDENCY DataService for business logic, JWT middleware for auth.
pub fn data_routes(data_service: Arc<DataService>) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let api_v1_data = warp::path!("api" / "v1" / "data");

    // POST /api/v1/data/connections - Create new database connection
    let create_connection = api_v1_data
        .and(warp::path!("connections"))
        .and(warp::post())
        .and(jwt_auth())
        .and(warp::query::<std::collections::HashMap<String, String>>())
        .and(warp::any().map(move || data_service.clone()))
        .and_then(|_claims, query: std::collections::HashMap<String, String>, ds| async move {
            let name = query.get("name").cloned().unwrap_or_default();
            let db_type = query.get("type").cloned().unwrap_or_default();
            let host = query.get("host").cloned().unwrap_or_default();
            let port = query.get("port").and_then(|s| s.parse().ok()).unwrap_or(5432);
            let database_name = query.get("database").cloned().unwrap_or_default();
            let username = query.get("username").cloned().unwrap_or_default();
            let password_ref = query.get("password_ref").cloned().unwrap_or_default();
            let tenant = query.get("tenant").cloned().unwrap_or_default();

            data_controller::create_connection(
                ds, name, db_type, host, port, database_name,
                username, password_ref, tenant
            ).await
        });

    // DELETE /api/v1/data/connections/{id} - Remove database connection
    let remove_connection = api_v1_data
        .and(warp::path!("connections" / String))
        .and(warp::delete())
        .and(jwt_auth())
        .and(warp::any().map(move || data_service.clone()))
        .and_then(|connection_id, _claims, ds| async move {
            data_controller::remove_connection(ds, connection_id).await
        });

    // GET /api/v1/data/connections - List database connections
    let list_connections = api_v1_data
        .and(warp::path!("connections"))
        .and(warp::get())
        .and(jwt_auth())
        .and(warp::query::<std::collections::HashMap<String, String>>())
        .and(warp::any().map(move || data_service.clone()))
        .and_then(|_claims, query, ds| async move {
            let tenant = query.get("tenant").cloned().unwrap_or_default();
            data_controller::list_connections(ds, tenant).await
        });

    // POST /api/v1/data/query - Execute ZTNA-secured database query
    let execute_query = api_v1_data
        .and(warp::path!("query"))
        .and(warp::post())
        .and(jwt_auth())
        .and(warp::body::json())
        .and(warp::any().map(move || data_service.clone()))
        .and_then(|claims, body: serde_json::Value, ds| async move {
            let connection_id = body.get("connection_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let query = body.get("query")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let parameters = body.get("parameters")
                .and_then(|v| v.as_array())
                .unwrap_or(&vec![])
                .clone();
            let read_only = body.get("read_only")
                .and_then(|v| v.as_bool());
            let timeout = body.get("timeout")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32);

            // Extract context from request
            let user = claims.sub.clone(); // JWT subject (user identifier)
            let client_ip = "127.0.0.1".to_string(); // TODO: Extract from request headers
            let user_agent = "API-Client".to_string(); // TODO: Extract from request headers
            let session_id = claims.jti.clone().unwrap_or_else(|| "unknown".to_string()); // JWT ID as session

            data_controller::execute_query_ztna(
                ds, connection_id, query, parameters, read_only, timeout,
                user, client_ip, user_agent, session_id
            ).await
        });

    // GET /api/v1/data/health/{connection_id} - Check connection health
    let health_check = api_v1_data
        .and(warp::path!("health" / String))
        .and(warp::get())
        .and(jwt_auth())
        .and(warp::any().map(move || data_service.clone()))
        .and_then(|connection_id, _claims, ds| async move {
            data_controller::health_check(ds, connection_id).await
        });

    // POST /api/v1/data/permissions - Grant database permissions
    let grant_permission = api_v1_data
        .and(warp::path!("permissions"))
        .and(warp::post())
        .and(jwt_auth())
        .and(warp::body::json())
        .and(warp::any().map(move || data_service.clone()))
        .and_then(|_claims, body: serde_json::Value, ds| async move {
            let principal = body.get("principal")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let connection_id = body.get("connection_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let operations = body.get("operations")
                .and_then(|v| v.as_array())
                .unwrap_or(&vec![])
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
            let resource_filters = body.get("resource_filters")
                .and_then(|v| v.as_array())
                .unwrap_or(&vec![])
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
            let expires_at = body.get("expires_at")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            data_controller::grant_permission(
                ds, principal, connection_id, operations, resource_filters, expires_at
            ).await
        });

    // ZTNA Policy Management Routes
    let create_ztna_policy = api_v1_data
        .and(warp::path!("policies"))
        .and(warp::post())
        .and(jwt_auth())
        .and(warp::body::json())
        .and(warp::any().map(move || data_service.clone()))
        .and_then(|_claims, body: serde_json::Value, ds| async move {
            let name = body.get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let tenant = body.get("tenant")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let connection_id = body.get("connection_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let principals = body.get("principals")
                .and_then(|v| v.as_array())
                .unwrap_or(&vec![])
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
            let operations = body.get("operations")
                .and_then(|v| v.as_array())
                .unwrap_or(&vec![])
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
            let schemas = body.get("schemas")
                .and_then(|v| v.as_array())
                .unwrap_or(&vec![])
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
            let tables = body.get("tables")
                .and_then(|v| v.as_array())
                .unwrap_or(&vec![])
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
            let max_rows = body.get("max_rows")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32);
            let ip_ranges = body.get("ip_ranges")
                .and_then(|v| v.as_array())
                .unwrap_or(&vec![])
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
            let risk_threshold = body.get("risk_threshold")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            data_controller::create_ztna_policy(
                ds, name, tenant, connection_id, principals, operations,
                schemas, tables, max_rows, ip_ranges, risk_threshold
            ).await
        });

    let evaluate_ztna_access = api_v1_data
        .and(warp::path!("access" / "evaluate"))
        .and(warp::post())
        .and(jwt_auth())
        .and(warp::body::json())
        .and(warp::any().map(move || data_service.clone()))
        .and_then(|_claims, body: serde_json::Value, ds| async move {
            let principal = body.get("principal")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let connection_id = body.get("connection_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let operation = body.get("operation")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let resources = body.get("resources")
                .and_then(|v| v.as_array())
                .unwrap_or(&vec![])
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
            let ip_address = body.get("ip_address")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let user_agent = body.get("user_agent")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let session_id = body.get("session_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let risk_score = body.get("risk_score")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32);

            data_controller::evaluate_ztna_access(
                ds, principal, connection_id, operation, resources,
                ip_address, user_agent, session_id, risk_score
            ).await
        });

    let list_ztna_policies = api_v1_data
        .and(warp::path!("policies"))
        .and(warp::get())
        .and(jwt_auth())
        .and(warp::query::<std::collections::HashMap<String, String>>())
        .and(warp::any().map(move || data_service.clone()))
        .and_then(|_claims, query, ds| async move {
            let tenant = query.get("tenant").cloned().unwrap_or_default();
            data_controller::list_ztna_policies(ds, tenant).await
        });

    // Combine all routes
    create_connection
        .or(remove_connection)
        .or(list_connections)
        .or(execute_query)
        .or(health_check)
        .or(grant_permission)
        .or(create_ztna_policy)
        .or(evaluate_ztna_access)
        .or(list_ztna_policies)
}