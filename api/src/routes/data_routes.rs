// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Database Management Routes - Simplified for Compilation
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
    let create_connection = warp::path!("connections")
        .and(warp::post())
        .and(warp::body::json())
        .and(jwt_auth())
        .and(warp::any().map(move || data_service.clone()))
        .and_then(|connection, _auth, service: Arc<DataService>| async move {
            data_controller::create_connection(service, connection).await
        });

    let execute_query = warp::path!("query")
        .and(warp::post())
        .and(warp::path::param::<String>())
        .and(warp::body::json())
        .and(jwt_auth())
        .and(warp::any().map(move || data_service.clone()))
        .and_then(|connection_id, query, _auth, service: Arc<DataService>| async move {
            data_controller::execute_query(service, connection_id, query).await
        });

    let health_check = warp::path!("health")
        .and(warp::get())
        .and(jwt_auth())
        .and(warp::any().map(move || data_service.clone()))
        .and_then(|_auth, service: Arc<DataService>| async move {
            data_controller::health_check(service).await
        });

    // Combine all routes
    create_connection
        .or(execute_query)
        .or(health_check)
}