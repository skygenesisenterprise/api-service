// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Device Management Routes - Simplified for Compilation
// ============================================================================

use warp::Filter;
use std::sync::Arc;
use crate::controllers::device_controller;
use crate::services::device_service::DeviceService;
use crate::middlewares::auth_middleware::jwt_auth;

/// [DEVICE ROUTES] Main Device Management Route Handler
/// @MISSION Provide unified routing for all device operations.
/// @THREAT Unauthorized access to device management endpoints.
/// @COUNTERMEASURE JWT authentication and device authorization.
/// @AUDIT All route access is logged.
/// @FLOW Authenticate -> Route -> Authorize -> Execute -> Audit
/// @DEPENDENCY DeviceService for business logic, JWT middleware for auth.
pub fn device_routes(device_service: Arc<DeviceService>) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let list_devices = warp::path!("devices")
        .and(warp::get())
        .and(warp::path::param::<String>())
        .and(warp::query::<std::collections::HashMap<String, String>>())
        .and(jwt_auth())
        .and(warp::any().map(move || device_service.clone()))
        .and_then(|organization_id, params, _auth, service: Arc<DeviceService>| async move {
            let page = params.get("page").and_then(|p| p.parse().ok()).unwrap_or(1);
            let per_page = params.get("per_page").and_then(|p| p.parse().ok()).unwrap_or(20);
            device_controller::list_devices(service, organization_id, page, per_page).await
        });

    let execute_command = warp::path!("devices")
        .and(warp::path::param::<String>())
        .and(warp::path!("command"))
        .and(warp::post())
        .and(warp::body::json())
        .and(jwt_auth())
        .and(warp::any().map(move || device_service.clone()))
        .and_then(|device_id, command, _auth, service: Arc<DeviceService>| async move {
            device_controller::execute_command(service, device_id, command).await
        });

    let get_metrics = warp::path!("devices")
        .and(warp::path::param::<String>())
        .and(warp::path!("metrics"))
        .and(warp::get())
        .and(jwt_auth())
        .and(warp::any().map(move || device_service.clone()))
        .and_then(|device_id, _auth, service: Arc<DeviceService>| async move {
            device_controller::get_metrics(service, device_id).await
        });

    // Combine all routes
    list_devices
        .or(execute_command)
        .or(get_metrics)
}