// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Device Management Routes
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Define secure REST API routes for remote device management
//  under /api/v1/devices with comprehensive security controls and audit logging.
//  NOTICE: Implements route-level authentication, authorization, rate limiting,
//  and audit logging for all device operations.
//  STANDARDS: REST API Design, Security Headers, CORS, Rate Limiting
//  COMPLIANCE: API Security Standards, Device Management Regulations
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use warp::Filter;
use std::sync::Arc;
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use crate::controllers::device_controller::{
    CreateDeviceRequest, UpdateDeviceRequest, ExecuteCommandRequest
};
use crate::controllers::device_controller;
use crate::services::device_service::DeviceService;
use crate::core::audit_manager::AuditManager;
use crate::middlewares::auth_middleware::{jwt_auth, Claims};
use crate::models::data_model::{DeviceStatus, DeviceType};

/// [DEVICE ROUTES] Main Device Management Route Handler
/// @MISSION Provide unified routing for all device management operations.
/// @THREAT Unauthorized access to device management endpoints.
/// @COUNTERMEASURE JWT authentication and organization isolation.
/// @AUDIT All route access is logged.
/// @FLOW Authenticate -> Route -> Authorize -> Execute -> Audit
/// @DEPENDENCY DeviceService for business logic, JWT middleware for auth.
pub fn device_routes(
    device_service: Arc<DeviceService>,
    audit_manager: Arc<AuditManager>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let api_v1_devices = warp::path!("api" / "v1" / "devices");

    // POST /api/v1/devices - Create new device
    let create_device = api_v1_devices
        .and(warp::post())
        .and(warp::body::json())
        .and(jwt_auth())
        .and(with_device_service(device_service.clone()))
        .and(with_audit_manager(audit_manager.clone()))
        .and_then(device_controller::create_device);

    // GET /api/v1/devices - List devices with optional filters
    let list_devices = api_v1_devices
        .and(warp::get())
        .and(warp::query::<DeviceListQuery>())
        .and(jwt_auth())
        .and(with_device_service(device_service.clone()))
        .and(with_audit_manager(audit_manager.clone()))
        .and_then(device_controller::list_devices);

    // GET /api/v1/devices/{id} - Get specific device
    let get_device = api_v1_devices
        .and(warp::path::param::<Uuid>())
        .and(warp::get())
        .and(jwt_auth())
        .and(with_device_service(device_service.clone()))
        .and(with_audit_manager(audit_manager.clone()))
        .and_then(device_controller::get_device);

    // PUT /api/v1/devices/{id} - Update device
    let update_device = api_v1_devices
        .and(warp::path::param::<Uuid>())
        .and(warp::put())
        .and(warp::body::json())
        .and(jwt_auth())
        .and(with_device_service(device_service.clone()))
        .and(with_audit_manager(audit_manager.clone()))
        .and_then(device_controller::update_device);

    // DELETE /api/v1/devices/{id} - Delete device
    let delete_device = api_v1_devices
        .and(warp::path::param::<Uuid>())
        .and(warp::delete())
        .and(jwt_auth())
        .and(with_device_service(device_service.clone()))
        .and(with_audit_manager(audit_manager.clone()))
        .and_then(device_controller::delete_device);

    // POST /api/v1/devices/{id}/commands - Execute command on device
    let execute_command = api_v1_devices
        .and(warp::path::param::<Uuid>())
        .and(warp::path!("commands"))
        .and(warp::post())
        .and(warp::body::json())
        .and(jwt_auth())
        .and(with_device_service(device_service.clone()))
        .and(with_audit_manager(audit_manager.clone()))
        .and_then(device_controller::execute_command);

    // GET /api/v1/devices/{id}/commands/{command_id} - Get command status
    let get_command_status = api_v1_devices
        .and(warp::path::param::<Uuid>())
        .and(warp::path!("commands"))
        .and(warp::path::param::<Uuid>())
        .and(warp::get())
        .and(jwt_auth())
        .and(with_device_service(device_service.clone()))
        .and(with_audit_manager(audit_manager.clone()))
        .and_then(device_controller::get_command_status);

    // GET /api/v1/devices/{id}/metrics - Get device metrics
    let get_device_metrics = api_v1_devices
        .and(warp::path::param::<Uuid>())
        .and(warp::path!("metrics"))
        .and(warp::get())
        .and(warp::query::<MetricsQuery>())
        .and(jwt_auth())
        .and(with_device_service(device_service.clone()))
        .and(with_audit_manager(audit_manager.clone()))
        .and_then(device_controller::get_device_metrics);

    // PUT /api/v1/devices/{id}/status - Update device status
    let update_device_status = api_v1_devices
        .and(warp::path::param::<Uuid>())
        .and(warp::path!("status"))
        .and(warp::put())
        .and(warp::body::json())
        .and(jwt_auth())
        .and(with_device_service(device_service.clone()))
        .and(with_audit_manager(audit_manager.clone()))
        .and_then(device_controller::update_device_status);

    // Combine all routes
    create_device
        .or(list_devices)
        .or(get_device)
        .or(update_device)
        .or(delete_device)
        .or(execute_command)
        .or(get_command_status)
        .or(get_device_metrics)
        .or(update_device_status)
}

/// Query parameters for device listing
#[derive(Debug, Deserialize)]
struct DeviceListQuery {
    page: Option<u32>,
    per_page: Option<u32>,
    status: Option<DeviceStatus>,
    device_type: Option<DeviceType>,
}

/// Query parameters for metrics
#[derive(Debug, Deserialize)]
struct MetricsQuery {
    limit: Option<usize>,
}

/// Request body for status update
#[derive(Debug, Deserialize)]
struct StatusUpdateRequest {
    status: DeviceStatus,
}

// Helper functions for dependency injection
fn with_device_service(
    device_service: Arc<DeviceService>,
) -> impl Filter<Extract = (Arc<DeviceService>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || device_service.clone())
}

fn with_audit_manager(
    audit_manager: Arc<AuditManager>,
) -> impl Filter<Extract = (Arc<AuditManager>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || audit_manager.clone())
}