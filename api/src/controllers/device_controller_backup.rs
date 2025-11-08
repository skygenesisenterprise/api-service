// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Device Management Controller
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide secure REST API endpoints for remote device management,
//  enabling client-server connections for device monitoring and control.
//  NOTICE: Implements device operations via /api/v1/devices endpoints with
//  authentication, authorization, rate limiting, and audit logging.
//  STANDARDS: REST API, JSON Schema, Authentication, Authorization, Auditing
//  COMPLIANCE: API Security, Device Management, Access Control
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use warp::Reply;
use std::sync::Arc;
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use serde_json::json;


use crate::models::data_model::{
    Device, DeviceStatus, DeviceType, DeviceConnectionType,
    CommandStatus, DeviceMetrics
};
use crate::services::device_service::DeviceService;
use crate::core::audit_manager::{AuditManager, AuditEvent, AuditEventType, AuditSeverity};
use crate::middlewares::auth_middleware::ApiError;

/// [DEVICE CREATE REQUEST] API Request for Creating New Device
#[derive(Debug, Deserialize, Serialize)]
pub struct CreateDeviceRequest {
    pub name: String,
    pub hostname: String,
    pub ip_address: Option<String>,
    pub device_type: DeviceType,
    pub connection_type: DeviceConnectionType,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub os_version: Option<String>,
    pub location: Option<String>,
    pub tags: Option<Vec<String>>,
    pub management_port: Option<u16>,
    pub credentials_ref: Option<String>,
    pub metadata: Option<std::collections::HashMap<String, String>>,
}

/// [DEVICE UPDATE REQUEST] API Request for Updating Device
#[derive(Debug, Deserialize, Serialize)]
pub struct UpdateDeviceRequest {
    pub name: Option<String>,
    pub hostname: Option<String>,
    pub ip_address: Option<String>,
    pub device_type: Option<DeviceType>,
    pub connection_type: Option<DeviceConnectionType>,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub os_version: Option<String>,
    pub status: Option<DeviceStatus>,
    pub location: Option<String>,
    pub tags: Option<Vec<String>>,
    pub management_port: Option<u16>,
    pub credentials_ref: Option<String>,
    pub metadata: Option<std::collections::HashMap<String, String>>,
}

/// [DEVICE COMMAND REQUEST] API Request for Executing Device Command
#[derive(Debug, Deserialize, Serialize)]
pub struct ExecuteCommandRequest {
    pub command: String,
    pub parameters: Option<std::collections::HashMap<String, String>>,
    pub timeout_seconds: Option<u32>,
}

/// [DEVICE LIST RESPONSE] API Response for Device List
#[derive(Debug, Serialize)]
pub struct DeviceListResponse {
    pub devices: Vec<Device>,
    pub total_count: i64,
    pub page: u32,
    pub per_page: u32,
}

/// [DEVICE COMMAND RESPONSE] API Response for Command Execution
#[derive(Debug, Serialize)]
pub struct CommandResponse {
    pub command_id: Uuid,
    pub status: CommandStatus,
    pub output: Option<String>,
    pub exit_code: Option<i32>,
}

/// [DEVICE METRICS RESPONSE] API Response for Device Metrics
#[derive(Debug, Serialize)]
pub struct MetricsResponse {
    pub metrics: Vec<DeviceMetrics>,
    pub device_id: Uuid,
}

/// [CREATE DEVICE ENDPOINT] Register New Device for Management
/// @MISSION Create new device entry in the system.
/// @THREAT Unauthorized device registration.
/// @COUNTERMEASURE Authentication and organization validation.
/// @AUDIT Device creation is logged with user context.
/// @FLOW Authenticate -> Validate -> Create -> Audit -> Return
pub async fn create_device(
    device_service: Arc<DeviceService>,
    audit_manager: Arc<AuditManager>,
    organization_id: Uuid,
    user_id: Uuid,
    request: CreateDeviceRequest,
) -> Result<impl Reply, warp::Rejection> {
    // Create device
    let device = device_service.create_device(
        request.name,
        request.hostname,
        request.ip_address,
        request.device_type,
        request.connection_type,
        request.vendor,
        request.model,
        request.os_version,
        organization_id,
        request.location,
        request.tags.unwrap_or_default(),
        request.management_port,
        request.credentials_ref,
        request.metadata.unwrap_or_default(),
    ).await.map_err(|e| {
        warp::reject::custom(ApiError::InternalError(e.to_string()))
    })?;

    // Audit device creation
    let event = AuditEvent {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now(),
        event_type: AuditEventType::LoginSuccess,
        severity: AuditSeverity::Low,
        user_id: Some(user_id.to_string()),
        tenant_id: Some(organization_id.to_string()),
        session_id: None,
        ip_address: None,
        user_agent: None,
        resource: "device_api".to_string(),
        action: format!("Device '{}' created with ID {}", device.name, device.id),
        status: "success".to_string(),
        details: json!({
            "device_id": device.id,
            "device_name": device.name,
            "organization_id": organization_id
        }),
        hmac_signature: "".to_string(),
    };
    audit_manager.log_event(event).await;

    Ok(warp::reply::json(&device))
}

/// [LIST DEVICES ENDPOINT] Get Devices for Organization
/// @MISSION Retrieve paginated list of devices.
/// @THREAT Unauthorized device listing.
/// @COUNTERMEASURE Organization-based filtering.
/// @AUDIT Device listing is logged.
pub async fn list_devices(
    device_service: Arc<DeviceService>,
    audit_manager: Arc<AuditManager>,
    organization_id: Uuid,
    user_id: Uuid,
    page: Option<u32>,
    per_page: Option<u32>,
    status_filter: Option<DeviceStatus>,
    type_filter: Option<DeviceType>,
) -> Result<impl Reply, warp::Rejection> {
    let page = page.unwrap_or(1);
    let per_page = per_page.unwrap_or(50);

    let (devices, total_count) = device_service.list_devices(
        organization_id,
        page,
        per_page,
        status_filter,
        type_filter,
    ).await.map_err(|e| {
        warp::reject::custom(ApiError::InternalError(e.to_string()))
    })?;

    // Audit device listing
    let event = AuditEvent {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now(),
        event_type: AuditEventType::MailReceived, // Using existing enum
        severity: AuditSeverity::Low,
        user_id: Some(user_id.to_string()),
        tenant_id: Some(organization_id.to_string()),
        session_id: None,
        ip_address: None,
        user_agent: None,
        resource: "device_api".to_string(),
        action: Some(format!("Listed {} devices for organization", devices.len())),
        status: "success".to_string(),
        details: Some(json!({
            "organization_id": organization_id,
            "page": page,
            "per_page": per_page,
            "total_count": total_count
        }).to_string()),
        hmac_signature: None,
    };
    audit_manager.log_event(event).await;

    let response = DeviceListResponse {
        devices,
        total_count,
        page,
        per_page,
    };

    Ok(warp::reply::json(&response))
}

/// [GET DEVICE ENDPOINT] Get Specific Device Details
/// @MISSION Retrieve detailed device information.
/// @THREAT Unauthorized device access.
/// @COUNTERMEASURE Device ownership validation.
/// @AUDIT Device access is logged.
pub async fn get_device(
    device_service: Arc<DeviceService>,
    audit_manager: Arc<AuditManager>,
    device_id: Uuid,
    organization_id: Uuid,
    user_id: Uuid,
) -> Result<impl Reply, warp::Rejection> {
    let device = device_service.get_device(device_id, organization_id).await
        .map_err(|e| {
            warp::reject::custom(ApiError::InternalError(e.to_string()))
        })?;

    // Audit device access
    let event = AuditEvent {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now(),
        event_type: AuditEventType::MailReceived,
        severity: AuditSeverity::Low,
        user_id: Some(user_id.to_string()),
        tenant_id: Some(organization_id.to_string()),
        session_id: None,
        ip_address: None,
        user_agent: None,
        resource: "device_api".to_string(),
        action: Some(format!("Accessed device '{}' details", device.name)),
        status: "success".to_string(),
        details: Some(json!({
            "device_id": device_id,
            "organization_id": organization_id
        }).to_string()),
        hmac_signature: None,
    };
    audit_manager.log_event(event).await;

    Ok(warp::reply::json(&device))
}

/// [UPDATE DEVICE ENDPOINT] Update Device Configuration
/// @MISSION Modify device settings and metadata.
/// @THREAT Unauthorized device modification.
/// @COUNTERMEASURE Device ownership validation.
/// @AUDIT Device updates are logged with changes.
pub async fn update_device(
    device_service: Arc<DeviceService>,
    audit_manager: Arc<AuditManager>,
    device_id: Uuid,
    organization_id: Uuid,
    user_id: Uuid,
    request: UpdateDeviceRequest,
) -> Result<impl Reply, warp::Rejection> {
    let updated_device = device_service.update_device(
        device_id,
        organization_id,
        request.name,
        request.hostname,
        request.ip_address,
        request.device_type,
        request.connection_type,
        request.vendor,
        request.model,
        request.os_version,
        request.status,
        request.location,
        request.tags,
        request.management_port,
        request.credentials_ref,
        request.metadata,
    ).await.map_err(|e| {
        warp::reject::custom(ApiError::InternalError(e.to_string()))
    })?;

    // Audit device update
    let event = AuditEvent {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now(),
        event_type: AuditEventType::LoginSuccess,
        severity: AuditSeverity::Low,
        user_id: Some(user_id.to_string()),
        tenant_id: Some(organization_id.to_string()),
        session_id: None,
        ip_address: None,
        user_agent: None,
        resource: "device_api".to_string(),
        action: Some(format!("Device '{}' updated", updated_device.name)),
        status: "success".to_string(),
        details: Some(json!({
            "device_id": device_id,
            "organization_id": organization_id
        }).to_string()),
        hmac_signature: None,
    };
    audit_manager.log_event(event).await;

    Ok(warp::reply::json(&updated_device))
}

/// [DELETE DEVICE ENDPOINT] Remove Device from Management
/// @MISSION Delete device entry and associated data.
/// @THREAT Unauthorized device deletion.
/// @COUNTERMEASURE Device ownership validation.
/// @AUDIT Device deletion is logged.
pub async fn delete_device(
    device_service: Arc<DeviceService>,
    audit_manager: Arc<AuditManager>,
    device_id: Uuid,
    organization_id: Uuid,
    user_id: Uuid,
) -> Result<impl Reply, warp::Rejection> {
    let device_name = device_service.get_device(device_id, organization_id).await
        .map(|d| d.name)
        .unwrap_or_else(|_| "unknown".to_string());

    device_service.delete_device(device_id, organization_id).await
        .map_err(|e| {
            warp::reject::custom(ApiError::InternalError(e.to_string()))
        })?;

    // Audit device deletion
    let event = AuditEvent {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now(),
        event_type: AuditEventType::LoginSuccess,
        severity: AuditSeverity::Medium, // Using Medium for Warning
        user_id: Some(user_id.to_string()),
        tenant_id: Some(organization_id.to_string()),
        session_id: None,
        ip_address: None,
        user_agent: None,
        resource: "device_api".to_string(),
        action: Some(format!("Device '{}' deleted", device_name)),
        status: "success".to_string(),
        details: Some(json!({
            "device_id": device_id,
            "organization_id": organization_id
        }).to_string()),
        hmac_signature: None,
    };
    audit_manager.log_event(event).await;

    Ok(warp::reply::json(&json!({"status": "device_deleted"})))
}

/// [EXECUTE COMMAND ENDPOINT] Execute Command on Device
/// @MISSION Run remote command on managed device.
/// @THREAT Unauthorized command execution.
/// @COUNTERMEASURE Device ownership and command validation.
/// @AUDIT All command executions are logged.
pub async fn execute_command(
    device_service: Arc<DeviceService>,
    audit_manager: Arc<AuditManager>,
    device_id: Uuid,
    organization_id: Uuid,
    user_id: Uuid,
    request: ExecuteCommandRequest,
) -> Result<impl Reply, warp::Rejection> {
    let command = device_service.execute_command(
        device_id,
        organization_id,
        user_id,
        request.command,
        request.parameters,
        request.timeout_seconds,
    ).await.map_err(|e| {
        warp::reject::custom(ApiError::InternalError(e.to_string()))
    })?;

    // Audit command execution
    let event = AuditEvent {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now(),
        event_type: AuditEventType::LoginSuccess,
        severity: AuditSeverity::Medium,
        user_id: Some(user_id.to_string()),
        tenant_id: Some(organization_id.to_string()),
        session_id: None,
        ip_address: None,
        user_agent: None,
        resource: "device_api".to_string(),
        action: Some(format!("Command executed on device {}", device_id)),
        status: "success".to_string(),
        details: Some(json!({
            "device_id": device_id,
            "organization_id": organization_id,
            "command_id": command.id,
            "command": request.command
        }).to_string()),
        hmac_signature: None,
    };
    audit_manager.log_event(event).await;

    let response = CommandResponse {
        command_id: command.id,
        status: command.status,
        output: command.output,
        exit_code: command.exit_code,
    };

    Ok(warp::reply::json(&response))
}

/// [GET COMMAND STATUS ENDPOINT] Check Command Execution Status
/// @MISSION Get status of running or completed command.
/// @THREAT Unauthorized command status access.
/// @COUNTERMEASURE Command ownership validation.
/// @AUDIT Command status checks are logged.
pub async fn get_command_status(
    device_service: Arc<DeviceService>,
    audit_manager: Arc<AuditManager>,
    command_id: Uuid,
    organization_id: Uuid,
    user_id: Uuid,
) -> Result<impl Reply, warp::Rejection> {
    let command = device_service.get_command_status(command_id, organization_id).await
        .map_err(|e| {
            warp::reject::custom(ApiError::InternalError(e.to_string()))
        })?;

    // Audit command status check
    let event = AuditEvent {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now(),
        event_type: AuditEventType::MailReceived,
        severity: AuditSeverity::Low,
        user_id: Some(user_id.to_string()),
        tenant_id: Some(organization_id.to_string()),
        session_id: None,
        ip_address: None,
        user_agent: None,
        resource: "device_api".to_string(),
        action: Some(format!("Checked status of command {}", command_id)),
        status: "success".to_string(),
        details: Some(json!({
            "command_id": command_id,
            "organization_id": organization_id,
            "status": format!("{:?}", command.status)
        }).to_string()),
        hmac_signature: None,
    };
    audit_manager.log_event(event).await;

    let response = CommandResponse {
        command_id: command.id,
        status: command.status,
        output: command.output,
        exit_code: command.exit_code,
    };

    Ok(warp::reply::json(&response))
}

/// [GET DEVICE METRICS ENDPOINT] Get Device Performance Metrics
/// @MISSION Retrieve device health and performance data.
/// @THREAT Unauthorized metrics access.
/// @COUNTERMEASURE Device ownership validation.
/// @AUDIT Metrics access is logged.
pub async fn get_device_metrics(
    device_service: Arc<DeviceService>,
    audit_manager: Arc<AuditManager>,
    device_id: Uuid,
    organization_id: Uuid,
    user_id: Uuid,
    limit: Option<usize>,
) -> Result<impl Reply, warp::Rejection> {
    let metrics = device_service.get_device_metrics(device_id, organization_id, limit).await
        .map_err(|e| {
            warp::reject::custom(ApiError::InternalError(e.to_string()))
        })?;

    // Audit metrics access
    let event = AuditEvent {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now(),
        event_type: AuditEventType::MailReceived,
        severity: AuditSeverity::Low,
        user_id: Some(user_id.to_string()),
        tenant_id: Some(organization_id.to_string()),
        session_id: None,
        ip_address: None,
        user_agent: None,
        resource: "device_api".to_string(),
        action: Some(format!("Retrieved metrics for device {}", device_id)),
        status: "success".to_string(),
        details: Some(json!({
            "device_id": device_id,
            "organization_id": organization_id,
            "metrics_count": metrics.len()
        }).to_string()),
        hmac_signature: None,
    };
    audit_manager.log_event(event).await;

    let response = MetricsResponse {
        metrics,
        device_id,
    };

    Ok(warp::reply::json(&response))
}

/// [UPDATE DEVICE STATUS ENDPOINT] Update Device Operational Status
/// @MISSION Change device status (online/offline/maintenance/etc.).
/// @THREAT Unauthorized status changes.
/// @COUNTERMEASURE Device ownership validation.
/// @AUDIT Status changes are logged.
pub async fn update_device_status(
    device_service: Arc<DeviceService>,
    audit_manager: Arc<AuditManager>,
    device_id: Uuid,
    organization_id: Uuid,
    user_id: Uuid,
    status: DeviceStatus,
) -> Result<impl Reply, warp::Rejection> {
    let updated_device = device_service.update_device_status(device_id, organization_id, status).await
        .map_err(|e| {
            warp::reject::custom(ApiError::InternalError(e.to_string()))
        })?;

    // Audit status update
    let event = AuditEvent {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now(),
        event_type: AuditEventType::LoginSuccess,
        severity: AuditSeverity::Low,
        user_id: Some(user_id.to_string()),
        tenant_id: Some(organization_id.to_string()),
        session_id: None,
        ip_address: None,
        user_agent: None,
        resource: "device_api".to_string(),
        action: Some(format!("Device '{}' status updated to {:?}", updated_device.name, status)),
        status: "success".to_string(),
        details: Some(json!({
            "device_id": device_id,
            "organization_id": organization_id,
            "new_status": format!("{:?}", status)
        }).to_string()),
        hmac_signature: None,
    };
    audit_manager.log_event(event).await;

    Ok(warp::reply::json(&updated_device))
}