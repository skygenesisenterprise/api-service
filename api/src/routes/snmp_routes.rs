// SNMP Routes - REST API endpoints for SNMP operations
// This module provides HTTP endpoints for SNMP management and monitoring

use warp::Filter;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use crate::core::snmp_manager::{SnmpManager, SnmpQueryRequest, SnmpQueryResponse, SnmpError};
use crate::core::snmp_agent::{SnmpAgent, SgeMib};
use crate::core::snmp_trap_listener::{SnmpTrapListener, SnmpTrap};
use crate::middlewares::auth_middleware::{jwt_auth, Claims};
use crate::core::vault::VaultClient;
use crate::core::audit_manager::{AuditManager, AuditEventType, AuditSeverity};

/// SNMP Query Request for REST API
#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
pub struct SnmpQueryApiRequest {
    /// Target IP address or hostname
    pub target: String,
    /// SNMP port (default: 161)
    #[serde(default = "default_port")]
    pub port: u16,
    /// SNMP version
    #[serde(default)]
    pub version: SnmpApiVersion,
    /// Community string (for v1/v2c)
    pub community: Option<String>,
    /// OID to query
    pub oid: String,
    /// Timeout in seconds
    pub timeout: Option<u64>,
}

/// SNMP Version for API
#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
pub enum SnmpApiVersion {
    #[serde(rename = "v1")]
    V1,
    #[serde(rename = "v2c")]
    V2c,
    #[serde(rename = "v3")]
    V3,
}

impl Default for SnmpApiVersion {
    fn default() -> Self {
        SnmpApiVersion::V2c
    }
}

/// SNMP Query Response for REST API
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SnmpQueryApiResponse {
    /// Success status
    pub success: bool,
    /// Query result
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<SnmpQueryResponse>,
    /// Error message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// SNMP MIB List Response
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SnmpMibListResponse {
    /// Available MIBs
    pub mibs: Vec<SnmpMibInfo>,
}

/// SNMP MIB Information
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SnmpMibInfo {
    /// MIB name
    pub name: String,
    /// Base OID
    pub base_oid: String,
    /// Description
    pub description: String,
    /// Available OIDs
    pub oids: Vec<SnmpOidInfo>,
}

/// SNMP OID Information
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SnmpOidInfo {
    /// OID string
    pub oid: String,
    /// Human-readable name
    pub name: String,
    /// Description
    pub description: String,
    /// Data type
    pub data_type: String,
}

/// SNMP Trap Log Response
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SnmpTrapLogResponse {
    /// List of recent traps
    pub traps: Vec<SnmpTrap>,
    /// Total count
    pub total_count: u64,
}

/// SNMP Configuration Request
#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
pub struct SnmpConfigRequest {
    /// Community strings
    pub community_strings: Option<Vec<String>>,
    /// Allowed sources (IP ranges)
    pub allowed_sources: Option<Vec<String>>,
    /// Trap listener port
    pub trap_port: Option<u16>,
    /// Enable/disable trap listener
    pub trap_enabled: Option<bool>,
}

fn default_port() -> u16 {
    161
}

/// Convert API version to internal version
fn convert_api_version(api_version: &SnmpApiVersion) -> crate::core::snmp_manager::SnmpVersion {
    match api_version {
        SnmpApiVersion::V1 => crate::core::snmp_manager::SnmpVersion::V1,
        SnmpApiVersion::V2c => crate::core::snmp_manager::SnmpVersion::V2c,
        SnmpApiVersion::V3 => crate::core::snmp_manager::SnmpVersion::V3,
    }
}

/// SNMP routes configuration
pub fn snmp_routes(
    snmp_manager: Arc<SnmpManager>,
    snmp_agent: Arc<SnmpAgent>,
    trap_listener: Arc<SnmpTrapListener>,
    audit_manager: Arc<AuditManager>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let snmp_base = warp::path("api")
        .and(warp::path("v1"))
        .and(warp::path("snmp"));

    // SNMP Query endpoint
    let query = snmp_base
        .and(warp::path("query"))
        .and(warp::post())
        .and(warp::body::json())
        .and(with_snmp_manager(snmp_manager.clone()))
        .and(with_audit_manager(audit_manager.clone()))
        .and(jwt_auth())
        .and_then(handle_snmp_query);

    // SNMP MIB list endpoint
    let mibs = snmp_base
        .and(warp::path("mibs"))
        .and(warp::get())
        .and(with_snmp_agent(snmp_agent.clone()))
        .and(jwt_auth())
        .and_then(handle_snmp_mibs);

    // SNMP Trap log endpoint
    let traps = snmp_base
        .and(warp::path("traps"))
        .and(warp::get())
        .and(warp::query::<TrapQueryParams>())
        .and(with_trap_listener(trap_listener.clone()))
        .and(with_audit_manager(audit_manager.clone()))
        .and(jwt_auth())
        .and_then(handle_snmp_traps);

    // SNMP Configuration endpoint
    let config = snmp_base
        .and(warp::path("config"))
        .and(warp::get())
        .and(with_trap_listener(trap_listener.clone()))
        .and(jwt_auth())
        .and_then(handle_get_snmp_config);

    let update_config = snmp_base
        .and(warp::path("config"))
        .and(warp::post())
        .and(warp::body::json())
        .and(with_trap_listener(trap_listener.clone()))
        .and(with_audit_manager(audit_manager.clone()))
        .and(jwt_auth())
        .and_then(handle_update_snmp_config);

    // SNMP Agent status endpoint
    let agent_status = snmp_base
        .and(warp::path("agent"))
        .and(warp::path("status"))
        .and(warp::get())
        .and(with_snmp_agent(snmp_agent.clone()))
        .and(jwt_auth())
        .and_then(handle_agent_status);

    // Combine all routes
    query
        .or(mibs)
        .or(traps)
        .or(config)
        .or(update_config)
        .or(agent_status)
}

/// Handle SNMP query requests
#[utoipa::path(
    post,
    path = "/api/v1/snmp/query",
    request_body = SnmpQueryApiRequest,
    responses(
        (status = 200, description = "SNMP query successful", body = SnmpQueryApiResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("jwt" = []))
)]
async fn handle_snmp_query(
    request: SnmpQueryApiRequest,
    snmp_manager: Arc<SnmpManager>,
    audit_manager: Arc<AuditManager>,
    claims: Claims,
) -> Result<impl warp::Reply, warp::Rejection> {
    // Convert API request to internal format
    let internal_request = SnmpQueryRequest {
        target: request.target.clone(),
        port: request.port,
        version: convert_api_version(&request.version),
        community: request.community,
        oid: request.oid.clone(),
        timeout: request.timeout,
    };

    // Audit the query attempt
    audit_manager.audit_event(
        AuditEventType::Access,
        AuditSeverity::Info,
        Some(&claims.sub),
        "snmp_api",
        &format!("SNMP query to {}:{} for OID {}", request.target, request.port, request.oid),
        None,
    ).await;

    // Execute query
    match snmp_manager.get(internal_request).await {
        Ok(result) => {
            let response = SnmpQueryApiResponse {
                success: true,
                result: Some(result),
                error: None,
            };
            Ok(warp::reply::json(&response))
        }
        Err(e) => {
            // Audit failed query
            audit_manager.audit_event(
                AuditEventType::Access,
                AuditSeverity::Warning,
                Some(&claims.sub),
                "snmp_api",
                &format!("SNMP query failed to {}: {}", request.target, e),
                None,
            ).await;

            let response = SnmpQueryApiResponse {
                success: false,
                result: None,
                error: Some(e.to_string()),
            };
            Ok(warp::reply::json(&response))
        }
    }
}

/// Handle SNMP MIB list requests
#[utoipa::path(
    get,
    path = "/api/v1/snmp/mibs",
    responses(
        (status = 200, description = "MIB list retrieved", body = SnmpMibListResponse),
        (status = 401, description = "Unauthorized")
    ),
    security(("jwt" = []))
)]
async fn handle_snmp_mibs(
    snmp_agent: Arc<SnmpAgent>,
    _claims: Claims,
) -> Result<impl warp::Reply, warp::Rejection> {
    // Get current MIB data to show available OIDs
    let mib = snmp_agent.get_mib().await;

    let sge_mib = SnmpMibInfo {
        name: "SGE-MIB".to_string(),
        base_oid: "1.3.6.1.4.1.8072.1.3.2.3".to_string(),
        description: "Sky Genesis Enterprise MIB for API monitoring".to_string(),
        oids: vec![
            SnmpOidInfo {
                oid: "1.3.6.1.4.1.8072.1.3.2.3.1.1.1.1".to_string(),
                name: "sgeApiStatus".to_string(),
                description: "Current API operational status".to_string(),
                data_type: "String".to_string(),
            },
            SnmpOidInfo {
                oid: "1.3.6.1.4.1.8072.1.3.2.3.1.1.2.1".to_string(),
                name: "sgeApiUptime".to_string(),
                description: "API uptime in seconds".to_string(),
                data_type: "Counter32".to_string(),
            },
            SnmpOidInfo {
                oid: "1.3.6.1.4.1.8072.1.3.2.3.1.1.4.1".to_string(),
                name: "sgeActiveConnections".to_string(),
                description: "Number of active connections".to_string(),
                data_type: "Gauge32".to_string(),
            },
            SnmpOidInfo {
                oid: "1.3.6.1.4.1.8072.1.3.2.3.1.1.5.1".to_string(),
                name: "sgeMemoryUsage".to_string(),
                description: "Memory usage in MB".to_string(),
                data_type: "Gauge32".to_string(),
            },
        ],
    };

    let response = SnmpMibListResponse {
        mibs: vec![sge_mib],
    };

    Ok(warp::reply::json(&response))
}

/// Query parameters for trap log
#[derive(Debug, Deserialize)]
struct TrapQueryParams {
    limit: Option<usize>,
    offset: Option<usize>,
}

/// Handle SNMP trap log requests
#[utoipa::path(
    get,
    path = "/api/v1/snmp/traps",
    params(
        ("limit" = Option<usize>, Query, description = "Maximum number of traps to return"),
        ("offset" = Option<usize>, Query, description = "Offset for pagination")
    ),
    responses(
        (status = 200, description = "Trap log retrieved", body = SnmpTrapLogResponse),
        (status = 401, description = "Unauthorized")
    ),
    security(("jwt" = []))
)]
async fn handle_snmp_traps(
    params: TrapQueryParams,
    trap_listener: Arc<SnmpTrapListener>,
    audit_manager: Arc<AuditManager>,
    claims: Claims,
) -> Result<impl warp::Reply, warp::Rejection> {
    // In a real implementation, traps would be stored in a database
    // For now, return empty list
    let traps = Vec::new();

    // Audit trap log access
    audit_manager.audit_event(
        AuditEventType::Access,
        AuditSeverity::Info,
        Some(&claims.sub),
        "snmp_api",
        "SNMP trap log accessed",
        None,
    ).await;

    let response = SnmpTrapLogResponse {
        traps,
        total_count: 0,
    };

    Ok(warp::reply::json(&response))
}

/// Handle get SNMP configuration
async fn handle_get_snmp_config(
    trap_listener: Arc<SnmpTrapListener>,
    _claims: Claims,
) -> Result<impl warp::Reply, warp::Rejection> {
    let config = trap_listener.get_config();
    Ok(warp::reply::json(config))
}

/// Handle update SNMP configuration
async fn handle_update_snmp_config(
    request: SnmpConfigRequest,
    mut trap_listener: Arc<SnmpTrapListener>,
    audit_manager: Arc<AuditManager>,
    claims: Claims,
) -> Result<impl warp::Reply, warp::Rejection> {
    // Update configuration
    let mut current_config = trap_listener.get_config().clone();

    if let Some(community_strings) = request.community_strings {
        // In a real implementation, validate and update community strings
        // For security, this should be done through Vault
    }

    if let Some(allowed_sources) = request.allowed_sources {
        current_config.allowed_sources = allowed_sources;
    }

    if let Some(trap_port) = request.trap_port {
        current_config.port = trap_port;
    }

    if let Some(trap_enabled) = request.trap_enabled {
        current_config.enabled = trap_enabled;
    }

    // Update the configuration
    Arc::get_mut(&mut trap_listener).unwrap().update_config(current_config);

    // Audit configuration change
    audit_manager.audit_event(
        AuditEventType::Security,
        AuditSeverity::Info,
        Some(&claims.sub),
        "snmp_api",
        "SNMP configuration updated",
        None,
    ).await;

    Ok(warp::reply::json(&serde_json::json!({"status": "configuration_updated"})))
}

/// Handle SNMP agent status
async fn handle_agent_status(
    snmp_agent: Arc<SnmpAgent>,
    _claims: Claims,
) -> Result<impl warp::Reply, warp::Rejection> {
    let mib = snmp_agent.get_mib().await;

    let status = serde_json::json!({
        "agent_status": "running",
        "mib_data": mib,
        "supported_oids": [
            "1.3.6.1.4.1.8072.1.3.2.3.1.1.1.1",  // sgeApiStatus
            "1.3.6.1.4.1.8072.1.3.2.3.1.1.2.1",  // sgeApiUptime
            "1.3.6.1.4.1.8072.1.3.2.3.1.1.4.1",  // sgeActiveConnections
            "1.3.6.1.4.1.8072.1.3.2.3.1.1.5.1"   // sgeMemoryUsage
        ]
    });

    Ok(warp::reply::json(&status))
}

// Helper functions for dependency injection
fn with_snmp_manager(
    snmp_manager: Arc<SnmpManager>,
) -> impl Filter<Extract = (Arc<SnmpManager>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || snmp_manager.clone())
}

fn with_snmp_agent(
    snmp_agent: Arc<SnmpAgent>,
) -> impl Filter<Extract = (Arc<SnmpAgent>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || snmp_agent.clone())
}

fn with_trap_listener(
    trap_listener: Arc<SnmpTrapListener>,
) -> impl Filter<Extract = (Arc<SnmpTrapListener>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || trap_listener.clone())
}

fn with_audit_manager(
    audit_manager: Arc<AuditManager>,
) -> impl Filter<Extract = (Arc<AuditManager>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || audit_manager.clone())
}