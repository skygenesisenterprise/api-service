// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: PowerAdmin Controller
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | SENSITIVE
//  MISSION: Provide REST API endpoints for PowerAdmin DNS management operations
//  including zone creation, record management, and DNSSEC configuration.
//  NOTICE: These endpoints enable programmatic DNS management through
//  the Sky Genesis API for automated infrastructure setup.
//  DNS: Zone management, record operations, DNSSEC
//  INTEGRATION: PowerAdmin HTTP API, PowerDNS backend
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use std::sync::Arc;
use warp::Filter;
use serde::{Deserialize, Serialize};
use crate::services::poweradmin_service::{PowerAdminService, PowerAdminZone, PowerAdminRecord};

/// [POWERADMIN HEALTH RESPONSE] Health Check Result
/// @MISSION Report PowerAdmin service availability.
/// @THREAT Undetected PowerAdmin connectivity issues.
/// @COUNTERMEASURE Structured health response.
/// @AUDIT Health checks logged for monitoring.
#[derive(Debug, Serialize, Deserialize)]
pub struct PowerAdminHealthResponse {
    pub healthy: bool,
    pub message: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// [CREATE ZONE REQUEST] Zone Creation Payload
/// @MISSION Define zone creation request structure.
/// @THREAT Invalid zone configuration.
/// @COUNTERMEASURE Validated request payload.
/// @AUDIT Zone creation requests logged.
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateZoneRequest {
    pub name: String,
    pub r#type: String, // MASTER, SLAVE, NATIVE
    pub nameservers: Option<Vec<String>>,
    pub template: Option<String>,
}

/// [CREATE RECORD REQUEST] Record Creation Payload
/// @MISSION Define record creation request structure.
/// @THREAT Invalid record configuration.
/// @COUNTERMEASURE Validated request payload.
/// @AUDIT Record creation requests logged.
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateRecordRequest {
    pub name: String,
    pub r#type: String,
    pub content: String,
    pub ttl: Option<i32>,
    pub prio: Option<i32>,
    pub disabled: Option<bool>,
}

/// [POWERADMIN CONTROLLER] API Endpoints for PowerAdmin DNS Management
/// @MISSION Provide RESTful interface for PowerAdmin operations.
/// @THREAT Manual DNS configuration overhead.
/// @COUNTERMEASURE Automated API-based configuration.
/// @DEPENDENCY PowerAdmin service must be initialized.
/// @PERFORMANCE Endpoints optimized for DNS operations.
/// @AUDIT All PowerAdmin operations logged and traced.
pub fn poweradmin_routes(
    poweradmin_service: Arc<PowerAdminService>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    // Health check endpoint
    let health = warp::path!("api" / "v1" / "poweradmin" / "health")
        .and(warp::get())
        .and_then({
            let poweradmin_service = Arc::clone(&poweradmin_service);
            move || {
                let poweradmin_service = Arc::clone(&poweradmin_service);
                async move {
                    match poweradmin_service.health_check().await {
                        Ok(healthy) => {
                            let response = PowerAdminHealthResponse {
                                healthy,
                                message: if healthy { "PowerAdmin service is healthy".to_string() } else { "PowerAdmin service is unhealthy".to_string() },
                                timestamp: chrono::Utc::now(),
                            };
                            Ok::<_, warp::Rejection>(warp::reply::json(&response))
                        },
                        Err(e) => {
                            let response = PowerAdminHealthResponse {
                                healthy: false,
                                message: format!("Health check failed: {}", e),
                                timestamp: chrono::Utc::now(),
                            };
                            Ok(warp::reply::json(&response))
                        }
                    }
                }
            }
        });

    // List zones endpoint
    let list_zones = warp::path!("api" / "v1" / "poweradmin" / "zones")
        .and(warp::get())
        .and_then({
            let poweradmin_service = Arc::clone(&poweradmin_service);
            move || {
                let poweradmin_service = Arc::clone(&poweradmin_service);
                async move {
                    match poweradmin_service.list_zones().await {
                        Ok(zones) => Ok::<_, warp::Rejection>(warp::reply::json(&zones)),
                        Err(e) => Ok(warp::reply::json(&serde_json::json!({
                            "error": format!("Failed to list zones: {}", e),
                            "timestamp": chrono::Utc::now()
                        })))
                    }
                }
            }
        });

    // Get zone endpoint
    let get_zone = warp::path!("api" / "v1" / "poweradmin" / "zones" / String)
        .and(warp::get())
        .and_then({
            let poweradmin_service = Arc::clone(&poweradmin_service);
            move |zone_id: String| {
                let poweradmin_service = Arc::clone(&poweradmin_service);
                async move {
                    match poweradmin_service.get_zone(&zone_id).await {
                        Ok(zone) => Ok::<_, warp::Rejection>(warp::reply::json(&zone)),
                        Err(e) => Ok(warp::reply::json(&serde_json::json!({
                            "error": format!("Failed to get zone: {}", e),
                            "timestamp": chrono::Utc::now()
                        })))
                    }
                }
            }
        });

    // Create zone endpoint
    let create_zone = warp::path!("api" / "v1" / "poweradmin" / "zones")
        .and(warp::post())
        .and(warp::body::json())
        .and_then({
            let poweradmin_service = Arc::clone(&poweradmin_service);
            move |request: CreateZoneRequest| {
                let poweradmin_service = Arc::clone(&poweradmin_service);
                async move {
                    let zone = PowerAdminZone {
                        name: request.name,
                        r#type: request.r#type,
                        nameservers: request.nameservers,
                        template: request.template,
                    };

                    match poweradmin_service.create_zone(zone).await {
                        Ok(result) => Ok::<_, warp::Rejection>(warp::reply::json(&result)),
                        Err(e) => Ok(warp::reply::json(&serde_json::json!({
                            "error": format!("Failed to create zone: {}", e),
                            "timestamp": chrono::Utc::now()
                        })))
                    }
                }
            }
        });

    // Update zone endpoint
    let update_zone = warp::path!("api" / "v1" / "poweradmin" / "zones" / String)
        .and(warp::put())
        .and(warp::body::json())
        .and_then({
            let poweradmin_service = Arc::clone(&poweradmin_service);
            move |zone_id: String, request: CreateZoneRequest| {
                let poweradmin_service = Arc::clone(&poweradmin_service);
                async move {
                    let zone = PowerAdminZone {
                        name: request.name,
                        r#type: request.r#type,
                        nameservers: request.nameservers,
                        template: request.template,
                    };

                    match poweradmin_service.update_zone(&zone_id, zone).await {
                        Ok(result) => Ok::<_, warp::Rejection>(warp::reply::json(&result)),
                        Err(e) => Ok(warp::reply::json(&serde_json::json!({
                            "error": format!("Failed to update zone: {}", e),
                            "timestamp": chrono::Utc::now()
                        })))
                    }
                }
            }
        });

    // Delete zone endpoint
    let delete_zone = warp::path!("api" / "v1" / "poweradmin" / "zones" / String)
        .and(warp::delete())
        .and_then({
            let poweradmin_service = Arc::clone(&poweradmin_service);
            move |zone_id: String| {
                let poweradmin_service = Arc::clone(&poweradmin_service);
                async move {
                    match poweradmin_service.delete_zone(&zone_id).await {
                        Ok(()) => Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "message": "Zone deleted successfully",
                            "timestamp": chrono::Utc::now()
                        }))),
                        Err(e) => Ok(warp::reply::json(&serde_json::json!({
                            "error": format!("Failed to delete zone: {}", e),
                            "timestamp": chrono::Utc::now()
                        })))
                    }
                }
            }
        });

    // List records endpoint
    let list_records = warp::path!("api" / "v1" / "poweradmin" / "zones" / String / "records")
        .and(warp::get())
        .and_then({
            let poweradmin_service = Arc::clone(&poweradmin_service);
            move |zone_id: String| {
                let poweradmin_service = Arc::clone(&poweradmin_service);
                async move {
                    match poweradmin_service.list_records(&zone_id).await {
                        Ok(records) => Ok::<_, warp::Rejection>(warp::reply::json(&records)),
                        Err(e) => Ok(warp::reply::json(&serde_json::json!({
                            "error": format!("Failed to list records: {}", e),
                            "timestamp": chrono::Utc::now()
                        })))
                    }
                }
            }
        });

    // Get record endpoint
    let get_record = warp::path!("api" / "v1" / "poweradmin" / "records" / String)
        .and(warp::get())
        .and_then({
            let poweradmin_service = Arc::clone(&poweradmin_service);
            move |record_id: String| {
                let poweradmin_service = Arc::clone(&poweradmin_service);
                async move {
                    match poweradmin_service.get_record(&record_id).await {
                        Ok(record) => Ok::<_, warp::Rejection>(warp::reply::json(&record)),
                        Err(e) => Ok(warp::reply::json(&serde_json::json!({
                            "error": format!("Failed to get record: {}", e),
                            "timestamp": chrono::Utc::now()
                        })))
                    }
                }
            }
        });

    // Create record endpoint
    let create_record = warp::path!("api" / "v1" / "poweradmin" / "zones" / String / "records")
        .and(warp::post())
        .and(warp::body::json())
        .and_then({
            let poweradmin_service = Arc::clone(&poweradmin_service);
            move |zone_id: String, request: CreateRecordRequest| {
                let poweradmin_service = Arc::clone(&poweradmin_service);
                async move {
                    let record = PowerAdminRecord {
                        name: request.name,
                        r#type: request.r#type,
                        content: request.content,
                        ttl: request.ttl.unwrap_or(3600),
                        prio: request.prio,
                        disabled: request.disabled.unwrap_or(false),
                    };

                    match poweradmin_service.create_record(&zone_id, record).await {
                        Ok(result) => Ok::<_, warp::Rejection>(warp::reply::json(&result)),
                        Err(e) => Ok(warp::reply::json(&serde_json::json!({
                            "error": format!("Failed to create record: {}", e),
                            "timestamp": chrono::Utc::now()
                        })))
                    }
                }
            }
        });

    // Update record endpoint
    let update_record = warp::path!("api" / "v1" / "poweradmin" / "records" / String)
        .and(warp::put())
        .and(warp::body::json())
        .and_then({
            let poweradmin_service = Arc::clone(&poweradmin_service);
            move |record_id: String, request: CreateRecordRequest| {
                let poweradmin_service = Arc::clone(&poweradmin_service);
                async move {
                    let record = PowerAdminRecord {
                        name: request.name,
                        r#type: request.r#type,
                        content: request.content,
                        ttl: request.ttl.unwrap_or(3600),
                        prio: request.prio,
                        disabled: request.disabled.unwrap_or(false),
                    };

                    match poweradmin_service.update_record(&record_id, record).await {
                        Ok(result) => Ok::<_, warp::Rejection>(warp::reply::json(&result)),
                        Err(e) => Ok(warp::reply::json(&serde_json::json!({
                            "error": format!("Failed to update record: {}", e),
                            "timestamp": chrono::Utc::now()
                        })))
                    }
                }
            }
        });

    // Delete record endpoint
    let delete_record = warp::path!("api" / "v1" / "poweradmin" / "records" / String)
        .and(warp::delete())
        .and_then({
            let poweradmin_service = Arc::clone(&poweradmin_service);
            move |record_id: String| {
                let poweradmin_service = Arc::clone(&poweradmin_service);
                async move {
                    match poweradmin_service.delete_record(&record_id).await {
                        Ok(()) => Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "message": "Record deleted successfully",
                            "timestamp": chrono::Utc::now()
                        }))),
                        Err(e) => Ok(warp::reply::json(&serde_json::json!({
                            "error": format!("Failed to delete record: {}", e),
                            "timestamp": chrono::Utc::now()
                        })))
                    }
                }
            }
        });

    // Combine all routes
    health
        .or(list_zones)
        .or(get_zone)
        .or(create_zone)
        .or(update_zone)
        .or(delete_zone)
        .or(list_records)
        .or(get_record)
        .or(create_record)
        .or(update_record)
        .or(delete_record)
}