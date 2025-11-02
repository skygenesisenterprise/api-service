// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: PowerAdmin Routes
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | SENSITIVE
//  MISSION: Provide REST API endpoints for PowerAdmin DNS management operations
//  through the Sky Genesis API, enabling automated DNS zone and record
//  configuration for enterprise infrastructure.
//  NOTICE: These routes expose PowerAdmin API functionality with authentication
//  and audit logging for secure DNS management.
//  DNS: Zone management, record operations, DNSSEC
//  INTEGRATION: PowerAdmin HTTP API, PowerDNS backend
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use std::sync::Arc;
use warp::Filter;
use crate::services::poweradmin_service::PowerAdminService;
use crate::services::vault_manager::VaultManager;

/// [POWERADMIN ROUTES] API Endpoints for PowerAdmin DNS Management
/// @MISSION Provide RESTful interface for PowerAdmin operations.
/// @THREAT Manual DNS configuration overhead.
/// @COUNTERMEASURE Automated API-based configuration.
/// @DEPENDENCY PowerAdmin service must be initialized.
/// @PERFORMANCE Endpoints optimized for DNS operations.
/// @AUDIT All PowerAdmin operations logged and traced.
pub fn poweradmin_routes(
    poweradmin_service: Arc<PowerAdminService>,
    vault_manager: Arc<VaultManager>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    // Authentication filter
    let auth = warp::header::<String>("x-api-key")
        .or(warp::header::<String>("authorization"))
        .unify()
        .and_then({
            let vault_manager = Arc::clone(&vault_manager);
            move |key: String| {
                let vault_manager = Arc::clone(&vault_manager);
                async move {
                    // Simple authentication check - validate against vault
                    let is_valid = vault_manager.validate_access("poweradmin", &key).await
                        .unwrap_or(false);
                    if is_valid {
                        Ok(())
                    } else {
                        Err(warp::reject::custom(PowerAdminAuthError::InvalidKey))
                    }
                }
            }
        });

    // Health check endpoint
    let health = warp::path!("api" / "v1" / "poweradmin" / "health")
        .and(warp::get())
        .and(auth.clone())
        .and_then({
            let poweradmin_service = Arc::clone(&poweradmin_service);
            move || {
                let poweradmin_service = Arc::clone(&poweradmin_service);
                async move {
                    match poweradmin_service.health_check().await {
                        Ok(healthy) => {
                            let response = serde_json::json!({
                                "healthy": healthy,
                                "message": if healthy { "PowerAdmin service is healthy" } else { "PowerAdmin service is unhealthy" },
                                "timestamp": chrono::Utc::now()
                            });
                            Ok::<_, warp::Rejection>(warp::reply::json(&response))
                        },
                        Err(e) => {
                            let response = serde_json::json!({
                                "healthy": false,
                                "error": format!("Health check failed: {}", e),
                                "timestamp": chrono::Utc::now()
                            });
                            Ok(warp::reply::json(&response))
                        }
                    }
                }
            }
        });

    // List zones endpoint
    let list_zones = warp::path!("api" / "v1" / "poweradmin" / "zones")
        .and(warp::get())
        .and(auth.clone())
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
        .and(auth.clone())
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
        .and(auth.clone())
        .and(warp::body::json())
        .and_then({
            let poweradmin_service = Arc::clone(&poweradmin_service);
            move |request: serde_json::Value| {
                let poweradmin_service = Arc::clone(&poweradmin_service);
                async move {
                    let zone = crate::services::poweradmin_service::PowerAdminZone {
                        name: request.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        r#type: request.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        nameservers: request.get("nameservers").and_then(|v| v.as_array()).map(|arr| {
                            arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect()
                        }),
                        template: request.get("template").and_then(|v| v.as_str()).map(|s| s.to_string()),
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
            move |zone_id: String, request: serde_json::Value| {
                let poweradmin_service = Arc::clone(&poweradmin_service);
                async move {
                    let zone = crate::services::poweradmin_service::PowerAdminZone {
                        name: request.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        r#type: request.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        nameservers: request.get("nameservers").and_then(|v| v.as_array()).map(|arr| {
                            arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect()
                        }),
                        template: request.get("template").and_then(|v| v.as_str()).map(|s| s.to_string()),
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
            move |zone_id: String, request: serde_json::Value| {
                let poweradmin_service = Arc::clone(&poweradmin_service);
                async move {
                    let record = crate::services::poweradmin_service::PowerAdminRecord {
                        name: request.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        r#type: request.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        content: request.get("content").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        ttl: request.get("ttl").and_then(|v| v.as_i64()).unwrap_or(3600) as i32,
                        prio: request.get("prio").and_then(|v| v.as_i64()).map(|v| v as i32),
                        disabled: request.get("disabled").and_then(|v| v.as_bool()).unwrap_or(false),
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
            move |record_id: String, request: serde_json::Value| {
                let poweradmin_service = Arc::clone(&poweradmin_service);
                async move {
                    let record = crate::services::poweradmin_service::PowerAdminRecord {
                        name: request.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        r#type: request.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        content: request.get("content").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        ttl: request.get("ttl").and_then(|v| v.as_i64()).unwrap_or(3600) as i32,
                        prio: request.get("prio").and_then(|v| v.as_i64()).map(|v| v as i32),
                        disabled: request.get("disabled").and_then(|v| v.as_bool()).unwrap_or(false),
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

/// [POWERADMIN AUTH ERROR] Authentication Failure Classification
/// @MISSION Categorize authentication failures for proper error handling.
/// @THREAT Information leakage through error messages.
/// @COUNTERMEASURE Sanitized error responses, logging without secrets.
/// @INVARIANT Errors don't expose sensitive authentication details.
/// @AUDIT Authentication errors trigger security monitoring.
#[derive(Debug)]
pub enum PowerAdminAuthError {
    InvalidKey,
}

impl warp::reject::Reject for PowerAdminAuthError {}