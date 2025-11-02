// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Grafana Routes
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | SENSITIVE
//  MISSION: Provide REST API endpoints for Grafana management operations
//  through the Sky Genesis API, enabling automated dashboard and datasource
//  configuration for enterprise monitoring.
//  NOTICE: These routes expose Grafana API functionality with authentication
//  and audit logging for secure monitoring setup.
//  MONITORING: Grafana dashboard management, datasource configuration
//  INTEGRATION: Grafana HTTP API, monitoring dashboards
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use std::sync::Arc;
use warp::Filter;
use crate::services::grafana_service::GrafanaService;

/// [GRAFANA ROUTES] API Endpoints for Grafana Management
/// @MISSION Provide RESTful interface for Grafana operations.
/// @THREAT Manual Grafana configuration overhead.
/// @COUNTERMEASURE Automated API-based configuration.
/// @DEPENDENCY Grafana service must be initialized.
/// @PERFORMANCE Endpoints optimized for management operations.
/// @AUDIT All Grafana operations logged and traced.
pub fn grafana_routes(
    grafana_service: Arc<GrafanaService>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    // Health check endpoint
    let health = warp::path!("api" / "v1" / "grafana" / "health")
        .and(warp::get())
        .and_then({
            let grafana_service = Arc::clone(&grafana_service);
            move || {
                let grafana_service = Arc::clone(&grafana_service);
                async move {
                    match grafana_service.health_check().await {
                        Ok(healthy) => {
                            let response = serde_json::json!({
                                "healthy": healthy,
                                "message": if healthy { "Grafana service is healthy" } else { "Grafana service is unhealthy" },
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

    // Create dashboard endpoint
    let create_dashboard = warp::path!("api" / "v1" / "grafana" / "dashboards")
        .and(warp::post())
        .and(warp::body::json())
        .and_then({
            let grafana_service = Arc::clone(&grafana_service);
            move |request: serde_json::Value| {
                let grafana_service = Arc::clone(&grafana_service);
                async move {
                    // Extract dashboard fields from request
                    let dashboard = request.get("dashboard").cloned().unwrap_or(serde_json::Value::Null);
                    let folder_id = request.get("folder_id").and_then(|v| v.as_i64());
                    let overwrite = request.get("overwrite").and_then(|v| v.as_bool()).unwrap_or(false);

                    let grafana_dashboard = crate::services::grafana_service::GrafanaDashboard {
                        dashboard,
                        folder_id,
                        overwrite,
                    };

                    match grafana_service.create_dashboard(grafana_dashboard).await {
                        Ok(result) => Ok::<_, warp::Rejection>(warp::reply::json(&result)),
                        Err(e) => Ok(warp::reply::json(&serde_json::json!({
                            "error": format!("Failed to create dashboard: {}", e),
                            "timestamp": chrono::Utc::now()
                        })))
                    }
                }
            }
        });

    // List dashboards endpoint
    let list_dashboards = warp::path!("api" / "v1" / "grafana" / "dashboards")
        .and(warp::get())
        .and_then({
            let grafana_service = Arc::clone(&grafana_service);
            move || {
                let grafana_service = Arc::clone(&grafana_service);
                async move {
                    match grafana_service.list_dashboards().await {
                        Ok(dashboards) => Ok::<_, warp::Rejection>(warp::reply::json(&dashboards)),
                        Err(e) => Ok(warp::reply::json(&serde_json::json!({
                            "error": format!("Failed to list dashboards: {}", e),
                            "timestamp": chrono::Utc::now()
                        })))
                    }
                }
            }
        });

    // Get dashboard endpoint
    let get_dashboard = warp::path!("api" / "v1" / "grafana" / "dashboards" / String)
        .and(warp::get())
        .and_then({
            let grafana_service = Arc::clone(&grafana_service);
            move |uid: String| {
                let grafana_service = Arc::clone(&grafana_service);
                async move {
                    match grafana_service.get_dashboard(&uid).await {
                        Ok(dashboard) => Ok::<_, warp::Rejection>(warp::reply::json(&dashboard)),
                        Err(e) => Ok(warp::reply::json(&serde_json::json!({
                            "error": format!("Failed to get dashboard: {}", e),
                            "timestamp": chrono::Utc::now()
                        })))
                    }
                }
            }
        });

    // Update dashboard endpoint
    let update_dashboard = warp::path!("api" / "v1" / "grafana" / "dashboards" / String)
        .and(warp::put())
        .and(warp::body::json())
        .and_then({
            let grafana_service = Arc::clone(&grafana_service);
            move |uid: String, request: serde_json::Value| {
                let grafana_service = Arc::clone(&grafana_service);
                async move {
                    let dashboard = request.get("dashboard").cloned().unwrap_or(serde_json::Value::Null);
                    let folder_id = request.get("folder_id").and_then(|v| v.as_i64());
                    let overwrite = request.get("overwrite").and_then(|v| v.as_bool()).unwrap_or(true);

                    let grafana_dashboard = crate::services::grafana_service::GrafanaDashboard {
                        dashboard,
                        folder_id,
                        overwrite,
                    };

                    match grafana_service.update_dashboard(&uid, grafana_dashboard).await {
                        Ok(result) => Ok::<_, warp::Rejection>(warp::reply::json(&result)),
                        Err(e) => Ok(warp::reply::json(&serde_json::json!({
                            "error": format!("Failed to update dashboard: {}", e),
                            "timestamp": chrono::Utc::now()
                        })))
                    }
                }
            }
        });

    // Delete dashboard endpoint
    let delete_dashboard = warp::path!("api" / "v1" / "grafana" / "dashboards" / String)
        .and(warp::delete())
        .and_then({
            let grafana_service = Arc::clone(&grafana_service);
            move |uid: String| {
                let grafana_service = Arc::clone(&grafana_service);
                async move {
                    match grafana_service.delete_dashboard(&uid).await {
                        Ok(()) => Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "message": "Dashboard deleted successfully",
                            "timestamp": chrono::Utc::now()
                        }))),
                        Err(e) => Ok(warp::reply::json(&serde_json::json!({
                            "error": format!("Failed to delete dashboard: {}", e),
                            "timestamp": chrono::Utc::now()
                        })))
                    }
                }
            }
        });

    // Create datasource endpoint
    let create_datasource = warp::path!("api" / "v1" / "grafana" / "datasources")
        .and(warp::post())
        .and(warp::body::json())
        .and_then({
            let grafana_service = Arc::clone(&grafana_service);
            move |request: serde_json::Value| {
                let grafana_service = Arc::clone(&grafana_service);
                async move {
                    let datasource = crate::services::grafana_service::GrafanaDatasource {
                        name: request.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        r#type: request.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        url: request.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        access: request.get("access").and_then(|v| v.as_str()).unwrap_or("proxy").to_string(),
                        basic_auth: request.get("basic_auth").and_then(|v| v.as_bool()),
                        basic_auth_user: request.get("basic_auth_user").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        secure_json_data: request.get("secure_json_data").and_then(|v| v.as_object()).map(|obj| {
                            obj.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string())).collect()
                        }),
                        json_data: request.get("json_data").cloned(),
                    };

                    match grafana_service.create_datasource(datasource).await {
                        Ok(result) => Ok::<_, warp::Rejection>(warp::reply::json(&result)),
                        Err(e) => Ok(warp::reply::json(&serde_json::json!({
                            "error": format!("Failed to create datasource: {}", e),
                            "timestamp": chrono::Utc::now()
                        })))
                    }
                }
            }
        });

    // Create alert rule endpoint
    let create_alert_rule = warp::path!("api" / "v1" / "grafana" / "alerts")
        .and(warp::post())
        .and(warp::body::json())
        .and_then({
            let grafana_service = Arc::clone(&grafana_service);
            move |request: serde_json::Value| {
                let grafana_service = Arc::clone(&grafana_service);
                async move {
                    let alert_rule = crate::services::grafana_service::GrafanaAlertRule {
                        title: request.get("title").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        condition: request.get("condition").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        data: request.get("data").and_then(|v| v.as_array()).cloned().unwrap_or_default(),
                        no_data_state: request.get("no_data_state").and_then(|v| v.as_str()).unwrap_or("NoData").to_string(),
                        exec_err_state: request.get("exec_err_state").and_then(|v| v.as_str()).unwrap_or("Error").to_string(),
                        for_duration: request.get("for_duration").and_then(|v| v.as_str()).unwrap_or("5m").to_string(),
                    };

                    match grafana_service.create_alert_rule(alert_rule).await {
                        Ok(result) => Ok::<_, warp::Rejection>(warp::reply::json(&result)),
                        Err(e) => Ok(warp::reply::json(&serde_json::json!({
                            "error": format!("Failed to create alert rule: {}", e),
                            "timestamp": chrono::Utc::now()
                        })))
                    }
                }
            }
        });

    // Combine all routes
    health
        .or(create_dashboard)
        .or(list_dashboards)
        .or(get_dashboard)
        .or(update_dashboard)
        .or(delete_dashboard)
        .or(create_datasource)
        .or(create_alert_rule)
}