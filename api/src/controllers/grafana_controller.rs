// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Grafana Controller
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | SENSITIVE
//  MISSION: Provide REST API endpoints for Grafana management operations
//  including dashboard creation, datasource configuration, and alerting.
//  NOTICE: These endpoints enable programmatic Grafana configuration through
//  the Sky Genesis API for automated monitoring setup.
//  MONITORING: Grafana operations, dashboard management, datasource setup
//  INTEGRATION: Grafana HTTP API, monitoring dashboards
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use std::sync::Arc;
use warp::Filter;
use serde::{Deserialize, Serialize};
use crate::services::grafana_service::{GrafanaService, GrafanaDashboard, GrafanaDatasource, GrafanaAlertRule};

/// [GRAFANA HEALTH RESPONSE] Health Check Result
/// @MISSION Report Grafana service availability.
/// @THREAT Undetected Grafana connectivity issues.
/// @COUNTERMEASURE Structured health response.
/// @AUDIT Health checks logged for monitoring.
#[derive(Debug, Serialize, Deserialize)]
pub struct GrafanaHealthResponse {
    pub healthy: bool,
    pub message: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// [CREATE DASHBOARD REQUEST] Dashboard Creation Payload
/// @MISSION Define dashboard creation request structure.
/// @THREAT Invalid dashboard configuration.
/// @COUNTERMEASURE Validated request payload.
/// @AUDIT Dashboard creation requests logged.
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateDashboardRequest {
    pub dashboard: serde_json::Value,
    pub folder_id: Option<i64>,
    pub overwrite: Option<bool>,
}

/// [CREATE DATASOURCE REQUEST] Datasource Creation Payload
/// @MISSION Define datasource creation request structure.
/// @THREAT Invalid datasource configuration.
/// @COUNTERMEASURE Validated request payload.
/// @AUDIT Datasource creation requests logged.
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateDatasourceRequest {
    pub name: String,
    pub r#type: String,
    pub url: String,
    pub access: Option<String>,
    pub basic_auth: Option<bool>,
    pub basic_auth_user: Option<String>,
    pub secure_json_data: Option<std::collections::HashMap<String, String>>,
    pub json_data: Option<serde_json::Value>,
}

/// [CREATE ALERT RULE REQUEST] Alert Rule Creation Payload
/// @MISSION Define alert rule creation request structure.
/// @THREAT Invalid alert configuration.
/// @COUNTERMEASURE Validated request payload.
/// @AUDIT Alert rule creation requests logged.
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateAlertRuleRequest {
    pub title: String,
    pub condition: String,
    pub data: Vec<serde_json::Value>,
    pub no_data_state: Option<String>,
    pub exec_err_state: Option<String>,
    pub for_duration: Option<String>,
}

/// [GRAFANA CONTROLLER] API Endpoints for Grafana Management
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
                            let response = GrafanaHealthResponse {
                                healthy,
                                message: if healthy { "Grafana service is healthy".to_string() } else { "Grafana service is unhealthy".to_string() },
                                timestamp: chrono::Utc::now(),
                            };
                            Ok::<_, warp::Rejection>(warp::reply::json(&response))
                        },
                        Err(e) => {
                            let response = GrafanaHealthResponse {
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

    // Create dashboard endpoint
    let create_dashboard = warp::path!("api" / "v1" / "grafana" / "dashboards")
        .and(warp::post())
        .and(warp::body::json())
        .and_then({
            let grafana_service = Arc::clone(&grafana_service);
            move |request: CreateDashboardRequest| {
                let grafana_service = Arc::clone(&grafana_service);
                async move {
                    let dashboard = GrafanaDashboard {
                        dashboard: request.dashboard,
                        folder_id: request.folder_id,
                        overwrite: request.overwrite.unwrap_or(false),
                    };

                    match grafana_service.create_dashboard(dashboard).await {
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
            move |uid: String, request: CreateDashboardRequest| {
                let grafana_service = Arc::clone(&grafana_service);
                async move {
                    let dashboard = GrafanaDashboard {
                        dashboard: request.dashboard,
                        folder_id: request.folder_id,
                        overwrite: request.overwrite.unwrap_or(true),
                    };

                    match grafana_service.update_dashboard(&uid, dashboard).await {
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
            move |request: CreateDatasourceRequest| {
                let grafana_service = Arc::clone(&grafana_service);
                async move {
                    let datasource = GrafanaDatasource {
                        name: request.name,
                        r#type: request.r#type,
                        url: request.url,
                        access: request.access.unwrap_or_else(|| "proxy".to_string()),
                        basic_auth: request.basic_auth,
                        basic_auth_user: request.basic_auth_user,
                        secure_json_data: request.secure_json_data,
                        json_data: request.json_data,
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
            move |request: CreateAlertRuleRequest| {
                let grafana_service = Arc::clone(&grafana_service);
                async move {
                    let alert_rule = GrafanaAlertRule {
                        title: request.title,
                        condition: request.condition,
                        data: request.data,
                        no_data_state: request.no_data_state.unwrap_or_else(|| "NoData".to_string()),
                        exec_err_state: request.exec_err_state.unwrap_or_else(|| "Error".to_string()),
                        for_duration: request.for_duration.unwrap_or_else(|| "5m".to_string()),
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