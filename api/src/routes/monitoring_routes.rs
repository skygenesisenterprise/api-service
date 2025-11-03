// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Monitoring Routes
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | SENSITIVE
//  MISSION: Provide REST API endpoints for system monitoring and health checks
//  compatible with Grafana and enterprise monitoring dashboards.
//  NOTICE: These endpoints expose system health, metrics, and status information
//  for operational monitoring and alerting.
//  MONITORING: Health checks, status reports, Prometheus metrics export
//  INTEGRATION: Grafana, Prometheus, ELK Stack, monitoring dashboards
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use warp::Filter;
use std::sync::Arc;
use crate::services::monitoring_service::MonitoringService;

/// [MONITORING ROUTES] System Health and Status Endpoints
/// @MISSION Provide comprehensive monitoring endpoints for Grafana integration.
/// @THREAT Insufficient system visibility for operators and automated monitoring.
/// @COUNTERMEASURE Multiple endpoints with different data granularities.
/// @DEPENDENCY Monitoring service for health checks and metric collection.
/// @PERFORMANCE Endpoints optimized for monitoring poll intervals.
/// @AUDIT All monitoring requests logged for security and compliance.
pub fn monitoring_routes(
    monitoring_service: Arc<MonitoringService>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    // Health check endpoint - lightweight status check
    let health_check = warp::path!("api" / "v1" / "health")
        .and(warp::get())
        .and_then({
            let monitoring_service = Arc::clone(&monitoring_service);
            move || {
                let monitoring_service = Arc::clone(&monitoring_service);
                async move {
                    match monitoring_service.check_system_health().await {
                        Ok(health) => Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "status": health.overall_status,
                            "timestamp": health.timestamp,
                            "version": health.version,
                            "uptime_seconds": health.uptime_seconds
                        }))),
                        Err(e) => Ok(warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": format!("Health check failed: {}", e),
                            "timestamp": chrono::Utc::now()
                        })))
                    }
                }
            }
        });

    // Detailed status endpoint - comprehensive system information
    let status_endpoint = warp::path!("api" / "v1" / "status")
        .and(warp::get())
        .and_then({
            let monitoring_service = Arc::clone(&monitoring_service);
            move || {
                let monitoring_service = Arc::clone(&monitoring_service);
                async move {
                    match monitoring_service.get_detailed_status().await {
                        Ok(status) => Ok::<_, warp::Rejection>(warp::reply::json(&status)),
                        Err(e) => Ok(warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": format!("Status retrieval failed: {}", e),
                            "timestamp": chrono::Utc::now()
                        })))
                    }
                }
            }
        });

    // Prometheus metrics endpoint - Grafana-compatible format
    let prometheus_metrics = warp::path!("api" / "v1" / "metrics" / "prometheus")
        .and(warp::get())
        .and_then({
            let monitoring_service = Arc::clone(&monitoring_service);
            move || {
                let monitoring_service = Arc::clone(&monitoring_service);
                async move {
                    let metrics = monitoring_service.export_prometheus_metrics().await;
                    Ok::<_, warp::Rejection>(
                        warp::reply::with_header(
                            metrics,
                            "Content-Type",
                            "text/plain; version=0.0.4; charset=utf-8"
                        )
                    )
                }
            }
        });

    // Component-specific health checks
    let component_health = warp::path!("api" / "v1" / "health" / String)
        .and(warp::get())
        .and_then({
            let monitoring_service = Arc::clone(&monitoring_service);
            move |component: String| {
                let monitoring_service = Arc::clone(&monitoring_service);
                async move {
                    match monitoring_service.check_system_health().await {
                        Ok(health) => {
                            // Find the specific component
                            if let Some(comp) = health.components.iter().find(|c| c.name == component) {
                                Ok::<_, warp::Rejection>(warp::reply::json(&comp))
                            } else {
                                Ok(warp::reply::json(&serde_json::json!({
                                    "status": "unknown",
                                    "message": format!("Component '{}' not found", component),
                                    "timestamp": chrono::Utc::now()
                                })))
                            }
                        },
                        Err(e) => Ok(warp::reply::json(&serde_json::json!({
                            "status": "error",
                            "message": format!("Health check failed: {}", e),
                            "timestamp": chrono::Utc::now()
                        })))
                    }
                }
            }
        });

    // Readiness probe endpoint - for Kubernetes/load balancers
    let readiness_probe = warp::path!("api" / "v1" / "ready")
        .and(warp::get())
        .and_then({
            let monitoring_service = Arc::clone(&monitoring_service);
            move || {
                let monitoring_service = Arc::clone(&monitoring_service);
                async move {
                    match monitoring_service.check_system_health().await {
                        Ok(health) => {
                            // Return 200 if healthy or degraded, 503 if unhealthy
                            let status_code = match health.overall_status {
                                crate::services::monitoring_service::HealthStatus::Healthy |
                                crate::services::monitoring_service::HealthStatus::Degraded => {
                                    warp::http::StatusCode::OK
                                },
                                _ => warp::http::StatusCode::SERVICE_UNAVAILABLE
                            };

                            Ok::<_, warp::Rejection>(
                                warp::reply::with_status(
                                    warp::reply::json(&serde_json::json!({
                                        "status": health.overall_status,
                                        "ready": matches!(health.overall_status,
                                            crate::services::monitoring_service::HealthStatus::Healthy |
                                            crate::services::monitoring_service::HealthStatus::Degraded)
                                    })),
                                    status_code
                                )
                            )
                        },
                        Err(_) => Ok(
                            warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({
                                    "status": "unhealthy",
                                    "ready": false
                                })),
                                warp::http::StatusCode::SERVICE_UNAVAILABLE
                            )
                        )
                    }
                }
            }
        });

    // Liveness probe endpoint - for Kubernetes
    let liveness_probe = warp::path!("api" / "v1" / "alive")
        .and(warp::get())
        .map(|| {
            warp::reply::with_status(
                warp::reply::json(&serde_json::json!({
                    "status": "alive",
                    "timestamp": chrono::Utc::now()
                })),
                warp::http::StatusCode::OK
            )
        });

    health_check.or(status_endpoint).or(prometheus_metrics).or(component_health).or(readiness_probe).or(liveness_probe)
}