use warp::Filter;
use std::sync::Arc;
use crate::core::opentelemetry::Metrics;
use crate::services::monitoring_service::MonitoringService;

pub fn opentelemetry_routes(
    metrics: Arc<Metrics>,
    monitoring_service: Arc<MonitoringService>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    // Metrics endpoint (JSON format for compatibility)
    let metrics_endpoint = warp::path!("api" / "v1" / "metrics")
        .and(warp::get())
        .and_then({
            let monitoring_service = Arc::clone(&monitoring_service);
            move || {
                let monitoring_service = Arc::clone(&monitoring_service);
                async move {
                    match monitoring_service.get_detailed_status().await {
                        Ok(status) => Ok::<_, warp::Rejection>(warp::reply::json(&status)),
                        Err(e) => Ok(warp::reply::json(&serde_json::json!({
                            "error": format!("Failed to retrieve metrics: {}", e),
                            "timestamp": chrono::Utc::now()
                        })))
                    }
                }
            }
        });

    // Traces endpoint
    let traces_endpoint = warp::path!("api" / "v1" / "telemetry" / "traces")
        .and(warp::get())
        .and_then(move || {
            let metrics = Arc::clone(&metrics);
            async move {
                // Return current trace information
                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "status": "traces_endpoint",
                    "note": "Trace data would be exported here"
                })))
            }
        });

    // Logs endpoint
    let logs_endpoint = warp::path!("api" / "v1" / "telemetry" / "logs")
        .and(warp::get())
        .and_then(move || {
            let metrics = Arc::clone(&metrics);
            async move {
                // Return current log information
                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "status": "logs_endpoint",
                    "note": "Log data would be exported here"
                })))
            }
        });

    // Health check for observability stack
    let health_endpoint = warp::path!("api" / "v1" / "telemetry" / "health")
        .and(warp::get())
        .and_then(move || {
            let metrics = Arc::clone(&metrics);
            async move {
                // Check health of observability components
                Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                    "status": "healthy",
                    "components": {
                        "opentelemetry": "active",
                        "metrics": "active",
                        "tracing": "active"
                    }
                })))
            }
        });

    metrics_endpoint.or(traces_endpoint).or(logs_endpoint).or(health_endpoint)
}