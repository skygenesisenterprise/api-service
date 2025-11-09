// Routes Rust module (Progressive integration)

use warp::Filter;
use serde_json;
mod test_routes;
mod mail_routes;
mod mac_routes;
mod logger_routes;
mod security_routes;
mod auth_routes; 
// mod data_routes;
// mod devices_routes;
// mod openpgp_routes;
// mod voip_routes;
// mod grafana_routes;
// mod poweradmin_routes 
// mod grpc_routes;
// mod oauth2_routes;
// mod sftp_routes;
// mod snmp_routes;
// mod ssh_routes;
// mod webhook_routes;
// mod monitoring_routes;
// mod opentelemetry_routes;  


pub fn routes() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    // Ultra-minimal routes for testing compilation
    let hello = warp::path!("hello")
        .and(warp::get())
        .map(|| "Hello, World!");
    
    let health = warp::path("api")
        .and(warp::path("v1"))
        .and(warp::path("health"))
        .and(warp::get())
        .map(|| {
            warp::reply::json(&serde_json::json!({
                "status": "healthy",
                "service": "sky-genesis-enterprise-api",
                "version": "1.0.0",
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "uptime_seconds": 0,
                "message": "API is running successfully!"
            }))
        });
    
    let docs = warp::path("docs")
        .and(warp::get())
        .map(|| {
            warp::reply::html(r#"
<!DOCTYPE html>
<html>
<head>
    <title>Sky Genesis Enterprise API</title>
</head>
<body>
    <h1>Sky Genesis Enterprise API</h1>
    <p>API is running!</p>
    <ul>
        <li><a href="/hello">Hello World</a></li>
        <li><a href="/api/v1/health">Health Check</a></li>
    </ul>
</body>
</html>
            "#)
        });

    let all_routes = hello.or(health).or(docs).or(test_routes::test_routes()).or(mail_routes::mail_routes()).or(mac_routes::mac_routes()).or(logger_routes::logger_routes()).or(security_routes::security_routes()).or(auth_routes::auth_routes());

    all_routes
        .with(warp::cors().allow_any_origin().allow_methods(vec!["GET", "POST", "PUT", "DELETE"]))
        .with(warp::log("api"))
}