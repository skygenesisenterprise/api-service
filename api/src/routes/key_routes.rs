use warp::Filter;
use std::sync::Arc;
use crate::controllers::key_controller;
use crate::services::key_service::KeyService;
use crate::middlewares::auth_middleware::jwt_auth;
use crate::middlewares::cert_auth_middleware::certificate_auth;

pub fn key_routes(key_service: Arc<KeyService>) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let create = warp::path!("api" / "keys")
        .and(warp::post())
        .and(jwt_auth())
        .and(warp::query::<std::collections::HashMap<String, String>>())
        .and(warp::any().map(move || key_service.clone()))
        .and_then(|_claims, query: std::collections::HashMap<String, String>, ks| async move {
            let key_type = query.get("type").cloned().unwrap_or_default();
            let tenant = query.get("tenant").cloned().unwrap_or_default();
            let ttl = query.get("ttl").and_then(|s| s.parse().ok()).unwrap_or(3600);
            let status = query.get("status").cloned().unwrap_or("sandbox".to_string());
            key_controller::create_key(ks, key_type, tenant, ttl, status).await
        });

    let revoke = warp::path!("api" / "keys" / String)
        .and(warp::delete())
        .and(jwt_auth())
        .and(warp::any().map(move || key_service.clone()))
        .and_then(|id, _claims, ks| async move {
            key_controller::revoke_key(ks, id).await
        });

    let get = warp::path!("api" / "keys" / String)
        .and(warp::get())
        .and(jwt_auth())
        .and(warp::any().map(move || key_service.clone()))
        .and_then(|id, _claims, ks| async move {
            key_controller::get_key(ks, id).await
        });

    let list = warp::path!("api" / "keys")
        .and(warp::get())
        .and(jwt_auth())
        .and(warp::query::<std::collections::HashMap<String, String>>())
        .and(warp::any().map(move || key_service.clone()))
        .and_then(|_claims, query, ks| async move {
            let tenant = query.get("tenant").cloned().unwrap_or_default();
            key_controller::list_keys(ks, tenant).await
        });

    // Certificate-specific routes
    let create_with_cert = warp::path!("api" / "keys" / "with-certificate")
        .and(warp::post())
        .and(jwt_auth())
        .and(warp::query::<std::collections::HashMap<String, String>>())
        .and(warp::any().map(move || key_service.clone()))
        .and_then(|_claims, query: std::collections::HashMap<String, String>, ks| async move {
            let key_type = query.get("type").cloned().unwrap_or_default();
            let tenant = query.get("tenant").cloned().unwrap_or_default();
            let ttl = query.get("ttl").and_then(|s| s.parse().ok()).unwrap_or(3600);
            let cert_type = query.get("cert_type").cloned().unwrap_or("rsa".to_string());
            let status = query.get("status").cloned().unwrap_or("sandbox".to_string());
            key_controller::create_key_with_certificate(ks, key_type, tenant, ttl, cert_type, status).await
        });

    // Convenience routes for sandbox and production keys
    let create_sandbox = warp::path!("api" / "keys" / "sandbox")
        .and(warp::post())
        .and(jwt_auth())
        .and(warp::query::<std::collections::HashMap<String, String>>())
        .and(warp::any().map(move || key_service.clone()))
        .and_then(|_claims, query: std::collections::HashMap<String, String>, ks| async move {
            let key_type = query.get("type").cloned().unwrap_or_default();
            let tenant = query.get("tenant").cloned().unwrap_or_default();
            let ttl = query.get("ttl").and_then(|s| s.parse().ok()).unwrap_or(3600);
            key_controller::create_sandbox_key(ks, key_type, tenant, ttl).await
        });

    let create_production = warp::path!("api" / "keys" / "production")
        .and(warp::post())
        .and(jwt_auth())
        .and(warp::query::<std::collections::HashMap<String, String>>())
        .and(warp::any().map(move || key_service.clone()))
        .and_then(|_claims, query: std::collections::HashMap<String, String>, ks| async move {
            let key_type = query.get("type").cloned().unwrap_or_default();
            let tenant = query.get("tenant").cloned().unwrap_or_default();
            let ttl = query.get("ttl").and_then(|s| s.parse().ok()).unwrap_or(3600);
            key_controller::create_production_key(ks, key_type, tenant, ttl).await
        });

    let create_sandbox_with_cert = warp::path!("api" / "keys" / "sandbox" / "with-certificate")
        .and(warp::post())
        .and(jwt_auth())
        .and(warp::query::<std::collections::HashMap<String, String>>())
        .and(warp::any().map(move || key_service.clone()))
        .and_then(|_claims, query: std::collections::HashMap<String, String>, ks| async move {
            let key_type = query.get("type").cloned().unwrap_or_default();
            let tenant = query.get("tenant").cloned().unwrap_or_default();
            let ttl = query.get("ttl").and_then(|s| s.parse().ok()).unwrap_or(3600);
            let cert_type = query.get("cert_type").cloned().unwrap_or("rsa".to_string());
            key_controller::create_sandbox_key_with_certificate(ks, key_type, tenant, ttl, cert_type).await
        });

    let create_production_with_cert = warp::path!("api" / "keys" / "production" / "with-certificate")
        .and(warp::post())
        .and(jwt_auth())
        .and(warp::query::<std::collections::HashMap<String, String>>())
        .and(warp::any().map(move || key_service.clone()))
        .and_then(|_claims, query: std::collections::HashMap<String, String>, ks| async move {
            let key_type = query.get("type").cloned().unwrap_or_default();
            let tenant = query.get("tenant").cloned().unwrap_or_default();
            let ttl = query.get("ttl").and_then(|s| s.parse().ok()).unwrap_or(3600);
            let cert_type = query.get("cert_type").cloned().unwrap_or("rsa".to_string());
            key_controller::create_production_key_with_certificate(ks, key_type, tenant, ttl, cert_type).await
        });

    let get_public_key = warp::path!("api" / "keys" / String / "public-key")
        .and(warp::get())
        .and(jwt_auth())
        .and(warp::any().map(move || key_service.clone()))
        .and_then(|id, _claims, ks| async move {
            key_controller::get_public_key(ks, id).await
        });

    let revoke_cert = warp::path!("api" / "keys" / String / "certificate")
        .and(warp::delete())
        .and(jwt_auth())
        .and(warp::any().map(move || key_service.clone()))
        .and_then(|id, _claims, ks| async move {
            key_controller::revoke_certificate(ks, id).await
        });

    // Certificate-based authentication route example
    let cert_authenticated_route = warp::path!("api" / "secure" / "cert")
        .and(warp::get())
        .and(certificate_auth(key_service.clone()))
        .and_then(|claims| async move {
            Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                "message": "Authenticated with certificate",
                "api_key_id": claims.api_key_id
            })))
        });

    create.or(revoke).or(get).or(list).or(create_with_cert).or(get_public_key).or(revoke_cert).or(cert_authenticated_route).or(create_sandbox).or(create_production).or(create_sandbox_with_cert).or(create_production_with_cert)
}