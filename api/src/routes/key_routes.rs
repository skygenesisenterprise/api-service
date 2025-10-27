use warp::Filter;
use std::sync::Arc;
use crate::controllers::key_controller;
use crate::services::key_service::KeyService;
use crate::middlewares::auth_middleware::jwt_auth;

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
            key_controller::create_key(ks, key_type, tenant, ttl).await
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

    create.or(revoke).or(get).or(list)
}