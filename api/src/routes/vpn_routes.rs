use warp::Filter;
use std::sync::Arc;
use crate::core::vpn::{VpnManager, TailscaleManager, VpnPeer};

pub fn vpn_routes(
    vpn_manager: Arc<VpnManager>,
    tailscale_manager: Arc<TailscaleManager>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let get_peers = warp::path!("vpn" / "peers")
        .and(warp::get())
        .and(warp::any().map(move || vpn_manager.clone()))
        .and_then(|vm| async move {
            let peers = vm.get_peers().await;
            Ok(warp::reply::json(&peers))
        });

    let add_peer = warp::path!("vpn" / "peers")
        .and(warp::post())
        .and(warp::body::json::<(String, VpnPeer)>())
        .and(warp::any().map(move || vpn_manager.clone()))
        .and_then(|(name, peer), vm| async move {
            match vm.add_peer(name, peer).await {
                Ok(_) => Ok(warp::reply::json(&serde_json::json!({"status": "success"}))),
                Err(e) => Ok(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"error": e.to_string()})),
                    warp::http::StatusCode::INTERNAL_SERVER_ERROR
                )),
            }
        });

    let remove_peer = warp::path!("vpn" / "peers" / String)
        .and(warp::delete())
        .and(warp::any().map(move || vpn_manager.clone()))
        .and_then(|name, vm| async move {
            match vm.remove_peer(&name).await {
                Ok(_) => Ok(warp::reply::json(&serde_json::json!({"status": "success"}))),
                Err(e) => Ok(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"error": e.to_string()})),
                    warp::http::StatusCode::INTERNAL_SERVER_ERROR
                )),
            }
        });

    let vpn_status = warp::path!("vpn" / "status")
        .and(warp::get())
        .and(warp::any().map(move || vpn_manager.clone()))
        .and_then(|vm| async move {
            match vm.get_status().await {
                Ok(status) => Ok(warp::reply::json(&serde_json::json!({"status": status}))),
                Err(e) => Ok(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"error": e.to_string()})),
                    warp::http::StatusCode::INTERNAL_SERVER_ERROR
                )),
            }
        });

    let tailscale_status = warp::path!("tailscale" / "status")
        .and(warp::get())
        .and(warp::any().map(move || tailscale_manager.clone()))
        .and_then(|tm| async move {
            match tm.get_status().await {
                Ok(status) => Ok(warp::reply::json(&serde_json::json!({"status": status}))),
                Err(e) => Ok(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"error": e.to_string()})),
                    warp::http::StatusCode::INTERNAL_SERVER_ERROR
                )),
            }
        });

    let tailscale_ip = warp::path!("tailscale" / "ip")
        .and(warp::get())
        .and(warp::any().map(move || tailscale_manager.clone()))
        .and_then(|tm| async move {
            match tm.get_ip().await {
                Ok(ip) => Ok(warp::reply::json(&serde_json::json!({"ip": ip}))),
                Err(e) => Ok(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({"error": e.to_string()})),
                    warp::http::StatusCode::INTERNAL_SERVER_ERROR
                )),
            }
        });

    get_peers.or(add_peer).or(remove_peer).or(vpn_status).or(tailscale_status).or(tailscale_ip)
}