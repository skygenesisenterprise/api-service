use warp::Filter;
use std::sync::Arc;
use crate::websocket::{WebSocketServer, handle_websocket_connection};
use crate::middlewares::auth_middleware::jwt_auth;
use crate::core::keycloak::KeycloakClient;

pub fn websocket_routes(ws_server: Arc<WebSocketServer>, keycloak_client: Arc<KeycloakClient>) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    // Public WebSocket endpoint (no authentication required)
    let public_ws = warp::path!("ws")
        .and(warp::ws())
        .and(warp::any().map(move || ws_server.clone()))
        .map(|ws: warp::ws::Ws, server| {
            ws.on_upgrade(move |websocket| handle_websocket_connection(websocket, server, None))
        });

    // Authenticated WebSocket endpoint (JWT required)
    let authenticated_ws = warp::path!("ws" / "auth")
        .and(jwt_auth(keycloak_client.clone()))
        .and(warp::ws())
        .and(warp::any().map(move || ws_server.clone()))
        .map(|claims: crate::middlewares::auth_middleware::Claims, ws: warp::ws::Ws, server| {
            ws.on_upgrade(move |websocket| handle_websocket_connection(websocket, server, Some(claims.sub)))
        });

    // WebSocket status endpoint
    let status = warp::path!("ws" / "status")
        .and(warp::get())
        .and(warp::any().map(move || ws_server.clone()))
        .and_then(move |server: Arc<WebSocketServer>| async move {
            let client_count = server.get_client_count().await;
            let channel_count = server.get_channel_count().await;

            Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                "status": "active",
                "clients_connected": client_count,
                "channels_active": channel_count,
                "timestamp": chrono::Utc::now().timestamp()
            })))
        });

    // Broadcast endpoint for server-side messages
    let broadcast = warp::path!("ws" / "broadcast" / String)
        .and(warp::post())
        .and(jwt_auth(keycloak_client.clone()))
        .and(warp::body::json())
        .and(warp::any().map(move || ws_server.clone()))
        .and_then(move |channel: String, _claims, data: serde_json::Value, server: Arc<WebSocketServer>| async move {
            use crate::websocket::WebSocketMessage;

            let message = WebSocketMessage::Broadcast {
                channel: channel.clone(),
                data,
            };

            server.broadcast_to_channel(&channel, message).await;

            Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                "status": "broadcast_sent",
                "channel": channel,
                "timestamp": chrono::Utc::now().timestamp()
            })))
        });

    // Notification endpoint
    let notify = warp::path!("ws" / "notify" / String)
        .and(warp::post())
        .and(jwt_auth(keycloak_client.clone()))
        .and(warp::body::json())
        .and(warp::any().map(move || ws_server.clone()))
        .and_then(move |user_id: String, _claims, body: serde_json::Value, server: Arc<WebSocketServer>| async move {
            use crate::websocket::WebSocketMessage;

            let title = body.get("title").and_then(|v| v.as_str()).unwrap_or("Notification");
            let message = body.get("message").and_then(|v| v.as_str()).unwrap_or("");
            let level = body.get("level").and_then(|v| v.as_str()).unwrap_or("info");

            let notification = WebSocketMessage::Notification {
                title: title.to_string(),
                message: message.to_string(),
                level: level.to_string(),
            };

            // Find client by user_id and send notification
            let clients = server.clients.read().await;
            let mut sent = false;
            for client in clients.values() {
                if client.user_id.as_ref() == Some(&user_id) {
                    server.send_to_client(&client.id, notification.clone()).await;
                    sent = true;
                }
            }

            Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                "status": if sent { "notification_sent" } else { "user_not_connected" },
                "user_id": user_id,
                "timestamp": chrono::Utc::now().timestamp()
            })))
        });

    // XMPP-style presence endpoints
    let presence_status = warp::path!("xmpp" / "presence")
        .and(warp::get())
        .and(warp::any().map(move || ws_server.clone()))
        .and_then(move |server: Arc<WebSocketServer>| async move {
            let presence_data = server.get_all_presence().await;
            let presence_json: serde_json::Value = presence_data.into_iter()
                .map(|(user_id, (status, message, timestamp))| {
                    (user_id, serde_json::json!({
                        "status": status,
                        "message": message,
                        "timestamp": timestamp
                    }))
                })
                .collect();

            Ok::<_, warp::Rejection>(warp::reply::json(&presence_json))
        });

    let presence_user = warp::path!("xmpp" / "presence" / String)
        .and(warp::get())
        .and(warp::any().map(move || ws_server.clone()))
        .and_then(move |user_id: String, server: Arc<WebSocketServer>| async move {
            match server.get_presence(&user_id).await {
                Some((status, message, timestamp)) => {
                    Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                        "user_id": user_id,
                        "status": status,
                        "message": message,
                        "timestamp": timestamp
                    })))
                },
                None => {
                    Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                        "user_id": user_id,
                        "status": "unknown",
                        "error": "User presence not found"
                    })))
                }
            }
        });

    let presence_update = warp::path!("xmpp" / "presence")
        .and(warp::post())
        .and(jwt_auth(keycloak_client.clone()))
        .and(warp::body::json())
        .and(warp::any().map(move || ws_server.clone()))
        .and_then(move |_claims, body: serde_json::Value, server: Arc<WebSocketServer>| async move {
            use crate::websocket::PresenceStatus;

            let user_id = body.get("user_id").and_then(|v| v.as_str()).unwrap_or("");
            let status_str = body.get("status").and_then(|v| v.as_str()).unwrap_or("online");
            let status_message = body.get("message").and_then(|v| v.as_str()).map(|s| s.to_string());

            let status = match status_str {
                "away" => PresenceStatus::Away,
                "busy" => PresenceStatus::Busy,
                "offline" => PresenceStatus::Offline,
                _ => PresenceStatus::Online,
            };

            server.update_presence(user_id, status, status_message).await;

            Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                "status": "presence_updated",
                "user_id": user_id,
                "timestamp": chrono::Utc::now().timestamp()
            })))
        });

    public_ws.or(authenticated_ws).or(status).or(broadcast).or(notify).or(presence_status).or(presence_user).or(presence_update)
}