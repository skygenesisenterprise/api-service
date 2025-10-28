use warp::Filter;
use std::sync::Arc;
use crate::websocket::{WebSocketServer, handle_websocket_connection};
use crate::middlewares::auth_middleware::jwt_auth;

pub fn websocket_routes(ws_server: Arc<WebSocketServer>) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    // Public WebSocket endpoint (no authentication required)
    let public_ws = warp::path!("ws")
        .and(warp::ws())
        .and(warp::any().map(move || ws_server.clone()))
        .map(|ws: warp::ws::Ws, server| {
            ws.on_upgrade(move |websocket| handle_websocket_connection(websocket, server, None))
        });

    // Authenticated WebSocket endpoint (JWT required)
    let authenticated_ws = warp::path!("ws" / "auth")
        .and(jwt_auth())
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
        .and(jwt_auth())
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
        .and(jwt_auth())
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

    public_ws.or(authenticated_ws).or(status).or(broadcast).or(notify)
}