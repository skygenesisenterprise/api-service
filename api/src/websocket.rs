use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use warp::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WebSocketMessage {
    // Client messages
    Subscribe { channel: String },
    Unsubscribe { channel: String },
    Ping,

    // Server messages
    Notification { title: String, message: String, level: String },
    Update { channel: String, data: serde_json::Value },
    Broadcast { channel: String, data: serde_json::Value },
    Error { message: String },

    // Pong response
    Pong,
}

#[derive(Debug, Clone)]
pub struct Client {
    pub id: Uuid,
    pub user_id: Option<String>,
    pub channels: Vec<String>,
    pub sender: mpsc::UnboundedSender<Result<Message, warp::Error>>,
}

#[derive(Debug, Clone)]
pub struct WebSocketServer {
    clients: Arc<RwLock<HashMap<Uuid, Client>>>,
    channels: Arc<RwLock<HashMap<String, Vec<Uuid>>>>,
}

impl WebSocketServer {
    pub fn new() -> Self {
        WebSocketServer {
            clients: Arc::new(RwLock::new(HashMap::new())),
            channels: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn add_client(&self, client: Client) {
        let client_id = client.id;
        self.clients.write().await.insert(client_id, client);
    }

    pub async fn remove_client(&self, client_id: &Uuid) {
        if let Some(client) = self.clients.write().await.remove(client_id) {
            // Remove client from all channels
            for channel in &client.channels {
                self.unsubscribe_from_channel(client_id, channel).await;
            }
        }
    }

    pub async fn subscribe_to_channel(&self, client_id: &Uuid, channel: &str) {
        let mut channels = self.channels.write().await;
        channels.entry(channel.to_string())
            .or_insert_with(Vec::new)
            .push(*client_id);

        // Update client's channel list
        if let Some(client) = self.clients.write().await.get_mut(client_id) {
            if !client.channels.contains(&channel.to_string()) {
                client.channels.push(channel.to_string());
            }
        }
    }

    pub async fn unsubscribe_from_channel(&self, client_id: &Uuid, channel: &str) {
        let mut channels = self.channels.write().await;
        if let Some(channel_clients) = channels.get_mut(channel) {
            channel_clients.retain(|&id| id != *client_id);
            if channel_clients.is_empty() {
                channels.remove(channel);
            }
        }

        // Update client's channel list
        if let Some(client) = self.clients.write().await.get_mut(client_id) {
            client.channels.retain(|c| c != channel);
        }
    }

    pub async fn broadcast_to_channel(&self, channel: &str, message: WebSocketMessage) {
        let channels = self.channels.read().await;
        if let Some(client_ids) = channels.get(channel) {
            let clients = self.clients.read().await;
            let json_message = serde_json::to_string(&message).unwrap_or_default();

            for client_id in client_ids {
                if let Some(client) = clients.get(client_id) {
                    let _ = client.sender.send(Ok(Message::text(json_message.clone())));
                }
            }
        }
    }

    pub async fn send_to_client(&self, client_id: &Uuid, message: WebSocketMessage) {
        let clients = self.clients.read().await;
        if let Some(client) = clients.get(client_id) {
            let json_message = serde_json::to_string(&message).unwrap_or_default();
            let _ = client.sender.send(Ok(Message::text(json_message)));
        }
    }

    pub async fn broadcast_to_all(&self, message: WebSocketMessage) {
        let clients = self.clients.read().await;
        let json_message = serde_json::to_string(&message).unwrap_or_default();

        for client in clients.values() {
            let _ = client.sender.send(Ok(Message::text(json_message.clone())));
        }
    }

    pub async fn get_channel_clients(&self, channel: &str) -> Vec<Uuid> {
        let channels = self.channels.read().await;
        channels.get(channel).cloned().unwrap_or_default()
    }

    pub async fn get_client_count(&self) -> usize {
        self.clients.read().await.len()
    }

    pub async fn get_channel_count(&self) -> usize {
        self.channels.read().await.len()
    }
}

pub async fn handle_websocket_connection(
    websocket: WebSocket,
    server: Arc<WebSocketServer>,
    user_id: Option<String>,
) {
    let (ws_sender, mut ws_receiver) = websocket.split();
    let (tx, rx) = mpsc::unbounded_channel();

    // Create client
    let client_id = Uuid::new_v4();
    let client = Client {
        id: client_id,
        user_id: user_id.clone(),
        channels: Vec::new(),
        sender: tx,
    };

    server.add_client(client).await;

    // Send welcome message
    let welcome_msg = WebSocketMessage::Notification {
        title: "Connected".to_string(),
        message: format!("WebSocket connection established. Client ID: {}", client_id),
        level: "info".to_string(),
    };
    server.send_to_client(&client_id, welcome_msg).await;

    // Forward messages from client to WebSocket
    tokio::spawn(async move {
        let mut rx = tokio_stream::wrappers::UnboundedReceiverStream::new(rx);
        while let Some(message) = rx.next().await {
            if let Ok(msg) = message {
                if ws_sender.send(msg).await.is_err() {
                    break;
                }
            }
        }
    });

    // Handle incoming messages from WebSocket
    while let Some(result) = ws_receiver.next().await {
        match result {
            Ok(message) => {
                if let Ok(text) = message.to_str() {
                    if let Ok(ws_message) = serde_json::from_str::<WebSocketMessage>(text) {
                        handle_websocket_message(&server, &client_id, ws_message).await;
                    }
                } else if message.is_close() {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    // Clean up when connection closes
    server.remove_client(&client_id).await;
}

async fn handle_websocket_message(server: &Arc<WebSocketServer>, client_id: &Uuid, message: WebSocketMessage) {
    match message {
        WebSocketMessage::Subscribe { channel } => {
            server.subscribe_to_channel(client_id, &channel).await;
            let confirm_msg = WebSocketMessage::Notification {
                title: "Subscribed".to_string(),
                message: format!("Successfully subscribed to channel: {}", channel),
                level: "success".to_string(),
            };
            server.send_to_client(client_id, confirm_msg).await;
        }
        WebSocketMessage::Unsubscribe { channel } => {
            server.unsubscribe_from_channel(client_id, &channel).await;
            let confirm_msg = WebSocketMessage::Notification {
                title: "Unsubscribed".to_string(),
                message: format!("Successfully unsubscribed from channel: {}", channel),
                level: "info".to_string(),
            };
            server.send_to_client(client_id, confirm_msg).await;
        }
        WebSocketMessage::Ping => {
            server.send_to_client(client_id, WebSocketMessage::Pong).await;
        }
        _ => {
            // Ignore other message types from client
        }
    }
}

// Utility functions for broadcasting common events
pub async fn broadcast_api_key_created(server: &Arc<WebSocketServer>, tenant: &str, key_id: &str) {
    let message = WebSocketMessage::Broadcast {
        channel: format!("tenant:{}", tenant),
        data: serde_json::json!({
            "event": "api_key_created",
            "key_id": key_id,
            "timestamp": chrono::Utc::now().timestamp()
        }),
    };
    server.broadcast_to_channel(&format!("tenant:{}", tenant), message).await;
}

pub async fn broadcast_api_key_revoked(server: &Arc<WebSocketServer>, tenant: &str, key_id: &str) {
    let message = WebSocketMessage::Broadcast {
        channel: format!("tenant:{}", tenant),
        data: serde_json::json!({
            "event": "api_key_revoked",
            "key_id": key_id,
            "timestamp": chrono::Utc::now().timestamp()
        }),
    };
    server.broadcast_to_channel(&format!("tenant:{}", tenant), message).await;
}

pub async fn notify_user(server: &Arc<WebSocketServer>, user_id: &str, title: &str, message: &str, level: &str) {
    let notification = WebSocketMessage::Notification {
        title: title.to_string(),
        message: message.to_string(),
        level: level.to_string(),
    };

    // Find client by user_id and send notification
    let clients = server.clients.read().await;
    for client in clients.values() {
        if client.user_id.as_ref() == Some(&user_id.to_string()) {
            server.send_to_client(&client.id, notification.clone()).await;
        }
    }
}

pub async fn broadcast_system_status(server: &Arc<WebSocketServer>, status: &str, details: serde_json::Value) {
    let message = WebSocketMessage::Broadcast {
        channel: "system".to_string(),
        data: serde_json::json!({
            "event": "system_status",
            "status": status,
            "details": details,
            "timestamp": chrono::Utc::now().timestamp()
        }),
    };
    server.broadcast_to_channel("system", message).await;
}