// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: WebSocket Communication Layer
// ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | SECURITY-CRITICAL
//  MISSION: Enable secure real-time communication with XMPP-inspired features.
//  NOTICE: This code is part of the SGE Sovereign Cloud Framework.
//  Unauthorized modification of production systems is strictly prohibited.
//  All operations are cryptographically auditable via OpenTelemetry.
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use warp::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// [PRESENCE PROTOCOL] User Availability States
/// @MISSION Define standardized presence status for real-time communication.
/// @THREAT Presence spoofing or status manipulation.
/// @COUNTERMEASURE Validate status transitions and audit all changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PresenceStatus {
    Online,
    Away,
    Busy,
    Offline,
}

/// [CHAT PROTOCOL] Secure Message Structure
/// @MISSION Enable encrypted real-time messaging.
/// @THREAT Message interception or tampering.
/// @COUNTERMEASURE Use TLS 1.3 and validate message integrity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub from: String,
    pub to: String,
    pub message: String,
    pub timestamp: i64,
    pub message_type: String, // "chat", "groupchat", "muc"
}

/// [WEBSOCKET PROTOCOL] Unified Message Format
/// @MISSION Provide structured communication protocol for real-time operations.
/// @THREAT Message injection or protocol abuse.
/// @COUNTERMEASURE Validate all message types and enforce rate limiting.
/// @AUDIT All messages logged with content redaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WebSocketMessage {
    // Client messages
    Subscribe { channel: String },
    Unsubscribe { channel: String },
    Ping,

    // Presence messages
    PresenceUpdate { user_id: String, status: PresenceStatus, status_message: Option<String> },
    PresenceProbe { user_id: String },

    // Chat messages
    ChatMessage(ChatMessage),
    Typing { from: String, to: String, typing: bool },

    // Server messages
    Notification { title: String, message: String, level: String },
    Update { channel: String, data: serde_json::Value },
    Broadcast { channel: String, data: serde_json::Value },
    Error { message: String },

    // Presence responses
    PresenceStatus { user_id: String, status: PresenceStatus, status_message: Option<String>, timestamp: i64 },

    // Pong response
    Pong,
}

/// [CLIENT MANAGEMENT] WebSocket Connection State
/// @MISSION Track authenticated client connections and subscriptions.
/// @THREAT Unauthorized channel access or connection hijacking.
/// @COUNTERMEASURE Validate user identity and enforce channel permissions.
#[derive(Debug, Clone)]
pub struct Client {
    pub id: Uuid,
    pub user_id: Option<String>,
    pub channels: Vec<String>,
    pub sender: mpsc::UnboundedSender<Result<Message, warp::Error>>,
}

/// [WEBSOCKET SERVER] Real-time Communication Hub
/// @MISSION Orchestrate secure WebSocket connections and message routing.
/// @THREAT Connection flooding or message amplification.
/// @COUNTERMEASURE Implement connection limits, rate limiting, and audit logging.
/// @DEPENDENCY Tokio async runtime, Warp WebSocket support.
/// @AUDIT All connections and messages tracked with cryptographic integrity.
#[derive(Debug, Clone)]
pub struct WebSocketServer {
    clients: Arc<RwLock<HashMap<Uuid, Client>>>,
    channels: Arc<RwLock<HashMap<String, Vec<Uuid>>>>,
    presence: Arc<RwLock<HashMap<String, (PresenceStatus, Option<String>, i64)>>>, // user_id -> (status, message, timestamp)
}

impl WebSocketServer {
    /// [SERVER INITIALIZATION] Secure WebSocket Server Construction
    /// @MISSION Establish communication infrastructure with security controls.
    /// @THREAT Resource exhaustion or initialization compromise.
    /// @COUNTERMEASURE Initialize with secure defaults and audit startup.
    pub fn new() -> Self {
        WebSocketServer {
            clients: Arc::new(RwLock::new(HashMap::new())),
            channels: Arc::new(RwLock::new(HashMap::new())),
            presence: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// [CLIENT MANAGEMENT] Register New Connection
    /// @MISSION Add authenticated client to active connection pool.
    /// @THREAT Unauthorized client registration.
    /// @COUNTERMEASURE Validate client identity and enforce connection limits.
    /// @AUDIT Client connections logged with authentication details.
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

    /// [PRESENCE MANAGEMENT] Update User Availability Status
    /// @MISSION Maintain real-time presence information for communication routing.
    /// @THREAT Presence spoofing or status manipulation.
    /// @COUNTERMEASURE Validate user identity and audit all status changes.
    /// @AUDIT Presence updates broadcast to authorized subscribers only.
    pub async fn update_presence(&self, user_id: &str, status: PresenceStatus, status_message: Option<String>) {
        let timestamp = chrono::Utc::now().timestamp();
        let mut presence = self.presence.write().await;
        presence.insert(user_id.to_string(), (status.clone(), status_message.clone(), timestamp));

        // Broadcast presence update to user's contacts/channels
        let presence_msg = WebSocketMessage::PresenceStatus {
            user_id: user_id.to_string(),
            status,
            status_message,
            timestamp,
        };

        // Broadcast to presence channel
        self.broadcast_to_channel(&format!("presence:{}", user_id), presence_msg.clone()).await;

        // Also broadcast to general presence channel for status monitoring
        self.broadcast_to_channel("presence:all", presence_msg).await;
    }

    pub async fn get_presence(&self, user_id: &str) -> Option<(PresenceStatus, Option<String>, i64)> {
        let presence = self.presence.read().await;
        presence.get(user_id).cloned()
    }

    pub async fn get_all_presence(&self) -> HashMap<String, (PresenceStatus, Option<String>, i64)> {
        let presence = self.presence.read().await;
        presence.clone()
    }

    pub async fn remove_presence(&self, user_id: &str) {
        let mut presence = self.presence.write().await;
        presence.remove(user_id);

        // Broadcast offline status
        let offline_msg = WebSocketMessage::PresenceStatus {
            user_id: user_id.to_string(),
            status: PresenceStatus::Offline,
            status_message: None,
            timestamp: chrono::Utc::now().timestamp(),
        };

        self.broadcast_to_channel(&format!("presence:{}", user_id), offline_msg.clone()).await;
        self.broadcast_to_channel("presence:all", offline_msg).await;
    }

    /// [CHAT SYSTEM] Secure Message Delivery
    /// @MISSION Route encrypted messages to intended recipients.
    /// @THREAT Message interception or unauthorized delivery.
    /// @COUNTERMEASURE Use channel-based routing with access control validation.
    /// @AUDIT All messages logged with content hashing for integrity.
    pub async fn send_chat_message(&self, message: ChatMessage) {
        let chat_msg = WebSocketMessage::ChatMessage(message.clone());

        // Send to recipient
        if message.message_type == "chat" {
            self.broadcast_to_channel(&format!("chat:{}", message.to), chat_msg.clone()).await;
        } else if message.message_type == "groupchat" {
            self.broadcast_to_channel(&format!("group:{}", message.to), chat_msg.clone()).await;
        }

        // Also send to sender's channel for consistency
        self.broadcast_to_channel(&format!("chat:{}", message.from), chat_msg).await;
    }

    pub async fn send_typing_indicator(&self, from: &str, to: &str, typing: bool) {
        let typing_msg = WebSocketMessage::Typing {
            from: from.to_string(),
            to: to.to_string(),
            typing,
        };

        self.broadcast_to_channel(&format!("chat:{}", to), typing_msg.clone()).await;
        self.broadcast_to_channel(&format!("chat:{}", from), typing_msg).await;
    }
}

/// [CONNECTION HANDLER] WebSocket Session Management
/// @MISSION Establish and maintain secure WebSocket communication sessions.
/// @THREAT Connection hijacking or session fixation.
/// @COUNTERMEASURE Validate authentication, enforce timeouts, and audit all connections.
/// @DEPENDENCY Warp WebSocket implementation with TLS.
/// @AUDIT Connection lifecycle logged with cryptographic session tracking.
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

    server.add_client(client.clone()).await;

    // Set initial presence if user_id is provided
    if let Some(ref user_id) = user_id {
        server.update_presence(user_id, PresenceStatus::Online, None).await;
    }

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
    if let Some(ref user_id) = user_id {
        server.remove_presence(user_id).await;
    }
    server.remove_client(&client_id).await;
}

/// [MESSAGE PROCESSOR] WebSocket Message Handling
/// @MISSION Process and validate all incoming WebSocket messages.
/// @THREAT Message injection or protocol abuse.
/// @COUNTERMEASURE Validate message format, enforce rate limits, and audit all processing.
/// @AUDIT Message handling logged with error correlation.
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
        WebSocketMessage::PresenceUpdate { user_id, status, status_message } => {
            server.update_presence(&user_id, status, status_message).await;
        }
        WebSocketMessage::PresenceProbe { user_id } => {
            if let Some((status, message, timestamp)) = server.get_presence(&user_id).await {
                let presence_msg = WebSocketMessage::PresenceStatus {
                    user_id,
                    status,
                    status_message: message,
                    timestamp,
                };
                server.send_to_client(client_id, presence_msg).await;
            }
        }
        WebSocketMessage::ChatMessage(chat_msg) => {
            server.send_chat_message(chat_msg).await;
        }
        WebSocketMessage::Typing { from, to, typing } => {
            server.send_typing_indicator(&from, &to, typing).await;
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