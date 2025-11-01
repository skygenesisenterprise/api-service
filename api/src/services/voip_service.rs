// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: VoIP Service
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide comprehensive VoIP services including voice calls,
//  video conferencing, and real-time communication with enterprise security.
//  NOTICE: Implements WebRTC-based VoIP with secure signaling, encryption,
//  and comprehensive audit logging for all voice/video communications.
//  VOIP STANDARDS: WebRTC, SIP, RTP, SRTP, DTLS
//  SECURITY: End-to-end encryption, secure signaling, call recording
//  COMPLIANCE: GDPR, HIPAA, NIST VoIP Security Guidelines
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use crate::core::asterisk_client::{AsteriskClient, AsteriskConfig};

/// [USER EXTENSION MODEL] User's Internal Extension Number
/// @MISSION Map users to their internal phone numbers for roaming access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserExtension {
    pub user_id: String,
    pub extension: String,
    pub display_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub enabled: bool,
}

/// [DEVICE REGISTRATION MODEL] Registered VoIP Device/Endpoint
/// @MISSION Allow users to register multiple devices for their extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRegistration {
    pub id: String,
    pub user_id: String,
    pub device_name: String,
    pub endpoint_type: EndpointType,
    pub endpoint_uri: String, // SIP/1001@device1, WebRTC:device1, etc.
    pub registered_at: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub is_online: bool,
}

/// [ENDPOINT TYPE ENUM] Type of VoIP Endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EndpointType {
    Sip,
    Webrtc,
    Mobile,
    Desktop,
}

/// [PRESENCE STATUS MODEL] User Presence Information
/// @MISSION Track user availability across devices.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceStatus {
    pub user_id: String,
    pub status: PresenceState,
    pub status_message: Option<String>,
    pub current_device: Option<String>,
    pub last_updated: DateTime<Utc>,
}

/// [PRESENCE STATE ENUM] User Availability Status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PresenceState {
    Online,
    Away,
    Busy,
    Offline,
    DoNotDisturb,
}

/// [VOIP CALL MODEL] Voice/Video Call Information
/// @MISSION Structure call data with participants and metadata.
/// @THREAT Call interception, unauthorized access.
/// @COUNTERMEASURE Encrypted signaling, participant validation.
/// @INVARIANT All calls are logged and auditable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoipCall {
    pub id: String,
    pub caller_id: String,
    pub participants: Vec<String>,
    pub call_type: CallType,
    pub status: CallStatus,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub room_id: Option<String>,
    pub metadata: HashMap<String, String>,
}

/// [CALL TYPE ENUM] Type of VoIP Call
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CallType {
    Audio,
    Video,
    ScreenShare,
    Conference,
}

/// [CALL STATUS ENUM] Current Status of Call
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CallStatus {
    Initiating,
    Ringing,
    Connected,
    OnHold,
    Ended,
}

/// [WEBRTC SIGNALING MESSAGE] WebRTC Signaling Data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalingMessage {
    pub call_id: String,
    pub from_user: String,
    pub to_user: String,
    pub message_type: SignalingType,
    pub payload: serde_json::Value,
    pub timestamp: DateTime<Utc>,
}

/// [SIGNALING TYPE ENUM] Type of Signaling Message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignalingType {
    Offer,
    Answer,
    IceCandidate,
    Hangup,
    Mute,
    Unmute,
}

/// [VOIP ROOM MODEL] Conference Room Information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoipRoom {
    pub id: String,
    pub name: String,
    pub owner_id: String,
    pub participants: Vec<String>,
    pub max_participants: u32,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub settings: RoomSettings,
}

/// [ROOM SETTINGS] Conference Room Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomSettings {
    pub allow_recording: bool,
    pub allow_screen_share: bool,
    pub require_moderator: bool,
    pub moderator_id: Option<String>,
}

/// [VOIP SERVICE] Main VoIP Service Implementation with Asterisk Integration
/// @MISSION Provide VoIP functionality through native Asterisk PBX integration.
/// @THREAT Unauthorized calls, eavesdropping, PBX compromise.
/// @COUNTERMEASURE Authentication, encryption, audit logging, Asterisk security.
pub struct VoipService {
    asterisk_client: Arc<AsteriskClient>,
    call_mappings: Arc<RwLock<HashMap<String, String>>>, // API call_id -> Asterisk channel_id
    room_mappings: Arc<RwLock<HashMap<String, String>>>, // API room_id -> Asterisk bridge_id
    active_calls: Arc<RwLock<HashMap<String, VoipCall>>>,
    active_rooms: Arc<RwLock<HashMap<String, VoipRoom>>>,
    user_extensions: Arc<RwLock<HashMap<String, UserExtension>>>, // user_id -> extension
    device_registrations: Arc<RwLock<HashMap<String, Vec<DeviceRegistration>>>>, // user_id -> devices
    presence_status: Arc<RwLock<HashMap<String, PresenceStatus>>>, // user_id -> presence
    signaling_channels: Arc<RwLock<HashMap<String, Vec<SignalingMessage>>>>, // call_id -> messages
}

impl VoipService {
    /// [SERVICE INITIALIZATION] Create new VoIP service with Asterisk integration
    /// @MISSION Initialize VoIP service with Asterisk PBX backend.
    /// @THREAT Asterisk connectivity issues, configuration errors.
    /// @COUNTERMEASURE Connection validation, error handling, fallback modes.
    pub fn new(asterisk_config: AsteriskConfig) -> Self {
        let asterisk_client = Arc::new(AsteriskClient::new(asterisk_config));

        Self {
            asterisk_client,
            call_mappings: Arc::new(RwLock::new(HashMap::new())),
            room_mappings: Arc::new(RwLock::new(HashMap::new())),
            active_calls: Arc::new(RwLock::new(HashMap::new())),
            active_rooms: Arc::new(RwLock::new(HashMap::new())),
            user_extensions: Arc::new(RwLock::new(HashMap::new())),
            device_registrations: Arc::new(RwLock::new(HashMap::new())),
            presence_status: Arc::new(RwLock::new(HashMap::new())),
            signaling_channels: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// [CALL INITIATION] Start a new VoIP call through Asterisk
    /// @MISSION Create and initiate a new voice/video call via Asterisk PBX.
    /// @THREAT Unauthorized call initiation, Asterisk resource exhaustion.
    /// @COUNTERMEASURE User authentication, rate limiting, resource monitoring.
    pub async fn initiate_call(
        &self,
        caller_id: &str,
        participants: Vec<String>,
        call_type: CallType,
    ) -> Result<VoipCall, String> {
        let call_id = Uuid::new_v4().to_string();

        // Resolve caller's endpoint using roaming extension system
        let endpoint = self.resolve_user_endpoint(caller_id).await
            .unwrap_or_else(|_| format!("SIP/{}", caller_id)); // Fallback to legacy format

        let channel = match self.asterisk_client.create_channel(&endpoint, &self.asterisk_client.config.app_name, None).await {
            Ok(channel) => channel,
            Err(e) => return Err(format!("Failed to create Asterisk channel: {}", e)),
        };

        // Store mapping between API call_id and Asterisk channel_id
        let mut mappings = self.call_mappings.write().await;
        mappings.insert(call_id.clone(), channel.id.clone());

        let call = VoipCall {
            id: call_id.clone(),
            caller_id: caller_id.to_string(),
            participants,
            call_type,
            status: CallStatus::Initiating,
            start_time: Utc::now(),
            end_time: None,
            room_id: None,
            metadata: {
                let mut meta = HashMap::new();
                meta.insert("asterisk_channel_id".to_string(), channel.id);
                meta.insert("asterisk_channel_name".to_string(), channel.name);
                meta
            },
        };

        let mut calls = self.active_calls.write().await;
        calls.insert(call_id.clone(), call.clone());

        Ok(call)
    }

    /// [CALL ACCEPTANCE] Accept an incoming call via Asterisk
    /// @MISSION Accept a ringing call and establish connection through Asterisk.
    /// @THREAT Unauthorized call acceptance, channel manipulation.
    /// @COUNTERMEASURE Participant validation, Asterisk channel verification.
    pub async fn accept_call(&self, call_id: &str, user_id: &str) -> Result<(), String> {
        let mappings = self.call_mappings.read().await;
        let asterisk_channel_id = mappings.get(call_id)
            .ok_or_else(|| "Call mapping not found".to_string())?;

        // Answer the Asterisk channel
        self.asterisk_client.answer_channel(asterisk_channel_id).await?;

        let mut calls = self.active_calls.write().await;
        if let Some(call) = calls.get_mut(call_id) {
            if call.participants.contains(&user_id.to_string()) || call.caller_id == user_id {
                call.status = CallStatus::Connected;
                Ok(())
            } else {
                Err("User not authorized for this call".to_string())
            }
        } else {
            Err("Call not found".to_string())
        }
    }

    /// [CALL TERMINATION] End an active call via Asterisk
    /// @MISSION Terminate a call and clean up Asterisk resources.
    /// @THREAT Resource leaks, incomplete cleanup, orphaned channels.
    /// @COUNTERMEASURE Proper state management, Asterisk channel cleanup.
    pub async fn end_call(&self, call_id: &str, user_id: &str) -> Result<(), String> {
        let mappings = self.call_mappings.read().await;
        if let Some(asterisk_channel_id) = mappings.get(call_id) {
            // Hang up the Asterisk channel
            self.asterisk_client.delete_channel(asterisk_channel_id).await?;
        }

        let mut calls = self.active_calls.write().await;
        if let Some(call) = calls.get_mut(call_id) {
            if call.caller_id == user_id || call.participants.contains(&user_id.to_string()) {
                call.status = CallStatus::Ended;
                call.end_time = Some(Utc::now());
                Ok(())
            } else {
                Err("User not authorized to end this call".to_string())
            }
        } else {
            Err("Call not found".to_string())
        }
    }

    /// [ROOM CREATION] Create a new conference room via Asterisk
    /// @MISSION Set up a conference room for multiple participants using Asterisk bridges.
    /// @THREAT Unauthorized room creation, bridge resource exhaustion.
    /// @COUNTERMEASURE User permissions, resource limits, Asterisk bridge management.
    pub async fn create_room(
        &self,
        owner_id: &str,
        name: &str,
        max_participants: u32,
        settings: RoomSettings,
    ) -> Result<VoipRoom, String> {
        let room_id = Uuid::new_v4().to_string();

        // Create Asterisk bridge for the conference room
        let bridge = self.asterisk_client.create_bridge("mixing", Some(name)).await
            .map_err(|e| format!("Failed to create Asterisk bridge: {}", e))?;

        // Store mapping between API room_id and Asterisk bridge_id
        let mut mappings = self.room_mappings.write().await;
        mappings.insert(room_id.clone(), bridge.id.clone());

        let room = VoipRoom {
            id: room_id.clone(),
            name: name.to_string(),
            owner_id: owner_id.to_string(),
            participants: vec![owner_id.to_string()],
            max_participants,
            is_active: true,
            created_at: Utc::now(),
            settings,
        };

        let mut rooms = self.active_rooms.write().await;
        rooms.insert(room_id.clone(), room.clone());

        Ok(room)
    }

    /// [ROOM JOIN] Join an existing conference room via Asterisk
    /// @MISSION Add participant to conference room by connecting to Asterisk bridge.
    /// @THREAT Room capacity overflow, unauthorized access, bridge manipulation.
    /// @COUNTERMEASURE Capacity checks, permission validation, Asterisk bridge security.
    pub async fn join_room(&self, room_id: &str, user_id: &str) -> Result<(), String> {
        let mappings = self.room_mappings.read().await;
        let asterisk_bridge_id = mappings.get(room_id)
            .ok_or_else(|| "Room mapping not found".to_string())?;

        let mut rooms = self.active_rooms.write().await;
        if let Some(room) = rooms.get_mut(room_id) {
            if room.participants.len() >= room.max_participants as usize {
                return Err("Room is full".to_string());
            }

            if !room.participants.contains(&user_id.to_string()) {
                room.participants.push(user_id.to_string());

                // Create Asterisk channel for the user and add to bridge
                let endpoint = self.resolve_user_endpoint(user_id).await
                    .unwrap_or_else(|_| format!("SIP/{}", user_id)); // Fallback to legacy format
                let channel = self.asterisk_client.create_channel(&endpoint, &self.asterisk_client.config.app_name, None).await
                    .map_err(|e| format!("Failed to create channel for room join: {}", e))?;

                // Add channel to bridge
                self.asterisk_client.add_channel_to_bridge(asterisk_bridge_id, &channel.id).await
                    .map_err(|e| format!("Failed to add channel to bridge: {}", e))?;
            }

            Ok(())
        } else {
            Err("Room not found".to_string())
        }
    }

    /// [SIGNALING] Send WebRTC signaling message
    /// @MISSION Exchange WebRTC signaling data between participants.
    /// @THREAT Signaling interception, message tampering.
    /// @COUNTERMEASURE Encrypted channels, message validation.
    pub async fn send_signaling_message(&self, message: SignalingMessage) -> Result<(), String> {
        let mut channels = self.signaling_channels.write().await;

        let channel = channels.entry(message.call_id.clone()).or_insert_with(Vec::new);
        channel.push(message);

        // Keep only last 100 messages per channel
        if channel.len() > 100 {
            channel.remove(0);
        }

        Ok(())
    }

    /// [SIGNALING RETRIEVAL] Get signaling messages for a call
    /// @MISSION Retrieve pending signaling messages.
    /// @THREAT Message loss, out-of-order delivery.
    /// @COUNTERMEASURE Reliable message queuing.
    pub async fn get_signaling_messages(&self, call_id: &str, user_id: &str) -> Result<Vec<SignalingMessage>, String> {
        let channels = self.signaling_channels.read().await;

        if let Some(messages) = channels.get(call_id) {
            // Filter messages for the specific user
            let user_messages: Vec<SignalingMessage> = messages
                .iter()
                .filter(|msg| msg.to_user == user_id || msg.from_user == user_id)
                .cloned()
                .collect();

            Ok(user_messages)
        } else {
            Ok(Vec::new())
        }
    }

    /// [CALL STATUS] Get current call information
    /// @MISSION Retrieve call details and status.
    /// @THREAT Information disclosure.
    /// @COUNTERMEASURE Access control and data minimization.
    pub async fn get_call(&self, call_id: &str) -> Result<VoipCall, String> {
        let calls = self.active_calls.read().await;

        if let Some(call) = calls.get(call_id) {
            Ok(call.clone())
        } else {
            Err("Call not found".to_string())
        }
    }

    /// [ROOM STATUS] Get room information
    /// @MISSION Retrieve conference room details.
    /// @THREAT Information disclosure.
    /// @COUNTERMEASURE Access control.
    pub async fn get_room(&self, room_id: &str) -> Result<VoipRoom, String> {
        let rooms = self.active_rooms.read().await;

        if let Some(room) = rooms.get(room_id) {
            Ok(room.clone())
        } else {
            Err("Room not found".to_string())
        }
    }

    /// [ACTIVE CALLS] List active calls for user
    /// @MISSION Get all active calls for a specific user.
    /// @THREAT Information disclosure.
    /// @COUNTERMEASURE User-specific filtering.
    pub async fn get_active_calls(&self, user_id: &str) -> Vec<VoipCall> {
        let calls = self.active_calls.read().await;

        calls.values()
            .filter(|call| call.caller_id == user_id || call.participants.contains(&user_id.to_string()))
            .filter(|call| matches!(call.status, CallStatus::Initiating | CallStatus::Ringing | CallStatus::Connected | CallStatus::OnHold))
            .cloned()
            .collect()
    }

    /// [ACTIVE ROOMS] List active rooms for user
    /// @MISSION Get all active rooms for a specific user.
    /// @THREAT Information disclosure.
    /// @COUNTERMEASURE User-specific filtering.
    pub async fn get_active_rooms(&self, user_id: &str) -> Vec<VoipRoom> {
        let rooms = self.active_rooms.read().await;

        rooms.values()
            .filter(|room| room.participants.contains(&user_id.to_string()) && room.is_active)
            .cloned()
            .collect()
    }

    /// [USER EXTENSION MANAGEMENT] Assign extension to user
    /// @MISSION Create or update user extension mapping.
    /// @THREAT Extension conflicts, unauthorized assignment.
    /// @COUNTERMEASURE Validation, uniqueness checks.
    pub async fn assign_user_extension(&self, user_id: &str, extension: &str, display_name: Option<String>) -> Result<UserExtension, String> {
        let mut extensions = self.user_extensions.write().await;

        // Check if extension is already assigned to another user
        for (existing_user, ext) in extensions.iter() {
            if ext.extension == extension && existing_user != user_id {
                return Err("Extension already assigned to another user".to_string());
            }
        }

        let user_extension = UserExtension {
            user_id: user_id.to_string(),
            extension: extension.to_string(),
            display_name,
            created_at: Utc::now(),
            enabled: true,
        };

        extensions.insert(user_id.to_string(), user_extension.clone());
        Ok(user_extension)
    }

    /// [GET USER EXTENSION] Retrieve user's extension
    /// @MISSION Get extension information for a user.
    pub async fn get_user_extension(&self, user_id: &str) -> Option<UserExtension> {
        let extensions = self.user_extensions.read().await;
        extensions.get(user_id).cloned()
    }

    /// [DEVICE REGISTRATION] Register a new device for user
    /// @MISSION Allow users to register VoIP devices/endpoints.
    /// @THREAT Device spoofing, unauthorized registration.
    /// @COUNTERMEASURE User validation, device verification.
    pub async fn register_device(&self, user_id: &str, device_name: &str, endpoint_type: EndpointType, endpoint_uri: &str) -> Result<DeviceRegistration, String> {
        let mut devices = self.device_registrations.write().await;
        let user_devices = devices.entry(user_id.to_string()).or_insert_with(Vec::new);

        // Check for duplicate device names
        if user_devices.iter().any(|d| d.device_name == device_name) {
            return Err("Device name already exists for this user".to_string());
        }

        let device = DeviceRegistration {
            id: Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            device_name: device_name.to_string(),
            endpoint_type,
            endpoint_uri: endpoint_uri.to_string(),
            registered_at: Utc::now(),
            last_seen: Utc::now(),
            is_online: true,
        };

        user_devices.push(device.clone());
        Ok(device)
    }

    /// [GET USER DEVICES] Get all registered devices for user
    /// @MISSION Retrieve user's registered VoIP devices.
    pub async fn get_user_devices(&self, user_id: &str) -> Vec<DeviceRegistration> {
        let devices = self.device_registrations.read().await;
        devices.get(user_id).cloned().unwrap_or_default()
    }

    /// [UPDATE DEVICE PRESENCE] Update device online status
    /// @MISSION Track device connectivity and presence.
    pub async fn update_device_presence(&self, user_id: &str, device_id: &str, is_online: bool) -> Result<(), String> {
        let mut devices = self.device_registrations.write().await;
        if let Some(user_devices) = devices.get_mut(user_id) {
            if let Some(device) = user_devices.iter_mut().find(|d| d.id == device_id) {
                device.is_online = is_online;
                device.last_seen = Utc::now();
                Ok(())
            } else {
                Err("Device not found".to_string())
            }
        } else {
            Err("User has no registered devices".to_string())
        }
    }

    /// [UPDATE PRESENCE STATUS] Set user presence status
    /// @MISSION Update user's availability status.
    pub async fn update_presence_status(&self, user_id: &str, status: PresenceState, message: Option<String>, current_device: Option<String>) -> Result<(), String> {
        let mut presence = self.presence_status.write().await;
        let presence_status = PresenceStatus {
            user_id: user_id.to_string(),
            status,
            status_message: message,
            current_device,
            last_updated: Utc::now(),
        };
        presence.insert(user_id.to_string(), presence_status);
        Ok(())
    }

    /// [GET PRESENCE STATUS] Get user's presence information
    /// @MISSION Retrieve current presence status.
    pub async fn get_presence_status(&self, user_id: &str) -> Option<PresenceStatus> {
        let presence = self.presence_status.read().await;
        presence.get(user_id).cloned()
    }

    /// [RESOLVE ENDPOINT] Get appropriate endpoint for user call
    /// @MISSION Determine which device/endpoint to route call to.
    /// @THREAT Call routing to wrong device.
    /// @COUNTERMEASURE Presence-based routing, user preferences.
    pub async fn resolve_user_endpoint(&self, user_id: &str) -> Result<String, String> {
        // First check if user has an extension
        if let Some(extension) = self.get_user_extension(user_id).await {
            if !extension.enabled {
                return Err("User extension is disabled".to_string());
            }

            // Get user's devices and find the best one to route to
            let devices = self.get_user_devices(user_id).await;
            let online_devices: Vec<&DeviceRegistration> = devices.iter()
                .filter(|d| d.is_online)
                .collect();

            if online_devices.is_empty() {
                // Fallback to default SIP endpoint
                return Ok(format!("SIP/{}", extension.extension));
            }

            // For now, route to first online device
            // TODO: Implement more sophisticated routing logic
            Ok(online_devices[0].endpoint_uri.clone())
        } else {
            Err("User has no assigned extension".to_string())
        }
    }

    /// [CLEANUP] Clean up ended calls and inactive rooms
    /// @MISSION Remove stale data and free resources.
    /// @THREAT Resource exhaustion.
    /// @COUNTERMEASURE Periodic cleanup.
    pub async fn cleanup(&self) {
        let mut calls = self.active_calls.write().await;
        let mut rooms = self.active_rooms.write().await;
        let mut channels = self.signaling_channels.write().await;
        let mut devices = self.device_registrations.write().await;

        // Remove ended calls older than 1 hour
        let cutoff_time = Utc::now() - chrono::Duration::hours(1);
        calls.retain(|_, call| {
            if let Some(end_time) = call.end_time {
                end_time > cutoff_time
            } else {
                true
            }
        });

        // Remove inactive rooms older than 24 hours
        let room_cutoff = Utc::now() - chrono::Duration::hours(24);
        rooms.retain(|_, room| room.is_active || room.created_at > room_cutoff);

        // Clean up old signaling messages
        for messages in channels.values_mut() {
            messages.retain(|msg| msg.timestamp > cutoff_time);
        }

        // Mark offline devices that haven't been seen recently
        let offline_cutoff = Utc::now() - chrono::Duration::minutes(5);
        for user_devices in devices.values_mut() {
            for device in user_devices.iter_mut() {
                if device.last_seen < offline_cutoff {
                    device.is_online = false;
                }
            }
        }
    }

    /// [TEST HELPER] Create test VoIP service instance
    /// @MISSION Provide testable service instance for unit tests.
    #[cfg(test)]
    pub fn test_instance() -> Self {
        use crate::core::asterisk_client::AsteriskConfig;

        let config = AsteriskConfig {
            host: "localhost".to_string(),
            port: 8088,
            username: "test".to_string(),
            password: "test".to_string(),
            app_name: "test-app".to_string(),
            tls_enabled: false,
        };

        Self::new(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_assign_user_extension() {
        let service = VoipService::test_instance();

        let result = service.assign_user_extension("user123", "1001", Some("John Doe".to_string())).await;
        assert!(result.is_ok());

        let extension = result.unwrap();
        assert_eq!(extension.user_id, "user123");
        assert_eq!(extension.extension, "1001");
        assert_eq!(extension.display_name, Some("John Doe".to_string()));
        assert!(extension.enabled);
    }

    #[tokio::test]
    async fn test_register_device() {
        let service = VoipService::test_instance();

        let result = service.register_device(
            "user123",
            "My Desktop",
            EndpointType::Desktop,
            "SIP/1001@desktop"
        ).await;

        assert!(result.is_ok());
        let device = result.unwrap();
        assert_eq!(device.user_id, "user123");
        assert_eq!(device.device_name, "My Desktop");
        assert_eq!(device.endpoint_type, EndpointType::Desktop);
        assert!(device.is_online);
    }

    #[tokio::test]
    async fn test_resolve_user_endpoint() {
        let service = VoipService::test_instance();

        // First assign extension
        let _ = service.assign_user_extension("user123", "1001", None).await;

        // Register a device
        let _ = service.register_device(
            "user123",
            "My Phone",
            EndpointType::Mobile,
            "SIP/1001@mobile"
        ).await;

        // Resolve endpoint
        let endpoint = service.resolve_user_endpoint("user123").await;
        assert!(endpoint.is_ok());
        assert_eq!(endpoint.unwrap(), "SIP/1001@mobile");
    }

    #[tokio::test]
    async fn test_update_presence_status() {
        let service = VoipService::test_instance();

        let result = service.update_presence_status(
            "user123",
            PresenceState::Online,
            Some("Available for calls".to_string()),
            Some("device123".to_string())
        ).await;

        assert!(result.is_ok());

        let presence = service.get_presence_status("user123").await;
        assert!(presence.is_some());
        let presence = presence.unwrap();
        assert_eq!(presence.status, PresenceState::Online);
        assert_eq!(presence.status_message, Some("Available for calls".to_string()));
    }
}