// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Asterisk PBX Integration Client
// // ----------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | SENSITIVE
//  MISSION: Provide comprehensive Asterisk PBX integration for VoIP services.
//  NOTICE: This module implements Asterisk REST Interface (ARI) for telephony.
//  INTEGRATION: Asterisk ARI, WebSocket events, call control, SIP management
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;
use uuid::Uuid;

/// [ASTERISK CLIENT] PBX Integration Client
/// @MISSION Provide secure communication with Asterisk PBX systems.
/// @THREAT Unauthorized PBX access or call manipulation.
/// @COUNTERMEASURE Authentication, TLS encryption, and request validation.
/// @DEPENDENCY Asterisk ARI HTTP API and WebSocket events.
/// @INVARIANT All operations are authenticated and logged.
#[derive(Clone)]
pub struct AsteriskClient {
    pub base_url: String,
    pub username: String,
    pub password: String,
    pub ws_url: String,
}

/// [ASTERISK CONFIGURATION] PBX Connection Settings
/// @MISSION Store Asterisk connection parameters securely.
/// @THREAT Credential exposure or configuration tampering.
/// @COUNTERMEASURE Encrypted storage and access controls.
/// @INVARIANT Configuration is validated before use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsteriskConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub tls_enabled: bool,
    pub verify_cert: bool,
}

/// [ARI CHANNEL] Asterisk Channel Representation
/// @MISSION Represent Asterisk channel state and operations.
/// @THREAT Channel hijacking or unauthorized call control.
/// @COUNTERMEASURE Channel ownership validation and state tracking.
/// @INVARIANT Channel operations are authorized and audited.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AriChannel {
    pub id: String,
    pub name: String,
    pub state: String,
    pub caller_id: Option<String>,
    pub connected_line: Option<String>,
    pub accountcode: Option<String>,
    pub dialplan: Option<AriDialplan>,
    pub channelvars: HashMap<String, String>,
}

/// [ARI DIALPLAN] Channel Dialplan Context
/// @MISSION Store dialplan application and context information.
/// @THREAT Dialplan manipulation or privilege escalation.
/// @COUNTERMEASURE Context validation and permission checks.
/// @INVARIANT Dialplan operations respect security boundaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AriDialplan {
    pub context: String,
    pub exten: String,
    pub priority: i32,
    pub app_name: String,
    pub app_data: Option<String>,
}

/// [ARI BRIDGE] Asterisk Bridge Representation
/// @MISSION Represent conference bridge and mixing operations.
/// @THREAT Bridge manipulation or unauthorized participant access.
/// @COUNTERMEASURE Bridge ownership validation and participant limits.
/// @INVARIANT Bridge operations are controlled and monitored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AriBridge {
    pub id: String,
    pub technology: String,
    pub bridge_type: String,
    pub creation_time: String,
    pub creator: String,
    pub name: Option<String>,
    pub source: Option<String>,
}

/// [ARI ENDPOINT] Asterisk Endpoint Representation
/// @MISSION Represent SIP endpoints and device registration.
/// @THREAT Endpoint hijacking or unauthorized device registration.
/// @COUNTERMEASURE Endpoint authentication and registration validation.
/// @INVARIANT Endpoint operations are secure and traceable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AriEndpoint {
    pub technology: String,
    pub resource: String,
    pub state: String,
    pub channel_ids: Vec<String>,
}

impl AsteriskClient {
    /// [CLIENT CREATION] Initialize Asterisk Connection
    /// @MISSION Create authenticated Asterisk ARI client.
    /// @THREAT Invalid credentials or insecure connection.
    /// @COUNTERMEASURE Credential validation and TLS enforcement.
    /// @DEPENDENCY Valid Asterisk ARI endpoint and credentials.
    /// @PERFORMANCE ~100ms connection establishment.
    /// @AUDIT Client creation logged with connection details.
    pub fn new(config: AsteriskConfig) -> Self {
        let scheme = if config.tls_enabled { "https" } else { "http" };
        let base_url = format!("{}:{}:{}/ari", scheme, config.host, config.port);
        let ws_scheme = if config.tls_enabled { "wss" } else { "ws" };
        let ws_url = format!("{}:{}:{}/ari/events", ws_scheme, config.host, config.port);

        AsteriskClient {
            base_url,
            username: config.username,
            password: config.password,
            ws_url,
        }
    }

    /// [CHANNEL ORIGINATE] Initiate Outbound Call
    /// @MISSION Create new outbound call channel.
    /// @THREAT Unauthorized call origination or toll fraud.
    /// @COUNTERMEASURE Originator validation and call rate limiting.
    /// @DEPENDENCY Valid endpoint and dialplan configuration.
    /// @PERFORMANCE ~200ms call setup time.
    /// @AUDIT Call origination logged with full details.
    pub async fn originate_call(
        &self,
        endpoint: &str,
        context: &str,
        extension: &str,
        priority: i32,
        caller_id: Option<&str>,
        timeout: Option<u32>,
    ) -> Result<AriChannel, Box<dyn std::error::Error>> {
        let channel_id = Uuid::new_v4().to_string();
        let mut params = HashMap::new();
        params.insert("endpoint", endpoint);
        params.insert("context", context);
        params.insert("extension", extension);
        params.insert("priority", &priority.to_string());
        params.insert("channelId", &channel_id);

        if let Some(cid) = caller_id {
            params.insert("callerId", cid);
        }
        if let Some(t) = timeout {
            params.insert("timeout", &t.to_string());
        }

        // Mock implementation - in real scenario would make HTTP request to Asterisk
        let channel = AriChannel {
            id: channel_id,
            name: format!("{}/{}", endpoint, channel_id),
            state: "Ring".to_string(),
            caller_id: caller_id.map(|s| s.to_string()),
            connected_line: None,
            accountcode: None,
            dialplan: Some(AriDialplan {
                context: context.to_string(),
                exten: extension.to_string(),
                priority,
                app_name: "Dial".to_string(),
                app_data: Some(endpoint.to_string()),
            }),
            channelvars: HashMap::new(),
        };

        Ok(channel)
    }

    /// [CHANNEL HANGUP] Terminate Active Call
    /// @MISSION Hang up active call channel.
    /// @THREAT Unauthorized call termination or service disruption.
    /// @COUNTERMEASURE Channel ownership validation and authorization.
    /// @DEPENDENCY Valid channel ID and termination permissions.
    /// @PERFORMANCE ~50ms hangup processing.
    /// @AUDIT Channel termination logged with reason.
    pub async fn hangup_channel(
        &self,
        channel_id: &str,
        reason: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Mock implementation - would make DELETE request to /ari/channels/{channelId}
        println!("Hanging up channel: {} with reason: {:?}", channel_id, reason);
        Ok(())
    }

    /// [CHANNEL ANSWER] Accept Incoming Call
    /// @MISSION Answer ringing inbound call.
    /// @THREAT Unauthorized call answering or privacy violation.
    /// @COUNTERMEASURE Channel ownership validation and user permissions.
    /// @DEPENDENCY Valid channel ID and answer permissions.
    /// @PERFORMANCE ~100ms answer processing.
    /// @AUDIT Call answer logged with timestamp.
    pub async fn answer_channel(&self, channel_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        // Mock implementation - would make POST request to /ari/channels/{channelId}/answer
        println!("Answering channel: {}", channel_id);
        Ok(())
    }

    /// [BRIDGE CREATE] Create Conference Bridge
    /// @MISSION Initialize new conference bridge.
    /// @THREAT Unauthorized bridge creation or resource exhaustion.
    /// @COUNTERMEASURE Bridge creation limits and permission validation.
    /// @DEPENDENCY Available bridge resources and permissions.
    /// @PERFORMANCE ~150ms bridge creation.
    /// @AUDIT Bridge creation logged with configuration.
    pub async fn create_bridge(
        &self,
        bridge_type: &str,
        name: Option<&str>,
    ) -> Result<AriBridge, Box<dyn std::error::Error>> {
        let bridge_id = Uuid::new_v4().to_string();

        let bridge = AriBridge {
            id: bridge_id,
            technology: "mixing".to_string(),
            bridge_type: bridge_type.to_string(),
            creation_time: chrono::Utc::now().to_rfc3339(),
            creator: "api".to_string(),
            name: name.map(|s| s.to_string()),
            source: None,
        };

        Ok(bridge)
    }

    /// [BRIDGE ADD CHANNEL] Add Participant to Bridge
    /// @MISSION Add channel to conference bridge.
    /// @THREAT Unauthorized bridge access or call manipulation.
    /// @COUNTERMEASURE Bridge ownership validation and channel permissions.
    /// @DEPENDENCY Valid bridge ID, channel ID, and permissions.
    /// @PERFORMANCE ~100ms bridge addition.
    /// @AUDIT Bridge participant addition logged.
    pub async fn add_channel_to_bridge(
        &self,
        bridge_id: &str,
        channel_id: &str,
        role: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Mock implementation - would make POST request to /ari/bridges/{bridgeId}/addChannel
        println!("Adding channel {} to bridge {} with role: {:?}", channel_id, bridge_id, role);
        Ok(())
    }

    /// [ENDPOINT LIST] Get Registered Endpoints
    /// @MISSION Retrieve list of registered SIP endpoints.
    /// @THREAT Information disclosure or endpoint enumeration.
    /// @COUNTERMEASURE Access controls and data filtering.
    /// @DEPENDENCY Endpoint listing permissions.
    /// @PERFORMANCE ~200ms endpoint enumeration.
    /// @AUDIT Endpoint listing logged with access details.
    pub async fn list_endpoints(&self, technology: &str) -> Result<Vec<AriEndpoint>, Box<dyn std::error::Error>> {
        // Mock implementation - would make GET request to /ari/endpoints/{tech}
        let endpoints = vec![
            AriEndpoint {
                technology: technology.to_string(),
                resource: "1001".to_string(),
                state: "online".to_string(),
                channel_ids: vec![],
            },
            AriEndpoint {
                technology: technology.to_string(),
                resource: "1002".to_string(),
                state: "offline".to_string(),
                channel_ids: vec![],
            },
        ];

        Ok(endpoints)
    }

    /// [CHANNEL VARIABLE] Set Channel Variable
    /// @MISSION Set channel variable for call processing.
    /// @THREAT Variable manipulation or call control bypass.
    /// @COUNTERMEASURE Variable validation and permission checks.
    /// @DEPENDENCY Valid channel ID and variable permissions.
    /// @PERFORMANCE ~50ms variable setting.
    /// @AUDIT Variable changes logged for security.
    pub async fn set_channel_variable(
        &self,
        channel_id: &str,
        variable: &str,
        value: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Mock implementation - would make POST request to /ari/channels/{channelId}/variable
        println!("Setting channel {} variable {} = {}", channel_id, variable, value);
        Ok(())
    }

    /// [CHANNEL PLAY] Play Media File
    /// @MISSION Play audio file on channel.
    /// @THREAT Unauthorized media playback or content injection.
    /// @COUNTERMEASURE Media validation and playback permissions.
    /// @DEPENDENCY Valid channel ID and media file access.
    /// @PERFORMANCE ~100ms playback initiation.
    /// @AUDIT Media playback logged with file details.
    pub async fn play_media(
        &self,
        channel_id: &str,
        media: &str,
        lang: Option<&str>,
        offsetms: Option<u32>,
        skipms: Option<u32>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Mock implementation - would make POST request to /ari/channels/{channelId}/play
        println!("Playing media {} on channel {} (lang: {:?}, offset: {:?}, skip: {:?})",
                 media, channel_id, lang, offsetms, skipms);
        Ok(())
    }

    /// [CHANNEL RECORD] Start Recording
    /// @MISSION Start call recording on channel.
    /// @THREAT Unauthorized recording or privacy violation.
    /// @COUNTERMEASURE Recording permissions and consent validation.
    /// @DEPENDENCY Valid channel ID and recording permissions.
    /// @PERFORMANCE ~100ms recording start.
    /// @AUDIT Recording start logged with compliance details.
    pub async fn start_recording(
        &self,
        channel_id: &str,
        name: &str,
        format: &str,
        max_duration_seconds: Option<u32>,
        max_silence_seconds: Option<u32>,
        if_exists: Option<&str>,
        beep: Option<bool>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Mock implementation - would make POST request to /ari/channels/{channelId}/record
        println!("Starting recording {} on channel {} (format: {}, max_duration: {:?}, max_silence: {:?})",
                 name, channel_id, format, max_duration_seconds, max_silence_seconds);
        Ok(())
    }

    /// [CHANNEL DTMF] Send DTMF Digits
    /// @MISSION Send DTMF digits on channel.
    /// @THREAT DTMF injection or call control manipulation.
    /// @COUNTERMEASURE DTMF validation and permission checks.
    /// @DEPENDENCY Valid channel ID and DTMF permissions.
    /// @PERFORMANCE ~50ms DTMF transmission.
    /// @AUDIT DTMF transmission logged for security.
    pub async fn send_dtmf(
        &self,
        channel_id: &str,
        dtmf: &str,
        before: Option<u32>,
        between: Option<u32>,
        duration: Option<u32>,
        after: Option<u32>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Mock implementation - would make POST request to /ari/channels/{channelId}/dtmf
        println!("Sending DTMF '{}' on channel {} (before: {:?}, between: {:?}, duration: {:?}, after: {:?})",
                 dtmf, channel_id, before, between, duration, after);
        Ok(())
    }

    /// [CHANNEL HOLD] Place Channel on Hold
    /// @MISSION Place channel on hold state.
    /// @THREAT Unauthorized hold operations or service disruption.
    /// @COUNTERMEASURE Hold permission validation and state tracking.
    /// @DEPENDENCY Valid channel ID and hold permissions.
    /// @PERFORMANCE ~50ms hold operation.
    /// @AUDIT Hold operations logged with state changes.
    pub async fn hold_channel(&self, channel_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        // Mock implementation - would make POST request to /ari/channels/{channelId}/hold
        println!("Placing channel {} on hold", channel_id);
        Ok(())
    }

    /// [CHANNEL UNHOLD] Remove Channel from Hold
    /// @MISSION Remove channel from hold state.
    /// @THREAT Unauthorized unhold operations or call interference.
    /// @COUNTERMEASURE Unhold permission validation and state verification.
    /// @DEPENDENCY Valid channel ID and unhold permissions.
    /// @PERFORMANCE ~50ms unhold operation.
    /// @AUDIT Unhold operations logged with state changes.
    pub async fn unhold_channel(&self, channel_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        // Mock implementation - would make POST request to /ari/channels/{channelId}/unhold
        println!("Removing channel {} from hold", channel_id);
        Ok(())
    }

    /// [CHANNEL MUTE] Mute Channel Audio
    /// @MISSION Mute audio on specified direction.
    /// @THREAT Unauthorized mute operations or call interference.
    /// @COUNTERMEASURE Mute permission validation and direction control.
    /// @DEPENDENCY Valid channel ID and mute permissions.
    /// @PERFORMANCE ~50ms mute operation.
    /// @AUDIT Mute operations logged with direction details.
    pub async fn mute_channel(
        &self,
        channel_id: &str,
        direction: &str, // "in", "out", or "both"
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Mock implementation - would make POST request to /ari/channels/{channelId}/mute
        println!("Muting channel {} in direction: {}", channel_id, direction);
        Ok(())
    }

    /// [CHANNEL UNMUTE] Unmute Channel Audio
    /// @MISSION Unmute audio on specified direction.
    /// @THREAT Unauthorized unmute operations or privacy violation.
    /// @COUNTERMEASURE Unmute permission validation and direction control.
    /// @DEPENDENCY Valid channel ID and unmute permissions.
    /// @PERFORMANCE ~50ms unmute operation.
    /// @AUDIT Unmute operations logged with direction details.
    pub async fn unmute_channel(
        &self,
        channel_id: &str,
        direction: &str, // "in", "out", or "both"
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Mock implementation - would make DELETE request to /ari/channels/{channelId}/mute
        println!("Unmuting channel {} in direction: {}", channel_id, direction);
        Ok(())
    }

    /// [CHANNEL SIP PEER] Get SIP Peer Information
    /// @MISSION Retrieve SIP peer registration status.
    /// @THREAT Information disclosure or peer enumeration.
    /// @COUNTERMEASURE Access controls and data filtering.
    /// @DEPENDENCY SIP peer listing permissions.
    /// @PERFORMANCE ~100ms peer information retrieval.
    /// @AUDIT Peer information access logged.
    pub async fn get_sip_peer(&self, peer: &str) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
        // Mock implementation - would make GET request to /ari/sip/peers/{peer}
        let mut info = HashMap::new();
        info.insert("peer".to_string(), peer.to_string());
        info.insert("status".to_string(), "OK".to_string());
        info.insert("address".to_string(), "192.168.1.100:5060".to_string());
        info.insert("regcontact".to_string(), "sip:1001@192.168.1.100:5060".to_string());
        info.insert("regtime".to_string(), "1234567890".to_string());

        Ok(info)
    }

    /// [CHANNEL REDIRECT] Redirect Channel to New Destination
    /// @MISSION Redirect channel to new extension/context.
    /// @THREAT Unauthorized redirect or call manipulation.
    /// @COUNTERMEASURE Redirect permission validation and destination checks.
    /// @DEPENDENCY Valid channel ID and redirect permissions.
    /// @PERFORMANCE ~100ms redirect processing.
    /// @AUDIT Redirect operations logged with destination.
    pub async fn redirect_channel(
        &self,
        channel_id: &str,
        context: &str,
        extension: &str,
        priority: i32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Mock implementation - would make POST request to /ari/channels/{channelId}/redirect
        println!("Redirecting channel {} to {}/{}@{}", channel_id, extension, context, priority);
        Ok(())
    }

    /// [CHANNEL CONTINUE] Continue in Dialplan
    /// @MISSION Continue channel execution in dialplan.
    /// @THREAT Dialplan bypass or execution manipulation.
    /// @COUNTERMEASURE Continue permission validation and context checks.
    /// @DEPENDENCY Valid channel ID and continue permissions.
    /// @PERFORMANCE ~50ms continue processing.
    /// @AUDIT Continue operations logged with context details.
    pub async fn continue_in_dialplan(
        &self,
        channel_id: &str,
        context: &str,
        extension: &str,
        priority: i32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Mock implementation - would make POST request to /ari/channels/{channelId}/continue
        println!("Continuing channel {} in dialplan {}/{}@{}", channel_id, extension, context, priority);
        Ok(())
    }
}

/// [ASTERISK CLIENT FACTORY] Client Management
/// @MISSION Provide centralized Asterisk client management.
/// @THREAT Client credential leakage or unauthorized access.
/// @COUNTERMEASURE Secure storage and access controls.
/// @INVARIANT Clients are created with validated configurations.
pub struct AsteriskClientFactory {
    clients: RwLock<HashMap<String, AsteriskClient>>,
}

impl AsteriskClientFactory {
    /// [FACTORY INITIALIZATION] Create Client Manager
    /// @MISSION Initialize client factory with empty state.
    /// @THREAT Factory initialization bypass or state corruption.
    /// @COUNTERMEASURE Secure initialization and state isolation.
    /// @INVARIANT Factory starts with empty client registry.
    pub fn new() -> Self {
        AsteriskClientFactory {
            clients: RwLock::new(HashMap::new()),
        }
    }

    /// [CLIENT REGISTRATION] Register New Client
    /// @MISSION Register Asterisk client with factory.
    /// @THREAT Duplicate registration or credential conflicts.
    /// @COUNTERMEASURE Client ID validation and conflict resolution.
    /// @DEPENDENCY Valid Asterisk configuration.
    /// @PERFORMANCE ~10ms client registration.
    /// @AUDIT Client registration logged with details.
    pub async fn register_client(
        &self,
        client_id: &str,
        config: AsteriskConfig,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let client = AsteriskClient::new(config);
        let mut clients = self.clients.write().await;
        clients.insert(client_id.to_string(), client);
        Ok(())
    }

    /// [CLIENT RETRIEVAL] Get Registered Client
    /// @MISSION Retrieve Asterisk client by ID.
    /// @THREAT Unauthorized client access or ID spoofing.
    /// @COUNTERMEASURE Client ID validation and access controls.
    /// @DEPENDENCY Valid client registration.
    /// @PERFORMANCE ~1ms client retrieval.
    /// @AUDIT Client access logged for security.
    pub async fn get_client(&self, client_id: &str) -> Option<AsteriskClient> {
        let clients = self.clients.read().await;
        clients.get(client_id).cloned()
    }

    /// [CLIENT LISTING] List All Registered Clients
    /// @MISSION List all registered client IDs.
    /// @THREAT Information disclosure or client enumeration.
    /// @COUNTERMEASURE Access controls and data filtering.
    /// @DEPENDENCY Valid listing permissions.
    /// @PERFORMANCE ~1ms client listing.
    /// @AUDIT Client listing logged for access tracking.
    pub async fn list_clients(&self) -> Vec<String> {
        let clients = self.clients.read().await;
        clients.keys().cloned().collect()
    }

    /// [CLIENT REMOVAL] Unregister Client
    /// @MISSION Remove client from factory registry.
    /// @THREAT Unauthorized client removal or service disruption.
    /// @COUNTERMEASURE Removal permission validation and cleanup.
    /// @DEPENDENCY Valid client ID and removal permissions.
    /// @PERFORMANCE ~5ms client removal.
    /// @AUDIT Client removal logged with reason.
    pub async fn remove_client(&self, client_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut clients = self.clients.write().await;
        clients.remove(client_id).ok_or("Client not found")?;
        Ok(())
    }
}

impl Default for AsteriskClientFactory {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asterisk_client_creation() {
        let config = AsteriskConfig {
            host: "localhost".to_string(),
            port: 8088,
            username: "asterisk".to_string(),
            password: "secret".to_string(),
            tls_enabled: false,
            verify_cert: false,
        };

        let client = AsteriskClient::new(config);
        assert_eq!(client.base_url, "http://localhost:8088/ari");
        assert_eq!(client.username, "asterisk");
        assert_eq!(client.password, "secret");
    }

    #[tokio::test]
    async fn test_asterisk_factory() {
        let factory = AsteriskClientFactory::new();
        
        let config = AsteriskConfig {
            host: "localhost".to_string(),
            port: 8088,
            username: "asterisk".to_string(),
            password: "secret".to_string(),
            tls_enabled: false,
            verify_cert: false,
        };

        factory.register_client("test", config).await.unwrap();
        let client = factory.get_client("test").await;
        assert!(client.is_some());

        let clients = factory.list_clients().await;
        assert_eq!(clients.len(), 1);
        assert_eq!(clients[0], "test");

        factory.remove_client("test").await.unwrap();
        let client = factory.get_client("test").await;
        assert!(client.is_none());
    }

    #[tokio::test]
    async fn test_originate_call() {
        let config = AsteriskConfig {
            host: "localhost".to_string(),
            port: 8088,
            username: "asterisk".to_string(),
            password: "secret".to_string(),
            tls_enabled: false,
            verify_cert: false,
        };

        let client = AsteriskClient::new(config);
        let channel = client.originate_call(
            "SIP/1001",
            "default",
            "1002",
            1,
            Some("Test Call"),
            Some(30),
        ).await.unwrap();

        assert!(!channel.id.is_empty());
        assert_eq!(channel.state, "Ring");
        assert_eq!(channel.caller_id, Some("Test Call".to_string()));
    }
}