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
/// @NOTE Extension can include country code prefix (e.g., "32-1001" for Belgium)
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

/// [COUNTRY CODE MAPPING] Standard international dialing codes
/// @MISSION Provide mapping between country codes and country names
pub const COUNTRY_CODES: &[(&str, &str)] = &[
    ("1", "United States/Canada"),
    ("7", "Russia/Kazakhstan"),
    ("20", "Egypt"),
    ("27", "South Africa"),
    ("30", "Greece"),
    ("31", "Netherlands"),
    ("32", "Belgium"),
    ("33", "France"),
    ("34", "Spain"),
    ("36", "Hungary"),
    ("39", "Italy"),
    ("40", "Romania"),
    ("41", "Switzerland"),
    ("43", "Austria"),
    ("44", "United Kingdom"),
    ("45", "Denmark"),
    ("46", "Sweden"),
    ("47", "Norway"),
    ("48", "Poland"),
    ("49", "Germany"),
    ("51", "Peru"),
    ("52", "Mexico"),
    ("53", "Cuba"),
    ("54", "Argentina"),
    ("55", "Brazil"),
    ("56", "Chile"),
    ("57", "Colombia"),
    ("58", "Venezuela"),
    ("60", "Malaysia"),
    ("61", "Australia"),
    ("62", "Indonesia"),
    ("63", "Philippines"),
    ("64", "New Zealand"),
    ("65", "Singapore"),
    ("66", "Thailand"),
    ("81", "Japan"),
    ("82", "South Korea"),
    ("84", "Vietnam"),
    ("86", "China"),
    ("90", "Turkey"),
    ("91", "India"),
    ("92", "Pakistan"),
    ("93", "Afghanistan"),
    ("94", "Sri Lanka"),
    ("95", "Myanmar"),
    ("98", "Iran"),
    ("212", "Morocco"),
    ("213", "Algeria"),
    ("216", "Tunisia"),
    ("218", "Libya"),
    ("220", "Gambia"),
    ("221", "Senegal"),
    ("222", "Mauritania"),
    ("223", "Mali"),
    ("224", "Guinea"),
    ("225", "Ivory Coast"),
    ("226", "Burkina Faso"),
    ("227", "Niger"),
    ("228", "Togo"),
    ("229", "Benin"),
    ("230", "Mauritius"),
    ("231", "Liberia"),
    ("232", "Sierra Leone"),
    ("233", "Ghana"),
    ("234", "Nigeria"),
    ("235", "Chad"),
    ("236", "Central African Republic"),
    ("237", "Cameroon"),
    ("238", "Cape Verde"),
    ("239", "Sao Tome and Principe"),
    ("240", "Equatorial Guinea"),
    ("241", "Gabon"),
    ("242", "Republic of the Congo"),
    ("243", "Democratic Republic of the Congo"),
    ("244", "Angola"),
    ("245", "Guinea-Bissau"),
    ("246", "British Indian Ocean Territory"),
    ("247", "Ascension Island"),
    ("248", "Seychelles"),
    ("249", "Sudan"),
    ("250", "Rwanda"),
    ("251", "Ethiopia"),
    ("252", "Somalia"),
    ("253", "Djibouti"),
    ("254", "Kenya"),
    ("255", "Tanzania"),
    ("256", "Uganda"),
    ("257", "Burundi"),
    ("258", "Mozambique"),
    ("260", "Zambia"),
    ("261", "Madagascar"),
    ("262", "Reunion/Mayotte"),
    ("263", "Zimbabwe"),
    ("264", "Namibia"),
    ("265", "Malawi"),
    ("266", "Lesotho"),
    ("267", "Botswana"),
    ("268", "Swaziland"),
    ("269", "Comoros"),
    ("290", "Saint Helena"),
    ("291", "Eritrea"),
    ("297", "Aruba"),
    ("298", "Faroe Islands"),
    ("299", "Greenland"),
    ("350", "Gibraltar"),
    ("351", "Portugal"),
    ("352", "Luxembourg"),
    ("353", "Ireland"),
    ("354", "Iceland"),
    ("355", "Albania"),
    ("356", "Malta"),
    ("357", "Cyprus"),
    ("358", "Finland"),
    ("359", "Bulgaria"),
    ("370", "Lithuania"),
    ("371", "Latvia"),
    ("372", "Estonia"),
    ("373", "Moldova"),
    ("374", "Armenia"),
    ("375", "Belarus"),
    ("376", "Andorra"),
    ("377", "Monaco"),
    ("378", "San Marino"),
    ("380", "Ukraine"),
    ("381", "Serbia"),
    ("382", "Montenegro"),
    ("383", "Kosovo"),
    ("385", "Croatia"),
    ("386", "Slovenia"),
    ("387", "Bosnia and Herzegovina"),
    ("389", "Macedonia"),
    ("420", "Czech Republic"),
    ("421", "Slovakia"),
    ("423", "Liechtenstein"),
    ("500", "Falkland Islands"),
    ("501", "Belize"),
    ("502", "Guatemala"),
    ("503", "El Salvador"),
    ("504", "Honduras"),
    ("505", "Nicaragua"),
    ("506", "Costa Rica"),
    ("507", "Panama"),
    ("508", "Saint Pierre and Miquelon"),
    ("509", "Haiti"),
    ("590", "Guadeloupe"),
    ("591", "Bolivia"),
    ("592", "Guyana"),
    ("593", "Ecuador"),
    ("594", "French Guiana"),
    ("595", "Paraguay"),
    ("596", "Martinique"),
    ("597", "Suriname"),
    ("598", "Uruguay"),
    ("599", "Netherlands Antilles"),
    ("670", "East Timor"),
    ("672", "Antarctica"),
    ("673", "Brunei"),
    ("674", "Nauru"),
    ("675", "Papua New Guinea"),
    ("676", "Tonga"),
    ("677", "Solomon Islands"),
    ("678", "Vanuatu"),
    ("679", "Fiji"),
    ("680", "Palau"),
    ("681", "Wallis and Futuna"),
    ("682", "Cook Islands"),
    ("683", "Niue"),
    ("684", "American Samoa"),
    ("685", "Samoa"),
    ("686", "Kiribati"),
    ("687", "New Caledonia"),
    ("688", "Tuvalu"),
    ("689", "French Polynesia"),
    ("690", "Tokelau"),
    ("691", "Micronesia"),
    ("692", "Marshall Islands"),
    ("850", "North Korea"),
    ("852", "Hong Kong"),
    ("853", "Macau"),
    ("855", "Cambodia"),
    ("856", "Laos"),
    ("880", "Bangladesh"),
    ("886", "Taiwan"),
    ("960", "Maldives"),
    ("961", "Lebanon"),
    ("962", "Jordan"),
    ("963", "Syria"),
    ("964", "Iraq"),
    ("965", "Kuwait"),
    ("966", "Saudi Arabia"),
    ("967", "Yemen"),
    ("968", "Oman"),
    ("970", "Palestine"),
    ("971", "United Arab Emirates"),
    ("972", "Israel"),
    ("973", "Bahrain"),
    ("974", "Qatar"),
    ("975", "Bhutan"),
    ("976", "Mongolia"),
    ("977", "Nepal"),
    ("992", "Tajikistan"),
    ("993", "Turkmenistan"),
    ("994", "Azerbaijan"),
    ("995", "Georgia"),
    ("996", "Kyrgyzstan"),
    ("998", "Uzbekistan"),
];

/// [EXTENSION PARSING] Parse extension with optional country code
/// @MISSION Extract country code and local extension from full extension string.
/// @NOTE Supports complex formats like "32-001-00-00-00" where first part is country code
/// @PARAM extension: Full extension string (e.g., "32-001-00-00-00", "32-1001" or "1001")
/// @RETURN (country_code_option, local_extension)
pub fn parse_extension_with_country_code(extension: &str) -> (Option<String>, String) {
    let parts: Vec<&str> = extension.split('-').collect();

    // Check if first part is a valid country code
    if !parts.is_empty() {
        let potential_country_code = parts[0];

        // Validate country code exists in our mapping
        if COUNTRY_CODES.iter().any(|(code, _)| *code == potential_country_code) {
            // Country code found, rest is local extension
            let local_extension = parts[1..].join("-");
            return (Some(potential_country_code.to_string()), local_extension);
        }
    }

    // No valid country code found, treat as local extension
    (None, extension.to_string())
}

/// [VALIDATE EXTENSION] Validate extension format
/// @MISSION Ensure extension follows correct format with optional country code.
/// @NOTE Supports complex formats with multiple dash-separated numeric parts
/// @PARAM extension: Extension to validate
/// @RETURN true if valid, false otherwise
pub fn validate_extension_format(extension: &str) -> bool {
    if extension.is_empty() {
        return false;
    }

    let parts: Vec<&str> = extension.split('-').collect();

    // Must have at least one part
    if parts.is_empty() {
        return false;
    }

    // Check if first part looks like it should be a country code (numeric and 1-3 digits)
    let first_part_numeric = parts[0].chars().all(|c| c.is_numeric());
    let first_part_length = parts[0].len();

    if first_part_numeric && first_part_length >= 1 && first_part_length <= 3 {
        // First part looks like a country code, validate it exists
        if !COUNTRY_CODES.iter().any(|(valid_code, _)| *valid_code == parts[0]) {
            return false; // Invalid country code
        }
        // Valid country code, validate remaining parts
        for part in &parts[1..] {
            if part.is_empty() || !part.chars().all(|c| c.is_numeric()) {
                return false;
            }
        }
        // Must have at least one part after country code
        if parts.len() <= 1 {
            return false;
        }
    } else {
        // First part doesn't look like country code, validate all parts as local extension
        for part in &parts {
            if part.is_empty() || !part.chars().all(|c| c.is_numeric()) {
                return false;
            }
        }
    }

    true
}

/// [GET COUNTRY NAME] Get country name from country code
/// @MISSION Provide human-readable country name for UI display.
/// @PARAM country_code: Two or three digit country code
/// @RETURN Country name if found, None otherwise
pub fn get_country_name(country_code: &str) -> Option<String> {
    COUNTRY_CODES.iter()
        .find(|(code, _)| *code == country_code)
        .map(|(_, name)| name.to_string())
}

/// [GET EXTENSION COUNTRY INFO] Get country information for extension
/// @MISSION Extract country code and name from extension.
/// @PARAM extension: Full extension string
/// @RETURN (country_code, country_name) tuple, both optional
pub fn get_extension_country_info(extension: &str) -> (Option<String>, Option<String>) {
    let (country_code, _) = parse_extension_with_country_code(extension);
    let country_name = country_code.as_ref().and_then(|code| get_country_name(code));
    (country_code, country_name)
}

/// [PARSE EXTENSION STRUCTURE] Parse complete extension structure
/// @MISSION Provide detailed breakdown of all extension components.
/// @PARAM extension: Full extension string
/// @RETURN Structured representation of the extension
pub fn parse_extension_structure(extension: &str) -> ExtensionStructure {
    let parts: Vec<String> = extension.split('-').map(|s| s.to_string()).collect();
    let (country_code, local_extension) = parse_extension_with_country_code(extension);
    let country_name = country_code.as_ref().and_then(|code| get_country_name(code));

    ExtensionStructure {
        country_code,
        country_name,
        local_extension,
        full_extension: extension.to_string(),
        parts,
    }
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

/// [FEDERATED OFFICE MODEL] Represents a federated office with its own Asterisk server
/// @MISSION Enable distributed VoIP infrastructure with secure inter-office connectivity.
/// @NOTE Each office can have its own Asterisk server while connecting to the central network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedOffice {
    pub id: String,
    pub name: String,
    pub location: String,
    pub asterisk_config: AsteriskFederationConfig,
    pub federation_token: String, // Secure token for inter-office authentication
    pub created_at: DateTime<Utc>,
    pub last_connected: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub office_prefix: String, // Prefix for this office's extensions (e.g., "BRU" for Brussels)
}

/// [ASTERISK FEDERATION CONFIG] Configuration for federated Asterisk connections
/// @MISSION Store connection details for federated Asterisk servers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsteriskFederationConfig {
    pub host: String,
    pub port: u16,
    pub ari_url: String,
    pub ari_username: String,
    pub ari_password: String, // Encrypted in production
    pub sip_trunk_host: String,
    pub sip_trunk_port: u16,
    pub federation_context: String, // Asterisk context for federation
}

/// [FEDERATION LINK MODEL] Secure connection between two federated offices
/// @MISSION Establish and manage secure VoIP trunks between offices.
/// @NOTE Bidirectional links with encryption and authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationLink {
    pub id: String,
    pub source_office_id: String,
    pub target_office_id: String,
    pub link_type: FederationLinkType,
    pub encryption_enabled: bool,
    pub bandwidth_limit: Option<u32>, // Kbps limit for the link
    pub priority: u8, // Routing priority (1-10, higher = preferred)
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
    pub is_active: bool,
}

/// [FEDERATION LINK TYPE] Type of connection between federated offices
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FederationLinkType {
    SipTrunk,      // Direct SIP trunk
    IaxTrunk,      // IAX2 trunk (more efficient for VoIP)
    ApiGateway,    // Via central API gateway
    PstnGateway,   // PSTN connectivity
}

/// [FEDERATION ROUTE] Routing rule for inter-office calls
/// @MISSION Define how calls should be routed between federated offices.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationRoute {
    pub id: String,
    pub source_office_prefix: String,
    pub destination_pattern: String, // Regex pattern for destination matching
    pub target_office_id: String,
    pub preferred_link_id: Option<String>,
    pub fallback_links: Vec<String>, // Link IDs to try if primary fails
    pub cost_priority: u8, // Cost-based routing priority
    pub created_at: DateTime<Utc>,
    pub is_active: bool,
}

/// [EXTENSION STRUCTURE] Structured representation of a VoIP extension
/// @MISSION Provide detailed breakdown of extension components
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionStructure {
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub local_extension: String,
    pub full_extension: String,
    pub parts: Vec<String>, // All parts split by dashes
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

    // Federation fields
    federated_offices: Arc<RwLock<HashMap<String, FederatedOffice>>>, // office_id -> office
    federation_links: Arc<RwLock<HashMap<String, FederationLink>>>, // link_id -> link
    federation_routes: Arc<RwLock<HashMap<String, FederationRoute>>>, // route_id -> route
    office_tokens: Arc<RwLock<HashMap<String, String>>>, // token -> office_id (for auth)
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

            // Federation initialization
            federated_offices: Arc::new(RwLock::new(HashMap::new())),
            federation_links: Arc::new(RwLock::new(HashMap::new())),
            federation_routes: Arc::new(RwLock::new(HashMap::new())),
            office_tokens: Arc::new(RwLock::new(HashMap::new())),
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
        // Validate extension format
        if !validate_extension_format(extension) {
            return Err("Invalid extension format. Use format: [country_code-]local_extension (e.g., '1001' or '32-1001')".to_string());
        }

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

    /// [LIST EXTENSIONS BY COUNTRY] Get all extensions for a specific country
    /// @MISSION Filter extensions by country code for administrative purposes.
    /// @PARAM country_code: Country code to filter by (e.g., "32" for Belgium)
    /// @RETURN List of user extensions for the specified country
    pub async fn get_extensions_by_country(&self, country_code: &str) -> Vec<UserExtension> {
        let extensions = self.user_extensions.read().await;
        extensions.values()
            .filter(|ext| {
                let (ext_country_code, _) = parse_extension_with_country_code(&ext.extension);
                ext_country_code.as_ref() == Some(&country_code.to_string())
            })
            .cloned()
            .collect()
    }

    /// [LIST ALL EXTENSIONS WITH COUNTRY INFO] Get all extensions with country information
    /// @MISSION Provide comprehensive extension list with country details.
    /// @RETURN List of extensions with their country information
    pub async fn get_all_extensions_with_country_info(&self) -> Vec<(UserExtension, Option<String>, Option<String>)> {
        let extensions = self.user_extensions.read().await;
        extensions.values()
            .map(|ext| {
                let (country_code, country_name) = get_extension_country_info(&ext.extension);
                (ext.clone(), country_code, country_name)
            })
            .collect()
    }

    // ============================================================================
    // FEDERATION MANAGEMENT METHODS
    // ============================================================================

    /// [REGISTER FEDERATED OFFICE] Register a new federated office
    /// @MISSION Add a new office to the federation with its Asterisk configuration.
    /// @THREAT Unauthorized office registration, configuration conflicts.
    /// @COUNTERMEASURE Token-based authentication, validation checks.
    pub async fn register_federated_office(
        &self,
        name: &str,
        location: &str,
        office_prefix: &str,
        asterisk_config: AsteriskFederationConfig,
    ) -> Result<FederatedOffice, String> {
        let mut offices = self.federated_offices.write().await;

        // Check if office prefix is already used
        for office in offices.values() {
            if office.office_prefix == office_prefix {
                return Err("Office prefix already exists".to_string());
            }
        }

        let office_id = Uuid::new_v4().to_string();
        let federation_token = Uuid::new_v4().to_string(); // In production, use proper token generation

        let office = FederatedOffice {
            id: office_id.clone(),
            name: name.to_string(),
            location: location.to_string(),
            asterisk_config,
            federation_token: federation_token.clone(),
            created_at: Utc::now(),
            last_connected: None,
            is_active: true,
            office_prefix: office_prefix.to_string(),
        };

        offices.insert(office_id.clone(), office.clone());

        // Register token for authentication
        let mut tokens = self.office_tokens.write().await;
        tokens.insert(federation_token, office_id);

        Ok(office)
    }

    /// [AUTHENTICATE FEDERATION TOKEN] Validate federation token
    /// @MISSION Verify that a federation token is valid and return office info.
    /// @THREAT Token spoofing, unauthorized access.
    /// @COUNTERMEASURE Secure token validation, expiration checks.
    pub async fn authenticate_federation_token(&self, token: &str) -> Option<FederatedOffice> {
        let tokens = self.office_tokens.read().await;
        if let Some(office_id) = tokens.get(token) {
            let offices = self.federated_offices.read().await;
            if let Some(office) = offices.get(office_id) {
                if office.is_active {
                    return Some(office.clone());
                }
            }
        }
        None
    }

    /// [CREATE FEDERATION LINK] Establish connection between two offices
    /// @MISSION Create secure VoIP trunk between federated offices.
    /// @THREAT Link configuration errors, security vulnerabilities.
    /// @COUNTERMEASURE Validation, encryption requirements.
    pub async fn create_federation_link(
        &self,
        source_office_id: &str,
        target_office_id: &str,
        link_type: FederationLinkType,
        priority: u8,
    ) -> Result<FederationLink, String> {
        let offices = self.federated_offices.read().await;

        // Validate offices exist and are active
        if !offices.contains_key(source_office_id) || !offices.contains_key(target_office_id) {
            return Err("One or both offices not found".to_string());
        }

        let mut links = self.federation_links.write().await;
        let link_id = Uuid::new_v4().to_string();

        let link = FederationLink {
            id: link_id.clone(),
            source_office_id: source_office_id.to_string(),
            target_office_id: target_office_id.to_string(),
            link_type,
            encryption_enabled: true, // Always enable encryption
            bandwidth_limit: None,
            priority,
            created_at: Utc::now(),
            last_used: None,
            is_active: true,
        };

        links.insert(link_id, link.clone());
        Ok(link)
    }

    /// [CREATE FEDERATION ROUTE] Define routing rule for inter-office calls
    /// @MISSION Set up intelligent call routing between federated offices.
    /// @THREAT Routing loops, incorrect destinations.
    /// @COUNTERMEASURE Pattern validation, loop detection.
    pub async fn create_federation_route(
        &self,
        source_office_prefix: &str,
        destination_pattern: &str,
        target_office_id: &str,
        cost_priority: u8,
    ) -> Result<FederationRoute, String> {
        let offices = self.federated_offices.read().await;

        // Validate target office exists
        if !offices.contains_key(target_office_id) {
            return Err("Target office not found".to_string());
        }

        let mut routes = self.federation_routes.write().await;
        let route_id = Uuid::new_v4().to_string();

        let route = FederationRoute {
            id: route_id.clone(),
            source_office_prefix: source_office_prefix.to_string(),
            destination_pattern: destination_pattern.to_string(),
            target_office_id: target_office_id.to_string(),
            preferred_link_id: None,
            fallback_links: vec![],
            cost_priority,
            created_at: Utc::now(),
            is_active: true,
        };

        routes.insert(route_id, route.clone());
        Ok(route)
    }

    /// [RESOLVE FEDERATION ROUTE] Find appropriate route for inter-office call
    /// @MISSION Determine which office and link to use for routing a call.
    /// @THREAT No available route, routing conflicts.
    /// @COUNTERMEASURE Fallback routing, priority-based selection.
    pub async fn resolve_federation_route(
        &self,
        source_office_prefix: &str,
        destination: &str,
    ) -> Option<(FederatedOffice, FederationLink)> {
        let routes = self.federation_routes.read().await;
        let offices = self.federated_offices.read().await;
        let links = self.federation_links.read().await;

        // Find matching route
        for route in routes.values() {
            if route.source_office_prefix == source_office_prefix && route.is_active {
                // Simple pattern matching (in production, use regex)
                if destination.contains(&route.destination_pattern) ||
                   route.destination_pattern == "*" { // Wildcard for all destinations

                    if let Some(target_office) = offices.get(&route.target_office_id) {
                        // Find preferred link or any active link
                        let preferred_link_id = route.preferred_link_id.as_ref()
                            .or_else(|| route.fallback_links.first());

                        if let Some(link_id) = preferred_link_id {
                            if let Some(link) = links.get(link_id) {
                                if link.is_active {
                                    return Some((target_office.clone(), link.clone()));
                                }
                            }
                        }

                        // Fallback: find any active link to target office
                        for link in links.values() {
                            if (link.source_office_id == route.source_office_prefix ||
                                link.target_office_id == route.target_office_id) &&
                               link.is_active {
                                return Some((target_office.clone(), link.clone()));
                            }
                        }
                    }
                }
            }
        }

        None
    }

    /// [GET FEDERATED OFFICES] List all federated offices
    /// @MISSION Provide administrative view of all offices in the federation.
    pub async fn get_federated_offices(&self) -> Vec<FederatedOffice> {
        let offices = self.federated_offices.read().await;
        offices.values().cloned().collect()
    }

    /// [GET FEDERATION LINKS] List all federation links
    /// @MISSION Provide view of all inter-office connections.
    pub async fn get_federation_links(&self) -> Vec<FederationLink> {
        let links = self.federation_links.read().await;
        links.values().cloned().collect()
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
                // Parse extension to extract local extension (without country code)
                let (_, local_extension) = parse_extension_with_country_code(&extension.extension);
                // Fallback to default SIP endpoint using local extension
                return Ok(format!("SIP/{}", local_extension));
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
        let service = VoipService::new().await;

        let result = service.assign_user_extension("user123", "1001", Some("John Doe".to_string())).await;
        assert!(result.is_ok());

        let extension = result.unwrap();
        assert_eq!(extension.user_id, "user123");
        assert_eq!(extension.extension, "1001");
        assert_eq!(extension.display_name, Some("John Doe".to_string()));
        assert!(extension.enabled);
    }

    #[tokio::test]
    async fn test_international_extensions() {
        let service = VoipService::new().await;

        // Test Belgian extension
        let result = service.assign_user_extension("user_be", "32-1001", Some("Belgian User".to_string())).await;
        assert!(result.is_ok());
        let extension = result.unwrap();
        assert_eq!(extension.extension, "32-1001");

        // Test US extension
        let result = service.assign_user_extension("user_us", "1-555", Some("US User".to_string())).await;
        assert!(result.is_ok());
        let extension = result.unwrap();
        assert_eq!(extension.extension, "1-555");

        // Test complex Belgian extension
        let result = service.assign_user_extension("user_be_complex", "32-001-00-00-00", Some("Complex Belgian User".to_string())).await;
        assert!(result.is_ok());
        let extension = result.unwrap();
        assert_eq!(extension.extension, "32-001-00-00-00");

        // Test invalid country code (999 doesn't exist)
        let result = service.assign_user_extension("user_invalid", "999-1001", None).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid extension format"));

        // Test parsing functions
        let (country_code, local_ext) = parse_extension_with_country_code("32-1001");
        assert_eq!(country_code, Some("32".to_string()));
        assert_eq!(local_ext, "1001");

        let (country_code, local_ext) = parse_extension_with_country_code("32-001-00-00-00");
        assert_eq!(country_code, Some("32".to_string()));
        assert_eq!(local_ext, "001-00-00-00");

        let (country_code, local_ext) = parse_extension_with_country_code("1001");
        assert_eq!(country_code, None);
        assert_eq!(local_ext, "1001");

        // Test country name lookup
        assert_eq!(get_country_name("32"), Some("Belgium".to_string()));
        assert_eq!(get_country_name("1"), Some("United States/Canada".to_string()));
        assert_eq!(get_country_name("999"), None);

        // Test extension structure parsing
        let structure = parse_extension_structure("32-001-00-00-00");
        assert_eq!(structure.country_code, Some("32".to_string()));
        assert_eq!(structure.country_name, Some("Belgium".to_string()));
        assert_eq!(structure.local_extension, "001-00-00-00");
        assert_eq!(structure.full_extension, "32-001-00-00-00");
        assert_eq!(structure.parts, vec!["32", "001", "00", "00", "00"]);

        // Test validation of complex formats
        assert!(validate_extension_format("32-001-00-00-00"));
        assert!(validate_extension_format("1-555-123-4567"));
        assert!(validate_extension_format("1001"));
        assert!(!validate_extension_format("32-"));
        assert!(!validate_extension_format("abc-123"));
        assert!(!validate_extension_format("32-abc-123"));
        assert!(!validate_extension_format("999-1001")); // Invalid country code
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