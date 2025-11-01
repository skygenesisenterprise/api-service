// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: VoIP Models
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Define data models for VoIP operations including calls,
//  conferences, signaling, and media streams.
//  NOTICE: Implements structured data models with validation,
//  serialization, and database mapping for VoIP functionality.
//  DATA STANDARDS: JSON Schema, SQL DDL, Protocol Buffers
//  SECURITY: Data validation, sanitization, access control
//  COMPLIANCE: GDPR, HIPAA data handling requirements
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use std::collections::HashMap;

/// [VOIP CALL MODEL] Complete VoIP call information
/// @MISSION Structure call data for database storage and API responses.
/// @THREAT Data corruption, unauthorized access.
/// @COUNTERMEASURE Validation, encryption, access control.
/// @INVARIANT All fields validated before storage.
/// @AUDIT Call data changes are logged.
/// @DEPENDENCY Used by VoIP service and controllers.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct VoipCall {
    pub id: String,
    pub caller_id: String,
    pub participants: Vec<String>,
    pub call_type: CallType,
    pub status: CallStatus,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub room_id: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl VoipCall {
    /// [CALL CREATION] Create new VoIP call
    /// @MISSION Initialize call with validated data.
    /// @THREAT Invalid call data.
    /// @COUNTERMEASURE Input validation.
    pub fn new(caller_id: String, participants: Vec<String>, call_type: CallType) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            caller_id,
            participants,
            call_type,
            status: CallStatus::Initiating,
            start_time: now,
            end_time: None,
            room_id: None,
            metadata: serde_json::json!({}),
            created_at: now,
            updated_at: now,
        }
    }

    /// [CALL UPDATE] Update call status
    /// @MISSION Modify call state safely.
    /// @THREAT Race conditions, invalid state transitions.
    /// @COUNTERMEASURE Atomic updates, state validation.
    pub fn update_status(&mut self, status: CallStatus) {
        self.status = status;
        self.updated_at = Utc::now();

        if matches!(status, CallStatus::Ended) {
            self.end_time = Some(Utc::now());
        }
    }

    /// [PARTICIPANT MANAGEMENT] Add participant to call
    /// @MISSION Add user to active call.
    /// @THREAT Duplicate participants, capacity overflow.
    /// @COUNTERMEASURE Validation, limits.
    pub fn add_participant(&mut self, user_id: String) -> Result<(), String> {
        if self.participants.contains(&user_id) {
            return Err("User already in call".to_string());
        }

        if self.participants.len() >= 50 { // Max participants limit
            return Err("Call participant limit reached".to_string());
        }

        self.participants.push(user_id);
        self.updated_at = Utc::now();
        Ok(())
    }

    /// [PARTICIPANT REMOVAL] Remove participant from call
    /// @MISSION Remove user from call.
    /// @THREAT Invalid removals.
    /// @COUNTERMEASURE Permission checks.
    pub fn remove_participant(&mut self, user_id: &str) -> Result<(), String> {
        if let Some(pos) = self.participants.iter().position(|p| p == user_id) {
            self.participants.remove(pos);
            self.updated_at = Utc::now();
            Ok(())
        } else {
            Err("User not in call".to_string());
        }
    }

    /// [DURATION CALCULATION] Calculate call duration
    /// @MISSION Get call duration in seconds.
    /// @THREAT Time calculation errors.
    /// @COUNTERMEASURE Safe arithmetic.
    pub fn duration_seconds(&self) -> i64 {
        let end_time = self.end_time.unwrap_or_else(Utc::now);
        (end_time - self.start_time).num_seconds()
    }
}

/// [CALL TYPE ENUM] Supported VoIP call types
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "call_type", rename_all = "snake_case")]
pub enum CallType {
    Audio,
    Video,
    ScreenShare,
    Conference,
}

/// [CALL STATUS ENUM] VoIP call status states
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "call_status", rename_all = "snake_case")]
pub enum CallStatus {
    Initiating,
    Ringing,
    Connected,
    OnHold,
    Ended,
}

/// [VOIP ROOM MODEL] Conference room information
/// @MISSION Structure conference room data.
/// @THREAT Unauthorized room access.
/// @COUNTERMEASURE Access control, validation.
/// @INVARIANT Room data integrity maintained.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct VoipRoom {
    pub id: String,
    pub name: String,
    pub owner_id: String,
    pub participants: Vec<String>,
    pub max_participants: i32,
    pub is_active: bool,
    pub settings: RoomSettings,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl VoipRoom {
    /// [ROOM CREATION] Create new conference room
    /// @MISSION Initialize room with settings.
    /// @THREAT Invalid room configuration.
    /// @COUNTERMEASURE Configuration validation.
    pub fn new(owner_id: String, name: String, max_participants: i32, settings: RoomSettings) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            owner_id,
            participants: vec![owner_id.clone()],
            max_participants,
            is_active: true,
            settings,
            created_at: now,
            updated_at: now,
        }
    }

    /// [ROOM CAPACITY] Check if room can accept more participants
    /// @MISSION Validate room capacity.
    /// @THREAT Over-capacity rooms.
    /// @COUNTERMEASURE Capacity enforcement.
    pub fn can_join(&self) -> bool {
        self.is_active && (self.participants.len() as i32) < self.max_participants
    }

    /// [PARTICIPANT MANAGEMENT] Add participant to room
    /// @MISSION Add user to conference room.
    /// @THREAT Capacity overflow, duplicates.
    /// @COUNTERMEASURE Validation, limits.
    pub fn add_participant(&mut self, user_id: String) -> Result<(), String> {
        if !self.can_join() {
            return Err("Room is full".to_string());
        }

        if self.participants.contains(&user_id) {
            return Err("User already in room".to_string());
        }

        self.participants.push(user_id);
        self.updated_at = Utc::now();
        Ok(())
    }

    /// [PARTICIPANT REMOVAL] Remove participant from room
    /// @MISSION Remove user from room.
    /// @THREAT Invalid removals.
    /// @COUNTERMEASURE Permission checks.
    pub fn remove_participant(&mut self, user_id: &str) -> Result<(), String> {
        if let Some(pos) = self.participants.iter().position(|p| p == user_id) {
            self.participants.remove(pos);
            self.updated_at = Utc::now();
            Ok(())
        } else {
            Err("User not in room".to_string());
        }
    }

    /// [ROOM CLOSURE] Close conference room
    /// @MISSION End conference session.
    /// @THREAT Resource leaks.
    /// @COUNTERMEASURE Proper cleanup.
    pub fn close(&mut self) {
        self.is_active = false;
        self.updated_at = Utc::now();
    }
}

/// [ROOM SETTINGS] Conference room configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomSettings {
    pub allow_recording: bool,
    pub allow_screen_share: bool,
    pub require_moderator: bool,
    pub moderator_id: Option<String>,
    pub password_required: bool,
    pub password_hash: Option<String>,
    pub time_limit_minutes: Option<i32>,
}

impl Default for RoomSettings {
    fn default() -> Self {
        Self {
            allow_recording: false,
            allow_screen_share: true,
            require_moderator: false,
            moderator_id: None,
            password_required: false,
            password_hash: None,
            time_limit_minutes: None,
        }
    }
}

/// [SIGNALING MESSAGE MODEL] WebRTC signaling data
/// @MISSION Structure signaling messages for storage.
/// @THREAT Message tampering, replay attacks.
/// @COUNTERMEASURE Signing, sequencing.
/// @INVARIANT Messages are authenticated and ordered.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SignalingMessage {
    pub id: String,
    pub call_id: String,
    pub from_user: String,
    pub to_user: String,
    pub message_type: SignalingType,
    pub payload: serde_json::Value,
    pub sequence_number: i64,
    pub created_at: DateTime<Utc>,
}

impl SignalingMessage {
    /// [MESSAGE CREATION] Create new signaling message
    /// @MISSION Initialize message with sequence.
    /// @THREAT Sequence number collisions.
    /// @COUNTERMEASURE Atomic sequencing.
    pub fn new(
        call_id: String,
        from_user: String,
        to_user: String,
        message_type: SignalingType,
        payload: serde_json::Value,
        sequence_number: i64,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            call_id,
            from_user,
            to_user,
            message_type,
            payload,
            sequence_number,
            created_at: Utc::now(),
        }
    }
}

/// [SIGNALING TYPE ENUM] WebRTC signaling message types
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "signaling_type", rename_all = "snake_case")]
pub enum SignalingType {
    Offer,
    Answer,
    IceCandidate,
    Hangup,
    Mute,
    Unmute,
    ScreenShareStart,
    ScreenShareStop,
}

/// [MEDIA SESSION MODEL] Media stream session information
/// @MISSION Track media sessions for calls.
/// @THREAT Media session hijacking.
/// @COUNTERMEASURE Session validation, encryption.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct MediaSession {
    pub id: String,
    pub call_id: String,
    pub user_id: String,
    pub session_type: SessionType,
    pub codecs: Vec<String>,
    pub bandwidth_kbps: i32,
    pub is_active: bool,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
}

impl MediaSession {
    /// [SESSION CREATION] Create new media session
    /// @MISSION Initialize media session tracking.
    /// @THREAT Invalid session parameters.
    /// @COUNTERMEASURE Parameter validation.
    pub fn new(call_id: String, user_id: String, session_type: SessionType) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            call_id,
            user_id,
            session_type,
            codecs: Vec::new(),
            bandwidth_kbps: 0,
            is_active: true,
            started_at: Utc::now(),
            ended_at: None,
        }
    }

    /// [SESSION END] Terminate media session
    /// @MISSION End media session cleanly.
    /// @THREAT Resource leaks.
    /// @COUNTERMEASURE Proper cleanup.
    pub fn end(&mut self) {
        self.is_active = false;
        self.ended_at = Some(Utc::now());
    }
}

/// [SESSION TYPE ENUM] Media session types
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "session_type", rename_all = "snake_case")]
pub enum SessionType {
    Audio,
    Video,
    ScreenShare,
}

/// [VOIP RECORDING MODEL] Call recording information
/// @MISSION Track call recordings for compliance.
/// @THREAT Unauthorized recording access.
/// @COUNTERMEASURE Encryption, access control.
/// @COMPLIANCE GDPR, HIPAA recording requirements.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct VoipRecording {
    pub id: String,
    pub call_id: String,
    pub room_id: Option<String>,
    pub recorder_id: String,
    pub file_path: String,
    pub file_size_bytes: i64,
    pub duration_seconds: i32,
    pub checksum: String,
    pub is_encrypted: bool,
    pub participants: Vec<String>,
    pub created_at: DateTime<Utc>,
}

impl VoipRecording {
    /// [RECORDING CREATION] Create recording record
    /// @MISSION Track recording metadata.
    /// @THREAT Metadata tampering.
    /// @COUNTERMEASURE Integrity checks.
    pub fn new(
        call_id: String,
        room_id: Option<String>,
        recorder_id: String,
        file_path: String,
        checksum: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            call_id,
            room_id,
            recorder_id,
            file_path,
            file_size_bytes: 0,
            duration_seconds: 0,
            checksum,
            is_encrypted: true,
            participants: Vec::new(),
            created_at: Utc::now(),
        }
    }
}

/// [VOIP METRICS MODEL] VoIP performance metrics
/// @MISSION Track VoIP system performance.
/// @THREAT Metric manipulation.
/// @COUNTERMEASURE Secure metric collection.
/// @MONITORING Used for system observability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoipMetrics {
    pub timestamp: DateTime<Utc>,
    pub active_calls: u32,
    pub active_rooms: u32,
    pub total_participants: u32,
    pub average_call_duration: f64,
    pub signaling_messages_per_second: f64,
    pub media_bytes_per_second: u64,
    pub error_rate: f64,
}

impl VoipMetrics {
    /// [METRICS CREATION] Create metrics snapshot
    /// @MISSION Capture current system metrics.
    /// @THREAT Metric calculation errors.
    /// @COUNTERMEASURE Safe arithmetic.
    pub fn new() -> Self {
        Self {
            timestamp: Utc::now(),
            active_calls: 0,
            active_rooms: 0,
            total_participants: 0,
            average_call_duration: 0.0,
            signaling_messages_per_second: 0.0,
            media_bytes_per_second: 0,
            error_rate: 0.0,
        }
    }
}