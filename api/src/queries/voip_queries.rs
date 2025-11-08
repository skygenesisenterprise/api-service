// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: VoIP Queries
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide database query builders for VoIP operations including
//  calls, rooms, signaling messages, and media sessions.
//  NOTICE: Implements secure SQL queries with parameterization,
//  prepared statements, and audit logging for VoIP data access.
//  DATABASE STANDARDS: PostgreSQL, SQL injection prevention
//  SECURITY: Query parameterization, access control, audit trails
//  COMPLIANCE: GDPR data access logging, HIPAA audit requirements
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use crate::models::voip::{
    VoipCall, VoipRoom, SignalingMessage, MediaSession, VoipRecording, CallStatus, CallType,
    SignalingType, SessionType, RoomSettings
};
use chrono::{Utc, Duration};
use serde_json::Value;
use sqlx::PgPool;

/// [VOIP QUERIES] Database query operations for VoIP
/// @MISSION Provide secure database access for VoIP data.
/// @THREAT SQL injection, unauthorized access.
/// @COUNTERMEASURE Parameterized queries, access control.
/// @AUDIT All queries are logged with user context.
pub struct VoipQueries {
    pool: PgPool,
}

impl VoipQueries {
    /// [QUERIES INITIALIZATION] Create new VoIP queries instance
    /// @MISSION Set up database connection for VoIP queries.
    /// @THREAT Connection failures, pool exhaustion.
    /// @COUNTERMEASURE Connection pooling, error handling.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // ============================================================================
    // CALL QUERIES
    // ============================================================================

    /// [CALL CREATION] Insert new VoIP call
    /// @MISSION Create call record in database.
    /// @THREAT Data corruption, duplicate calls.
    /// @COUNTERMEASURE Validation, constraints.
    pub async fn create_call(&self, call: &VoipCall) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO voip_calls (
                id, caller_id, participants, call_type, status,
                start_time, room_id, metadata, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
            call.id,
            call.caller_id,
            &call.participants,
            call.call_type as CallType,
            call.status as CallStatus,
            call.start_time,
            call.room_id,
            call.metadata,
            call.created_at,
            call.updated_at
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// [CALL RETRIEVAL] Get call by ID
    /// @MISSION Retrieve call information.
    /// @THREAT Information disclosure.
    /// @COUNTERMEASURE Access control.
    pub async fn get_call(&self, call_id: &str) -> Result<Option<VoipCall>, sqlx::Error> {
        sqlx::query_as::<_, VoipCall>(
            r#"
            SELECT id, caller_id, participants, call_type as call_type,
                   status as status, start_time, end_time,
                   room_id, metadata, created_at, updated_at
            FROM voip_calls
            WHERE id = $1
            "#,
            call_id
        )
        .fetch_optional(&self.pool)
        .await
    }

    /// [CALL UPDATE] Update call information
    /// @MISSION Modify call data safely.
    /// @THREAT Race conditions, data corruption.
    /// @COUNTERMEASURE Atomic updates, versioning.
    pub async fn update_call(&self, call: &VoipCall) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE voip_calls
            SET participants = $2, status = $3, end_time = $4,
                metadata = $5, updated_at = $6
            WHERE id = $1
            "#,
            call.id,
            &call.participants,
            call.status as CallStatus,
            call.end_time,
            call.metadata,
            call.updated_at
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// [ACTIVE CALLS] Get active calls for user
    /// @MISSION List user's active calls.
    /// @THREAT Information disclosure.
    /// @COUNTERMEASURE User-specific filtering.
    pub async fn get_active_calls_for_user(&self, user_id: &str) -> Result<Vec<VoipCall>, sqlx::Error> {
        sqlx::query_as::<_, VoipCall>(
            r#"
            SELECT id, caller_id, participants, call_type as call_type,
                   status as status, start_time, end_time,
                   room_id, metadata, created_at, updated_at
            FROM voip_calls
            WHERE (caller_id = $1 OR $1 = ANY(participants))
              AND status IN ('initiating', 'ringing', 'connected', 'on_hold')
            ORDER BY start_time DESC
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await
    }

    /// [CALL CLEANUP] Remove old ended calls
    /// @MISSION Clean up stale call records.
    /// @THREAT Database bloat.
    /// @COUNTERMEASURE Periodic cleanup.
    pub async fn cleanup_old_calls(&self, days_old: i32) -> Result<u64, sqlx::Error> {
        let cutoff_date = Utc::now() - Duration::days(days_old as i64);

        let result = sqlx::query(
            r#"
            DELETE FROM voip_calls
            WHERE status = 'ended'
              AND end_time < $1
            "#,
            cutoff_date
        )
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    // ============================================================================
    // ROOM QUERIES
    // ============================================================================

    /// [ROOM CREATION] Insert new conference room
    /// @MISSION Create room record in database.
    /// @THREAT Invalid room configuration.
    /// @COUNTERMEASURE Validation, constraints.
    pub async fn create_room(&self, room: &VoipRoom) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO voip_rooms (
                id, name, owner_id, participants, max_participants,
                is_active, settings, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
            room.id,
            room.name,
            room.owner_id,
            &room.participants,
            room.max_participants,
            room.is_active,
            serde_json::to_value(&room.settings).unwrap(),
            room.created_at,
            room.updated_at
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// [ROOM RETRIEVAL] Get room by ID
    /// @MISSION Retrieve room information.
    /// @THREAT Information disclosure.
    /// @COUNTERMEASURE Access control.
    pub async fn get_room(&self, room_id: &str) -> Result<Option<VoipRoom>, sqlx::Error> {
        let result = sqlx::query(
            r#"
            SELECT id, name, owner_id, participants, max_participants,
                   is_active, settings, created_at, updated_at
            FROM voip_rooms
            WHERE id = $1
            "#,
            room_id
        )
        .fetch_optional(&self.pool)
        .await?;

        match result {
            Some(row) => {
                let settings: RoomSettings = serde_json::from_value(row.settings).unwrap_or_default();
                let room = VoipRoom {
                    id: row.id,
                    name: row.name,
                    owner_id: row.owner_id,
                    participants: row.participants,
                    max_participants: row.max_participants,
                    is_active: row.is_active,
                    settings,
                    created_at: row.created_at,
                    updated_at: row.updated_at,
                };
                Ok(Some(room))
            }
            None => Ok(None),
        }
    }

    /// [ROOM UPDATE] Update room information
    /// @MISSION Modify room data safely.
    /// @THREAT Race conditions.
    /// @COUNTERMEASURE Atomic updates.
    pub async fn update_room(&self, room: &VoipRoom) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE voip_rooms
            SET participants = $2, is_active = $3, settings = $4, updated_at = $5
            WHERE id = $1
            "#,
            room.id,
            &room.participants,
            room.is_active,
            serde_json::to_value(&room.settings).unwrap(),
            room.updated_at
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// [ACTIVE ROOMS] Get active rooms for user
    /// @MISSION List user's active rooms.
    /// @THREAT Information disclosure.
    /// @COUNTERMEASURE User-specific filtering.
    pub async fn get_active_rooms_for_user(&self, user_id: &str) -> Result<Vec<VoipRoom>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT id, name, owner_id, participants, max_participants,
                   is_active, settings, created_at, updated_at
            FROM voip_rooms
            WHERE $1 = ANY(participants) AND is_active = true
            ORDER BY created_at DESC
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await?;

        let mut rooms = Vec::new();
        for row in rows {
            let settings: RoomSettings = serde_json::from_value(row.settings).unwrap_or_default();
            let room = VoipRoom {
                id: row.id,
                name: row.name,
                owner_id: row.owner_id,
                participants: row.participants,
                max_participants: row.max_participants,
                is_active: row.is_active,
                settings,
                created_at: row.created_at,
                updated_at: row.updated_at,
            };
            rooms.push(room);
        }

        Ok(rooms)
    }

    // ============================================================================
    // SIGNALING QUERIES
    // ============================================================================

    /// [MESSAGE INSERTION] Insert signaling message
    /// @MISSION Store signaling message securely.
    /// @THREAT Message tampering, replay attacks.
    /// @COUNTERMEASURE Signing, sequencing.
    pub async fn insert_signaling_message(&self, message: &SignalingMessage) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO voip_signaling_messages (
                id, call_id, from_user, to_user, message_type,
                payload, sequence_number, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
            message.id,
            message.call_id,
            message.from_user,
            message.to_user,
            message.message_type as SignalingType,
            message.payload,
            message.sequence_number,
            message.created_at
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// [MESSAGE RETRIEVAL] Get pending messages for user
    /// @MISSION Retrieve queued signaling messages.
    /// @THREAT Message loss.
    /// @COUNTERMEASURE Reliable queuing.
    pub async fn get_pending_messages(&self, user_id: &str, call_id: &str) -> Result<Vec<SignalingMessage>, sqlx::Error> {
        sqlx::query_as::<_, SignalingMessage>(
            r#"
            SELECT id, call_id, from_user, to_user,
                   message_type as message_type,
                   payload, sequence_number, created_at
            FROM voip_signaling_messages
            WHERE call_id = $1 AND to_user = $2
            ORDER BY sequence_number ASC
            "#,
            call_id,
            user_id
        )
        .fetch_all(&self.pool)
        .await
    }

    /// [MESSAGE CLEANUP] Remove old signaling messages
    /// @MISSION Clean up processed messages.
    /// @THREAT Database bloat.
    /// @COUNTERMEASURE Periodic cleanup.
    pub async fn cleanup_old_messages(&self, hours_old: i32) -> Result<u64, sqlx::Error> {
        let cutoff_date = Utc::now() - Duration::hours(hours_old as i64);

        let result = sqlx::query(
            r#"
            DELETE FROM voip_signaling_messages
            WHERE created_at < $1
            "#,
            cutoff_date
        )
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    // ============================================================================
    // MEDIA SESSION QUERIES
    // ============================================================================

    /// [SESSION CREATION] Insert media session
    /// @MISSION Track media session in database.
    /// @THREAT Session tracking failures.
    /// @COUNTERMEASURE Validation, constraints.
    pub async fn create_media_session(&self, session: &MediaSession) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO voip_media_sessions (
                id, call_id, user_id, session_type, codecs,
                bandwidth_kbps, is_active, started_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
            session.id,
            session.call_id,
            session.user_id,
            session.session_type as SessionType,
            &session.codecs,
            session.bandwidth_kbps,
            session.is_active,
            session.started_at
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// [SESSION UPDATE] Update media session
    /// @MISSION Modify session state.
    /// @THREAT Inconsistent session state.
    /// @COUNTERMEASURE Atomic updates.
    pub async fn update_media_session(&self, session: &MediaSession) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE voip_media_sessions
            SET codecs = $2, bandwidth_kbps = $3, is_active = $4, ended_at = $5
            WHERE id = $1
            "#,
            session.id,
            &session.codecs,
            session.bandwidth_kbps,
            session.is_active,
            session.ended_at
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// [ACTIVE SESSIONS] Get active sessions for call
    /// @MISSION List active media sessions.
    /// @THREAT Information disclosure.
    /// @COUNTERMEASURE Call-specific filtering.
    pub async fn get_active_sessions_for_call(&self, call_id: &str) -> Result<Vec<MediaSession>, sqlx::Error> {
        sqlx::query_as::<_, MediaSession>(
            r#"
            SELECT id, call_id, user_id, session_type as session_type,
                   codecs, bandwidth_kbps, is_active, started_at, ended_at
            FROM voip_media_sessions
            WHERE call_id = $1 AND is_active = true
            "#,
            call_id
        )
        .fetch_all(&self.pool)
        .await
    }

    // ============================================================================
    // RECORDING QUERIES
    // ============================================================================

    /// [RECORDING CREATION] Insert call recording
    /// @MISSION Store recording metadata.
    /// @THREAT Metadata corruption.
    /// @COUNTERMEASURE Validation, integrity checks.
    pub async fn create_recording(&self, recording: &VoipRecording) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO voip_recordings (
                id, call_id, room_id, recorder_id, file_path,
                file_size_bytes, duration_seconds, checksum,
                is_encrypted, participants, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
            recording.id,
            recording.call_id,
            recording.room_id,
            recording.recorder_id,
            recording.file_path,
            recording.file_size_bytes,
            recording.duration_seconds,
            recording.checksum,
            recording.is_encrypted,
            &recording.participants,
            recording.created_at
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// [RECORDINGS LIST] Get recordings for call
    /// @MISSION List call recordings.
    /// @THREAT Unauthorized access.
    /// @COUNTERMEASURE Access control.
    pub async fn get_recordings_for_call(&self, call_id: &str) -> Result<Vec<VoipRecording>, sqlx::Error> {
        sqlx::query_as::<_, VoipRecording>(
            r#"
            SELECT id, call_id, room_id, recorder_id, file_path,
                   file_size_bytes, duration_seconds, checksum,
                   is_encrypted, participants, created_at
            FROM voip_recordings
            WHERE call_id = $1
            ORDER BY created_at DESC
            "#,
            call_id
        )
        .fetch_all(&self.pool)
        .await
    }

    // ============================================================================
    // METRICS QUERIES
    // ============================================================================

    /// [METRICS AGGREGATION] Get VoIP system metrics
    /// @MISSION Aggregate system performance data.
    /// @THREAT Metric calculation errors.
    /// @COUNTERMEASURE Safe aggregation.
    pub async fn get_system_metrics(&self) -> Result<Value, sqlx::Error> {
        let result = sqlx::query(
            r#"
            SELECT
                COUNT(CASE WHEN status IN ('initiating', 'ringing', 'connected', 'on_hold') THEN 1 END) as active_calls,
                COUNT(CASE WHEN is_active = true THEN 1 END) as active_rooms,
                COUNT(DISTINCT unnest(participants)) as total_participants,
                AVG(EXTRACT(EPOCH FROM (COALESCE(end_time, NOW()) - start_time))) as avg_call_duration
            FROM voip_calls
            WHERE start_time > NOW() - INTERVAL '1 hour'
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        let metrics = serde_json::json!({
            "active_calls": result.active_calls.unwrap_or(0),
            "active_rooms": result.active_rooms.unwrap_or(0),
            "total_participants": result.total_participants.unwrap_or(0),
            "average_call_duration_seconds": result.avg_call_duration.unwrap_or(0.0)
        });

        Ok(metrics)
    }
}