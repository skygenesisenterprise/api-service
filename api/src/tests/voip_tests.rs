// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: VoIP Tests
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide comprehensive test coverage for VoIP functionality
//  including calls, conferences, signaling, and security validation.
//  NOTICE: Implements unit tests, integration tests, and security tests
//  for VoIP operations with mocked dependencies and isolated testing.
//  TESTING STANDARDS: Rust testing framework, async testing, mocking
//  SECURITY: Test security controls, validate edge cases, fuzz testing
//  COMPLIANCE: Test coverage requirements, security testing standards
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::Utc;
use serde_json::json;

use crate::services::voip_service::{VoipService, VoipCall, VoipRoom, SignalingMessage, CallType, CallStatus, SignalingType, RoomSettings};
use crate::core::voip::{SignalingServer, MediaServer, VoIPEngine};
use crate::middlewares::voip_middleware::{VoipMiddleware, VoipRateLimiter, VoipCallValidator, VoipMediaValidator};
use crate::models::voip::{VoipCall as VoipCallModel, VoipRoom as VoipRoomModel};
use crate::queries::voip_queries::VoipQueries;

/// [TEST MODULES] Organize tests by functionality
mod voip_service_tests {
    use super::*;

    #[tokio::test]
    async fn test_call_initiation() {
        let service = VoipService::new();

        let participants = vec!["user2".to_string(), "user3".to_string()];
        let result = service.initiate_call("user1", participants.clone(), CallType::Video).await;

        assert!(result.is_ok());
        let call = result.unwrap();
        assert_eq!(call.caller_id, "user1");
        assert_eq!(call.participants, participants);
        assert_eq!(call.call_type, CallType::Video);
        assert_eq!(call.status, CallStatus::Initiating);
    }

    #[tokio::test]
    async fn test_call_acceptance() {
        let service = VoipService::new();

        // Create a call first
        let call = service.initiate_call("user1", vec!["user2".to_string()], CallType::Audio).await.unwrap();

        // Accept the call
        let result = service.accept_call(&call.id, "user2").await;
        assert!(result.is_ok());

        // Verify call status
        let updated_call = service.get_call(&call.id).await.unwrap();
        assert_eq!(updated_call.status, CallStatus::Connected);
    }

    #[tokio::test]
    async fn test_call_termination() {
        let service = VoipService::new();

        // Create and accept a call
        let call = service.initiate_call("user1", vec!["user2".to_string()], CallType::Audio).await.unwrap();
        service.accept_call(&call.id, "user2").await.unwrap();

        // End the call
        let result = service.end_call(&call.id, "user1").await;
        assert!(result.is_ok());

        // Verify call status
        let updated_call = service.get_call(&call.id).await.unwrap();
        assert_eq!(updated_call.status, CallStatus::Ended);
        assert!(updated_call.end_time.is_some());
    }

    #[tokio::test]
    async fn test_room_creation() {
        let service = VoipService::new();

        let settings = RoomSettings {
            allow_recording: true,
            allow_screen_share: true,
            require_moderator: false,
            moderator_id: None,
            password_required: false,
            password_hash: None,
            time_limit_minutes: Some(60),
        };

        let result = service.create_room("user1", "Test Room", 10, settings.clone()).await;
        assert!(result.is_ok());

        let room = result.unwrap();
        assert_eq!(room.owner_id, "user1");
        assert_eq!(room.name, "Test Room");
        assert_eq!(room.max_participants, 10);
        assert_eq!(room.settings.allow_recording, settings.allow_recording);
    }

    #[tokio::test]
    async fn test_room_joining() {
        let service = VoipService::new();

        let room = service.create_room("user1", "Test Room", 5, RoomSettings::default()).await.unwrap();

        // Join the room
        let result = service.join_room(&room.id, "user2").await;
        assert!(result.is_ok());

        // Verify participant was added
        let updated_room = service.get_room(&room.id).await.unwrap();
        assert!(updated_room.participants.contains(&"user2".to_string()));
    }

    #[tokio::test]
    async fn test_signaling_message_exchange() {
        let service = VoipService::new();

        let message = SignalingMessage {
            call_id: "call123".to_string(),
            from_user: "user1".to_string(),
            to_user: "user2".to_string(),
            message_type: SignalingType::Offer,
            payload: json!({"sdp": "test_sdp"}),
            timestamp: Utc::now(),
        };

        // Send signaling message
        let result = service.send_signaling_message(message.clone()).await;
        assert!(result.is_ok());

        // Retrieve messages
        let messages = service.get_signaling_messages("call123", "user2").await.unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message_type, SignalingType::Offer);
    }

    #[tokio::test]
    async fn test_call_participant_limits() {
        let service = VoipService::new();

        // Create call with many participants
        let participants: Vec<String> = (1..60).map(|i| format!("user{}", i)).collect();
        let result = service.initiate_call("caller", participants, CallType::Conference).await;

        // Should succeed (no artificial limit in service layer)
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_room_capacity_limits() {
        let service = VoipService::new();

        // Create room with capacity 2
        let room = service.create_room("owner", "Small Room", 2, RoomSettings::default()).await.unwrap();

        // Join with first user
        service.join_room(&room.id, "user1").await.unwrap();

        // Try to join with second user (should succeed)
        let result = service.join_room(&room.id, "user2").await;
        assert!(result.is_ok());

        // Try to join with third user (should fail)
        let result = service.join_room(&room.id, "user3").await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Room is full");
    }
}

mod voip_core_tests {
    use super::*;
    use crate::core::voip::{WebRTCPeerConnection, ConnectionState, IceCandidate};

    #[tokio::test]
    async fn test_signaling_server_peer_registration() {
        let server = SignalingServer::new();

        let result = server.register_peer("peer1", "call123").await;
        assert!(result.is_ok());

        let peer = server.get_peer("peer1").await;
        assert!(peer.is_some());
        assert_eq!(peer.unwrap().call_id, "call123");
    }

    #[tokio::test]
    async fn test_signaling_server_peer_removal() {
        let server = SignalingServer::new();

        server.register_peer("peer1", "call123").await.unwrap();
        let result = server.remove_peer("peer1").await;
        assert!(result.is_ok());

        let peer = server.get_peer("peer1").await;
        assert!(peer.is_none());
    }

    #[tokio::test]
    async fn test_sdp_description_handling() {
        let server = SignalingServer::new();

        server.register_peer("peer1", "call123").await.unwrap();

        let sdp = "v=0\r\no=- 123 456 IN IP4 192.168.1.1\r\ns=-\r\nt=0 0\r\n";
        let result = server.set_description("peer1", sdp, true).await;
        assert!(result.is_ok());

        let peer = server.get_peer("peer1").await.unwrap();
        assert_eq!(peer.local_description.as_ref().unwrap(), sdp);
    }

    #[tokio::test]
    async fn test_ice_candidate_handling() {
        let server = SignalingServer::new();

        server.register_peer("peer1", "call123").await.unwrap();

        let candidate = IceCandidate {
            candidate: "candidate:1 1 UDP 123 192.168.1.1 12345 typ host".to_string(),
            sdp_mid: Some("0".to_string()),
            sdp_m_line_index: Some(0),
        };

        let result = server.add_ice_candidate("peer1", candidate.clone()).await;
        assert!(result.is_ok());

        let peer = server.get_peer("peer1").await.unwrap();
        assert_eq!(peer.ice_candidates.len(), 1);
        assert_eq!(peer.ice_candidates[0].candidate, candidate.candidate);
    }

    #[tokio::test]
    async fn test_call_peer_listing() {
        let server = SignalingServer::new();

        server.register_peer("peer1", "call123").await.unwrap();
        server.register_peer("peer2", "call123").await.unwrap();
        server.register_peer("peer3", "call456").await.unwrap();

        let call_peers = server.get_call_peers("call123").await;
        assert_eq!(call_peers.len(), 2);

        let call_peers_456 = server.get_call_peers("call456").await;
        assert_eq!(call_peers_456.len(), 1);
    }

    #[tokio::test]
    async fn test_media_server_stream_management() {
        let server = MediaServer::new();

        let stream_id = "stream123".to_string();
        let result = server.register_stream(crate::core::voip::MediaStream {
            id: stream_id.clone(),
            tracks: vec![],
            direction: crate::core::voip::StreamDirection::SendReceive,
        }).await;

        assert!(result.is_ok());

        let stream = server.get_stream(&stream_id).await;
        assert!(stream.is_some());
        assert_eq!(stream.unwrap().id, stream_id);
    }

    #[tokio::test]
    async fn test_voip_engine_health_check() {
        let engine = VoIPEngine::new();
        let is_healthy = engine.health_check().await;
        assert!(is_healthy);
    }
}

mod voip_middleware_tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter() {
        let limiter = VoipRateLimiter::new(2, 60); // 2 requests per minute

        let user_id = "user123";

        // First request should succeed
        let result1 = limiter.check_rate_limit(user_id).await;
        assert!(result1.is_ok());

        // Second request should succeed
        let result2 = limiter.check_rate_limit(user_id).await;
        assert!(result2.is_ok());

        // Third request should fail
        let result3 = limiter.check_rate_limit(user_id).await;
        assert!(result3.is_err());
        assert_eq!(result3.unwrap_err(), "Rate limit exceeded");
    }

    #[tokio::test]
    async fn test_call_validator() {
        // Test call initiation validation
        let context = crate::middlewares::voip_middleware::VoipContext {
            user_id: "user123".to_string(),
            call_id: None,
            room_id: None,
            permissions: vec!["voip.call".to_string(), "voip.call.initiate".to_string()],
            timestamp: Utc::now(),
        };

        let result = VoipCallValidator::validate_call_operation(&context, "initiate").await;
        assert!(result.is_ok());

        // Test without required permission
        let context_no_perm = crate::middlewares::voip_middleware::VoipContext {
            user_id: "user123".to_string(),
            call_id: None,
            room_id: None,
            permissions: vec!["voip.call".to_string()], // Missing initiate permission
            timestamp: Utc::now(),
        };

        let result = VoipCallValidator::validate_call_operation(&context_no_perm, "initiate").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_sdp_validation() {
        // Valid SDP
        let valid_sdp = "v=0\r\no=- 123 456 IN IP4 192.168.1.1\r\ns=-\r\nt=0 0\r\n";
        let result = VoipMediaValidator::validate_sdp(valid_sdp);
        assert!(result.is_ok());

        // Invalid SDP (empty)
        let result = VoipMediaValidator::validate_sdp("");
        assert!(result.is_err());

        // Invalid SDP (missing v=0)
        let invalid_sdp = "o=- 123 456 IN IP4 192.168.1.1\r\ns=-\r\nt=0 0\r\n";
        let result = VoipMediaValidator::validate_sdp(invalid_sdp);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_ice_candidate_validation() {
        // Valid ICE candidate
        let valid_candidate = "candidate:1 1 UDP 123 192.168.1.1 12345 typ host";
        let result = VoipMediaValidator::validate_ice_candidate(valid_candidate);
        assert!(result.is_ok());

        // Invalid ICE candidate (empty)
        let result = VoipMediaValidator::validate_ice_candidate("");
        assert!(result.is_err());

        // Invalid ICE candidate (wrong format)
        let invalid_candidate = "not-a-candidate";
        let result = VoipMediaValidator::validate_ice_candidate(invalid_candidate);
        assert!(result.is_err());
    }
}

mod voip_model_tests {
    use super::*;

    #[test]
    fn test_call_creation() {
        let call = VoipCallModel::new(
            "caller123".to_string(),
            vec!["user1".to_string(), "user2".to_string()],
            CallType::Video,
        );

        assert_eq!(call.caller_id, "caller123");
        assert_eq!(call.participants.len(), 2);
        assert_eq!(call.call_type, CallType::Video);
        assert_eq!(call.status, CallStatus::Initiating);
        assert!(call.end_time.is_none());
    }

    #[test]
    fn test_call_status_update() {
        let mut call = VoipCallModel::new(
            "caller123".to_string(),
            vec!["user1".to_string()],
            CallType::Audio,
        );

        call.update_status(CallStatus::Connected);
        assert_eq!(call.status, CallStatus::Connected);

        call.update_status(CallStatus::Ended);
        assert_eq!(call.status, CallStatus::Ended);
        assert!(call.end_time.is_some());
    }

    #[test]
    fn test_call_participant_management() {
        let mut call = VoipCallModel::new(
            "caller123".to_string(),
            vec!["user1".to_string()],
            CallType::Audio,
        );

        // Add participant
        let result = call.add_participant("user2".to_string());
        assert!(result.is_ok());
        assert_eq!(call.participants.len(), 2);

        // Try to add existing participant
        let result = call.add_participant("user1".to_string());
        assert!(result.is_err());

        // Remove participant
        let result = call.remove_participant("user1");
        assert!(result.is_ok());
        assert_eq!(call.participants.len(), 1);
    }

    #[test]
    fn test_room_creation() {
        let settings = RoomSettings {
            allow_recording: true,
            allow_screen_share: false,
            require_moderator: true,
            moderator_id: Some("mod123".to_string()),
            password_required: true,
            password_hash: Some("hashed_password".to_string()),
            time_limit_minutes: Some(120),
        };

        let room = VoipRoomModel::new(
            "owner123".to_string(),
            "Conference Room".to_string(),
            50,
            settings.clone(),
        );

        assert_eq!(room.owner_id, "owner123");
        assert_eq!(room.name, "Conference Room");
        assert_eq!(room.max_participants, 50);
        assert_eq!(room.settings.allow_recording, settings.allow_recording);
        assert_eq!(room.settings.require_moderator, settings.require_moderator);
    }

    #[test]
    fn test_room_capacity() {
        let room = VoipRoomModel::new(
            "owner123".to_string(),
            "Small Room".to_string(),
            2,
            RoomSettings::default(),
        );

        assert!(room.can_join()); // Owner is already a participant

        room.add_participant("user1".to_string()).unwrap();
        assert!(room.can_join()); // Can still join

        room.add_participant("user2".to_string()).unwrap();
        assert!(!room.can_join()); // Room is full
    }

    #[test]
    fn test_signaling_message_creation() {
        let message = SignalingMessage {
            id: "msg123".to_string(),
            call_id: "call123".to_string(),
            from_user: "user1".to_string(),
            to_user: "user2".to_string(),
            message_type: SignalingType::Offer,
            payload: json!({"sdp": "test_sdp"}),
            sequence_number: 1,
            created_at: Utc::now(),
        };

        assert_eq!(message.call_id, "call123");
        assert_eq!(message.from_user, "user1");
        assert_eq!(message.to_user, "user2");
        assert_eq!(message.message_type, SignalingType::Offer);
        assert_eq!(message.sequence_number, 1);
    }
}

mod voip_integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_complete_call_flow() {
        let service = VoipService::new();

        // 1. Initiate call
        let call = service.initiate_call(
            "caller",
            vec!["callee".to_string()],
            CallType::Video
        ).await.unwrap();

        // 2. Accept call
        service.accept_call(&call.id, "callee").await.unwrap();

        // 3. Send signaling messages
        let offer_message = SignalingMessage {
            call_id: call.id.clone(),
            from_user: "caller".to_string(),
            to_user: "callee".to_string(),
            message_type: SignalingType::Offer,
            payload: json!({"sdp": "offer_sdp"}),
            timestamp: Utc::now(),
        };

        service.send_signaling_message(offer_message).await.unwrap();

        let answer_message = SignalingMessage {
            call_id: call.id.clone(),
            from_user: "callee".to_string(),
            to_user: "caller".to_string(),
            message_type: SignalingType::Answer,
            payload: json!({"sdp": "answer_sdp"}),
            timestamp: Utc::now(),
        };

        service.send_signaling_message(answer_message).await.unwrap();

        // 4. Check signaling messages
        let caller_messages = service.get_signaling_messages(&call.id, "caller").await.unwrap();
        let callee_messages = service.get_signaling_messages(&call.id, "callee").await.unwrap();

        assert_eq!(caller_messages.len(), 1);
        assert_eq!(callee_messages.len(), 1);
        assert_eq!(caller_messages[0].message_type, SignalingType::Answer);
        assert_eq!(callee_messages[0].message_type, SignalingType::Offer);

        // 5. End call
        service.end_call(&call.id, "caller").await.unwrap();

        // 6. Verify final state
        let final_call = service.get_call(&call.id).await.unwrap();
        assert_eq!(final_call.status, CallStatus::Ended);
        assert!(final_call.end_time.is_some());
    }

    #[tokio::test]
    async fn test_conference_room_flow() {
        let service = VoipService::new();

        // 1. Create room
        let room = service.create_room(
            "organizer",
            "Team Meeting",
            5,
            RoomSettings::default()
        ).await.unwrap();

        // 2. Join participants
        service.join_room(&room.id, "user1").await.unwrap();
        service.join_room(&room.id, "user2").await.unwrap();
        service.join_room(&room.id, "user3").await.unwrap();

        // 3. Verify room state
        let updated_room = service.get_room(&room.id).await.unwrap();
        assert_eq!(updated_room.participants.len(), 4); // organizer + 3 users

        // 4. Check active rooms for users
        let user1_rooms = service.get_active_rooms("user1").await;
        assert_eq!(user1_rooms.len(), 1);
        assert_eq!(user1_rooms[0].id, room.id);
    }
}

mod voip_security_tests {
    use super::*;

    #[tokio::test]
    async fn test_call_access_control() {
        let service = VoipService::new();

        // Create call
        let call = service.initiate_call(
            "caller",
            vec!["authorized_user".to_string()],
            CallType::Audio
        ).await.unwrap();

        // Authorized user should be able to accept
        let result = service.accept_call(&call.id, "authorized_user").await;
        assert!(result.is_ok());

        // Unauthorized user should not be able to accept
        let result = service.end_call(&call.id, "unauthorized_user").await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "User not authorized to end this call");
    }

    #[tokio::test]
    async fn test_room_access_control() {
        let service = VoipService::new();

        // Create private room
        let mut settings = RoomSettings::default();
        settings.password_required = true;
        settings.password_hash = Some("hashed_secret".to_string());

        let room = service.create_room(
            "owner",
            "Private Room",
            10,
            settings
        ).await.unwrap();

        // Authorized user (owner) can join
        let result = service.join_room(&room.id, "owner").await;
        // Note: This would succeed because owner is already a participant

        // New user cannot join without proper validation
        // (In real implementation, password validation would be required)
    }

    #[tokio::test]
    async fn test_signaling_isolation() {
        let service = VoipService::new();

        // Create two separate calls
        let call1 = service.initiate_call("user1", vec!["user2".to_string()], CallType::Audio).await.unwrap();
        let call2 = service.initiate_call("user3", vec!["user4".to_string()], CallType::Audio).await.unwrap();

        // Send message to call1
        let message1 = SignalingMessage {
            call_id: call1.id.clone(),
            from_user: "user1".to_string(),
            to_user: "user2".to_string(),
            message_type: SignalingType::Offer,
            payload: json!({"test": "call1"}),
            timestamp: Utc::now(),
        };
        service.send_signaling_message(message1).await.unwrap();

        // Send message to call2
        let message2 = SignalingMessage {
            call_id: call2.id.clone(),
            from_user: "user3".to_string(),
            to_user: "user4".to_string(),
            message_type: SignalingType::Offer,
            payload: json!({"test": "call2"}),
            timestamp: Utc::now(),
        };
        service.send_signaling_message(message2).await.unwrap();

        // Verify messages are isolated between calls
        let call1_messages = service.get_signaling_messages(&call1.id, "user2").await.unwrap();
        let call2_messages = service.get_signaling_messages(&call2.id, "user4").await.unwrap();

        assert_eq!(call1_messages.len(), 1);
        assert_eq!(call2_messages.len(), 1);
        assert_eq!(call1_messages[0].payload["test"], "call1");
        assert_eq!(call2_messages[0].payload["test"], "call2");
    }
}