// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: VoIP Controller
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide secure VoIP endpoints for voice/video calls,
//  conference management, and real-time communication.
//  NOTICE: Implements WebRTC signaling, call management, and conference
//  controls with enterprise security and audit logging.
//  VOIP STANDARDS: WebRTC, SIP, RTP, SRTP, DTLS
//  SECURITY: End-to-end encryption, secure signaling, call recording
//  COMPLIANCE: GDPR, HIPAA, NIST VoIP Security Guidelines
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use warp::Reply;
use crate::services::voip_service::{VoipService, VoipCall, VoipRoom, SignalingMessage, CallType, RoomSettings};
use crate::core::asterisk_client::{AsteriskClient, AriChannel, AriBridge, AriEndpoint};
use std::sync::Arc;
use warp::http::StatusCode;
use serde::{Deserialize, Serialize};

/// [INITIATE CALL REQUEST] Start New Call Request
#[derive(Deserialize, utoipa::ToSchema)]
pub struct InitiateCallRequest {
    pub participants: Vec<String>,
    pub call_type: CallType,
}

/// [CREATE ROOM REQUEST] Create Conference Room Request
#[derive(Deserialize, utoipa::ToSchema)]
pub struct CreateRoomRequest {
    pub name: String,
    pub max_participants: u32,
    pub settings: RoomSettings,
}

/// [SIGNALING REQUEST] WebRTC Signaling Message
#[derive(Deserialize, utoipa::ToSchema)]
pub struct SignalingRequest {
    pub to_user: String,
    pub message_type: String,
    pub payload: serde_json::Value,
}

/// [ERROR RESPONSE] Standard Error Response
#[derive(Serialize, utoipa::ToSchema)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

/// [INITIATE CALL HANDLER] Start a new VoIP call
/// @MISSION Create and initiate a new voice/video call.
/// @THREAT Unauthorized call initiation.
/// @COUNTERMEASURE User authentication and permission validation.
/// @AUDIT All call initiations are logged.
#[utoipa::path(
    post,
    path = "/api/v1/voip/calls",
    request_body = InitiateCallRequest,
    responses(
        (status = 201, description = "Call initiated successfully", body = VoipCall),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse)
    )
)]
pub async fn initiate_call(
    voip_service: Arc<VoipService>,
    user_id: String,
    req: InitiateCallRequest,
) -> Result<impl Reply, warp::Rejection> {
    match voip_service.initiate_call(&user_id, req.participants, req.call_type).await {
        Ok(call) => {
            let response = warp::reply::json(&call);
            Ok(warp::reply::with_status(response, StatusCode::CREATED))
        }
        Err(err) => {
            let error_response = ErrorResponse {
                error: "Call initiation failed".to_string(),
                message: err,
            };
            let response = warp::reply::json(&error_response);
            Ok(warp::reply::with_status(response, StatusCode::BAD_REQUEST))
        }
    }
}

/// [ACCEPT CALL HANDLER] Accept an incoming call
/// @MISSION Accept a ringing call and establish connection.
/// @THREAT Unauthorized call acceptance.
/// @COUNTERMEASURE Participant validation.
/// @AUDIT Call acceptance events are logged.
#[utoipa::path(
    post,
    path = "/api/v1/voip/calls/{call_id}/accept",
    responses(
        (status = 200, description = "Call accepted successfully"),
        (status = 404, description = "Call not found", body = ErrorResponse),
        (status = 403, description = "Not authorized", body = ErrorResponse)
    )
)]
pub async fn accept_call(
    voip_service: Arc<VoipService>,
    user_id: String,
    call_id: String,
) -> Result<impl Reply, warp::Rejection> {
    match voip_service.accept_call(&call_id, &user_id).await {
        Ok(_) => Ok(warp::reply::with_status("Call accepted", StatusCode::OK)),
        Err(err) => {
            let error_response = ErrorResponse {
                error: "Call acceptance failed".to_string(),
                message: err,
            };
            let response = warp::reply::json(&error_response);
            let status = if err.contains("not found") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::FORBIDDEN
            };
            Ok(warp::reply::with_status(response, status))
        }
    }
}

/// [END CALL HANDLER] Terminate an active call
/// @MISSION End a call and clean up resources.
/// @THREAT Resource leaks.
/// @COUNTERMEASURE Proper cleanup and state management.
/// @AUDIT Call termination events are logged.
#[utoipa::path(
    post,
    path = "/api/v1/voip/calls/{call_id}/end",
    responses(
        (status = 200, description = "Call ended successfully"),
        (status = 404, description = "Call not found", body = ErrorResponse),
        (status = 403, description = "Not authorized", body = ErrorResponse)
    )
)]
pub async fn end_call(
    voip_service: Arc<VoipService>,
    user_id: String,
    call_id: String,
) -> Result<impl Reply, warp::Rejection> {
    match voip_service.end_call(&call_id, &user_id).await {
        Ok(_) => Ok(warp::reply::with_status("Call ended", StatusCode::OK)),
        Err(err) => {
            let error_response = ErrorResponse {
                error: "Call termination failed".to_string(),
                message: err,
            };
            let response = warp::reply::json(&error_response);
            let status = if err.contains("not found") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::FORBIDDEN
            };
            Ok(warp::reply::with_status(response, status))
        }
    }
}

/// [GET CALL HANDLER] Get call information
/// @MISSION Retrieve call details and status.
/// @THREAT Information disclosure.
/// @COUNTERMEASURE Access control.
#[utoipa::path(
    get,
    path = "/api/v1/voip/calls/{call_id}",
    responses(
        (status = 200, description = "Call information retrieved", body = VoipCall),
        (status = 404, description = "Call not found", body = ErrorResponse)
    )
)]
pub async fn get_call(
    voip_service: Arc<VoipService>,
    call_id: String,
) -> Result<impl Reply, warp::Rejection> {
    match voip_service.get_call(&call_id).await {
        Ok(call) => {
            let response = warp::reply::json(&call);
            Ok(warp::reply::with_status(response, StatusCode::OK))
        }
        Err(err) => {
            let error_response = ErrorResponse {
                error: "Call retrieval failed".to_string(),
                message: err,
            };
            let response = warp::reply::json(&error_response);
            Ok(warp::reply::with_status(response, StatusCode::NOT_FOUND))
        }
    }
}

/// [LIST ACTIVE CALLS HANDLER] Get user's active calls
/// @MISSION List all active calls for the authenticated user.
/// @THREAT Information disclosure.
/// @COUNTERMEASURE User-specific filtering.
#[utoipa::path(
    get,
    path = "/api/v1/voip/calls",
    responses(
        (status = 200, description = "Active calls retrieved", body = Vec<VoipCall>)
    )
)]
pub async fn list_active_calls(
    voip_service: Arc<VoipService>,
    user_id: String,
) -> Result<impl Reply, warp::Rejection> {
    let calls = voip_service.get_active_calls(&user_id).await;
    let response = warp::reply::json(&calls);
    Ok(warp::reply::with_status(response, StatusCode::OK))
}

/// [CREATE ROOM HANDLER] Create a new conference room
/// @MISSION Set up a conference room for multiple participants.
/// @THREAT Unauthorized room creation.
/// @COUNTERMEASURE User permissions.
/// @AUDIT Room creation events are logged.
#[utoipa::path(
    post,
    path = "/api/v1/voip/rooms",
    request_body = CreateRoomRequest,
    responses(
        (status = 201, description = "Room created successfully", body = VoipRoom),
        (status = 400, description = "Invalid request", body = ErrorResponse)
    )
)]
pub async fn create_room(
    voip_service: Arc<VoipService>,
    user_id: String,
    req: CreateRoomRequest,
) -> Result<impl Reply, warp::Rejection> {
    match voip_service.create_room(&user_id, &req.name, req.max_participants, req.settings).await {
        Ok(room) => {
            let response = warp::reply::json(&room);
            Ok(warp::reply::with_status(response, StatusCode::CREATED))
        }
        Err(err) => {
            let error_response = ErrorResponse {
                error: "Room creation failed".to_string(),
                message: err,
            };
            let response = warp::reply::json(&error_response);
            Ok(warp::reply::with_status(response, StatusCode::BAD_REQUEST))
        }
    }
}

/// [JOIN ROOM HANDLER] Join an existing conference room
/// @MISSION Add participant to conference room.
/// @THREAT Room capacity overflow.
/// @COUNTERMEASURE Capacity checks.
#[utoipa::path(
    post,
    path = "/api/v1/voip/rooms/{room_id}/join",
    responses(
        (status = 200, description = "Joined room successfully"),
        (status = 404, description = "Room not found", body = ErrorResponse),
        (status = 403, description = "Room full or not authorized", body = ErrorResponse)
    )
)]
pub async fn join_room(
    voip_service: Arc<VoipService>,
    user_id: String,
    room_id: String,
) -> Result<impl Reply, warp::Rejection> {
    match voip_service.join_room(&room_id, &user_id).await {
        Ok(_) => Ok(warp::reply::with_status("Joined room", StatusCode::OK)),
        Err(err) => {
            let error_response = ErrorResponse {
                error: "Join room failed".to_string(),
                message: err,
            };
            let response = warp::reply::json(&error_response);
            let status = if err.contains("not found") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::FORBIDDEN
            };
            Ok(warp::reply::with_status(response, status))
        }
    }
}

/// [GET ROOM HANDLER] Get room information
/// @MISSION Retrieve conference room details.
/// @THREAT Information disclosure.
/// @COUNTERMEASURE Access control.
#[utoipa::path(
    get,
    path = "/api/v1/voip/rooms/{room_id}",
    responses(
        (status = 200, description = "Room information retrieved", body = VoipRoom),
        (status = 404, description = "Room not found", body = ErrorResponse)
    )
)]
pub async fn get_room(
    voip_service: Arc<VoipService>,
    room_id: String,
) -> Result<impl Reply, warp::Rejection> {
    match voip_service.get_room(&room_id).await {
        Ok(room) => {
            let response = warp::reply::json(&room);
            Ok(warp::reply::with_status(response, StatusCode::OK))
        }
        Err(err) => {
            let error_response = ErrorResponse {
                error: "Room retrieval failed".to_string(),
                message: err,
            };
            let response = warp::reply::json(&error_response);
            Ok(warp::reply::with_status(response, StatusCode::NOT_FOUND))
        }
    }
}

/// [LIST ACTIVE ROOMS HANDLER] Get user's active rooms
/// @MISSION List all active rooms for the authenticated user.
/// @THREAT Information disclosure.
/// @COUNTERMEASURE User-specific filtering.
#[utoipa::path(
    get,
    path = "/api/v1/voip/rooms",
    responses(
        (status = 200, description = "Active rooms retrieved", body = Vec<VoipRoom>)
    )
)]
pub async fn list_active_rooms(
    voip_service: Arc<VoipService>,
    user_id: String,
) -> Result<impl Reply, warp::Rejection> {
    let rooms = voip_service.get_active_rooms(&user_id).await;
    let response = warp::reply::json(&rooms);
    Ok(warp::reply::with_status(response, StatusCode::OK))
}

/// [SIGNALING HANDLER] Send WebRTC signaling message
/// @MISSION Exchange WebRTC signaling data.
/// @THREAT Signaling interception.
/// @COUNTERMEASURE Encrypted channels.
#[utoipa::path(
    post,
    path = "/api/v1/voip/calls/{call_id}/signaling",
    request_body = SignalingRequest,
    responses(
        (status = 200, description = "Signaling message sent"),
        (status = 400, description = "Invalid request", body = ErrorResponse)
    )
)]
pub async fn send_signaling(
    voip_service: Arc<VoipService>,
    user_id: String,
    call_id: String,
    req: SignalingRequest,
) -> Result<impl Reply, warp::Rejection> {
    use crate::services::voip_service::SignalingType;

    let message_type = match req.message_type.as_str() {
        "offer" => SignalingType::Offer,
        "answer" => SignalingType::Answer,
        "ice_candidate" => SignalingType::IceCandidate,
        "hangup" => SignalingType::Hangup,
        "mute" => SignalingType::Mute,
        "unmute" => SignalingType::Unmute,
        _ => {
            let error_response = ErrorResponse {
                error: "Invalid signaling type".to_string(),
                message: format!("Unknown signaling type: {}", req.message_type),
            };
            let response = warp::reply::json(&error_response);
            return Ok(warp::reply::with_status(response, StatusCode::BAD_REQUEST));
        }
    };

    let message = SignalingMessage {
        call_id: call_id.clone(),
        from_user: user_id,
        to_user: req.to_user,
        message_type,
        payload: req.payload,
        timestamp: chrono::Utc::now(),
    };

    match voip_service.send_signaling_message(message).await {
        Ok(_) => Ok(warp::reply::with_status("Signaling message sent", StatusCode::OK)),
        Err(err) => {
            let error_response = ErrorResponse {
                error: "Signaling failed".to_string(),
                message: err,
            };
            let response = warp::reply::json(&error_response);
            Ok(warp::reply::with_status(response, StatusCode::BAD_REQUEST))
        }
    }
}

/// [GET SIGNALING HANDLER] Get signaling messages
/// @MISSION Retrieve pending signaling messages.
/// @THREAT Message loss.
/// @COUNTERMEASURE Reliable queuing.
#[utoipa::path(
    get,
    path = "/api/v1/voip/calls/{call_id}/signaling",
    responses(
        (status = 200, description = "Signaling messages retrieved", body = Vec<SignalingMessage>)
    )
)]
pub async fn get_signaling(
    voip_service: Arc<VoipService>,
    user_id: String,
    call_id: String,
) -> Result<impl Reply, warp::Rejection> {
    match voip_service.get_signaling_messages(&call_id, &user_id).await {
        Ok(messages) => {
            let response = warp::reply::json(&messages);
            Ok(warp::reply::with_status(response, StatusCode::OK))
        }
        Err(err) => {
            let error_response = ErrorResponse {
                error: "Signaling retrieval failed".to_string(),
                message: err,
            };
            let response = warp::reply::json(&error_response);
            Ok(warp::reply::with_status(response, StatusCode::BAD_REQUEST))
        }
    }
}

// ===== ASTERISK-SPECIFIC ENDPOINTS =====

/// [GET ASTERISK CHANNELS] Get all active Asterisk channels
/// @MISSION Retrieve real-time channel information from Asterisk PBX.
/// @THREAT Information disclosure, PBX state exposure.
/// @COUNTERMEASURE Access control, data sanitization.
/// @AUDIT Channel queries are logged.
#[utoipa::path(
    get,
    path = "/api/v1/voip/asterisk/channels",
    responses(
        (status = 200, description = "Channels retrieved successfully", body = Vec<AriChannel>),
        (status = 500, description = "Asterisk communication error", body = ErrorResponse)
    )
)]
pub async fn get_asterisk_channels(
    asterisk_client: Arc<AsteriskClient>,
) -> Result<impl Reply, warp::Rejection> {
    match asterisk_client.get_channels().await {
        Ok(channels) => {
            let response = warp::reply::json(&channels);
            Ok(warp::reply::with_status(response, StatusCode::OK))
        }
        Err(err) => {
            let error_response = ErrorResponse {
                error: "Failed to retrieve Asterisk channels".to_string(),
                message: err,
            };
            let response = warp::reply::json(&error_response);
            Ok(warp::reply::with_status(response, StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}

/// [GET ASTERISK CHANNEL] Get specific Asterisk channel information
/// @MISSION Retrieve detailed channel information from Asterisk.
/// @THREAT Information disclosure.
/// @COUNTERMEASURE Access control.
/// @AUDIT Channel access is logged.
#[utoipa::path(
    get,
    path = "/api/v1/voip/asterisk/channels/{channel_id}",
    responses(
        (status = 200, description = "Channel information retrieved", body = AriChannel),
        (status = 404, description = "Channel not found", body = ErrorResponse),
        (status = 500, description = "Asterisk communication error", body = ErrorResponse)
    )
)]
pub async fn get_asterisk_channel(
    channel_id: String,
    asterisk_client: Arc<AsteriskClient>,
) -> Result<impl Reply, warp::Rejection> {
    match asterisk_client.get_channel(&channel_id).await {
        Ok(channel) => {
            let response = warp::reply::json(&channel);
            Ok(warp::reply::with_status(response, StatusCode::OK))
        }
        Err(err) => {
            let error_response = ErrorResponse {
                error: "Failed to retrieve Asterisk channel".to_string(),
                message: err,
            };
            let response = warp::reply::json(&error_response);
            let status = if err.contains("not found") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            Ok(warp::reply::with_status(response, status))
        }
    }
}

/// [GET ASTERISK BRIDGES] Get all Asterisk bridges
/// @MISSION Retrieve conference bridge information from Asterisk.
/// @THREAT Information disclosure.
/// @COUNTERMEASURE Access control.
/// @AUDIT Bridge queries are logged.
#[utoipa::path(
    get,
    path = "/api/v1/voip/asterisk/bridges",
    responses(
        (status = 200, description = "Bridges retrieved successfully", body = Vec<AriBridge>),
        (status = 500, description = "Asterisk communication error", body = ErrorResponse)
    )
)]
pub async fn get_asterisk_bridges(
    asterisk_client: Arc<AsteriskClient>,
) -> Result<impl Reply, warp::Rejection> {
    match asterisk_client.get_bridges().await {
        Ok(bridges) => {
            let response = warp::reply::json(&bridges);
            Ok(warp::reply::with_status(response, StatusCode::OK))
        }
        Err(err) => {
            let error_response = ErrorResponse {
                error: "Failed to retrieve Asterisk bridges".to_string(),
                message: err,
            };
            let response = warp::reply::json(&error_response);
            Ok(warp::reply::with_status(response, StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}

/// [GET ASTERISK ENDPOINTS] Get all SIP endpoints
/// @MISSION Retrieve SIP endpoint information from Asterisk.
/// @THREAT Information disclosure.
/// @COUNTERMEASURE Access control.
/// @AUDIT Endpoint queries are logged.
#[utoipa::path(
    get,
    path = "/api/v1/voip/asterisk/endpoints",
    responses(
        (status = 200, description = "Endpoints retrieved successfully", body = Vec<AriEndpoint>),
        (status = 500, description = "Asterisk communication error", body = ErrorResponse)
    )
)]
pub async fn get_asterisk_endpoints(
    asterisk_client: Arc<AsteriskClient>,
) -> Result<impl Reply, warp::Rejection> {
    match asterisk_client.get_endpoints().await {
        Ok(endpoints) => {
            let response = warp::reply::json(&endpoints);
            Ok(warp::reply::with_status(response, StatusCode::OK))
        }
        Err(err) => {
            let error_response = ErrorResponse {
                error: "Failed to retrieve Asterisk endpoints".to_string(),
                message: err,
            };
            let response = warp::reply::json(&error_response);
            Ok(warp::reply::with_status(response, StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}

/// [GET ASTERISK ENDPOINT] Get specific SIP endpoint information
/// @MISSION Retrieve detailed endpoint information from Asterisk.
/// @THREAT Information disclosure.
/// @COUNTERMEASURE Access control.
/// @AUDIT Endpoint access is logged.
#[utoipa::path(
    get,
    path = "/api/v1/voip/asterisk/endpoints/{tech}/{resource}",
    responses(
        (status = 200, description = "Endpoint information retrieved", body = AriEndpoint),
        (status = 404, description = "Endpoint not found", body = ErrorResponse),
        (status = 500, description = "Asterisk communication error", body = ErrorResponse)
    )
)]
pub async fn get_asterisk_endpoint(
    tech: String,
    resource: String,
    asterisk_client: Arc<AsteriskClient>,
) -> Result<impl Reply, warp::Rejection> {
    match asterisk_client.get_endpoint(&tech, &resource).await {
        Ok(endpoint) => {
            let response = warp::reply::json(&endpoint);
            Ok(warp::reply::with_status(response, StatusCode::OK))
        }
        Err(err) => {
            let error_response = ErrorResponse {
                error: "Failed to retrieve Asterisk endpoint".to_string(),
                message: err,
            };
            let response = warp::reply::json(&error_response);
            let status = if err.contains("not found") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            Ok(warp::reply::with_status(response, status))
        }
    }
}

/// [GET ASTERISK INFO] Get Asterisk system information
/// @MISSION Retrieve Asterisk PBX system status and configuration.
/// @THREAT Information disclosure.
/// @COUNTERMEASURE Access control, data filtering.
/// @AUDIT System queries are logged.
#[utoipa::path(
    get,
    path = "/api/v1/voip/asterisk/info",
    responses(
        (status = 200, description = "Asterisk information retrieved", body = serde_json::Value),
        (status = 500, description = "Asterisk communication error", body = ErrorResponse)
    )
)]
pub async fn get_asterisk_info(
    asterisk_client: Arc<AsteriskClient>,
) -> Result<impl Reply, warp::Rejection> {
    match asterisk_client.get_asterisk_info().await {
        Ok(info) => {
            let response = warp::reply::json(&info);
            Ok(warp::reply::with_status(response, StatusCode::OK))
        }
        Err(err) => {
            let error_response = ErrorResponse {
                error: "Failed to retrieve Asterisk information".to_string(),
                message: err,
            };
            let response = warp::reply::json(&error_response);
            Ok(warp::reply::with_status(response, StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}

/// [ASTERISK HEALTH CHECK] Check Asterisk connectivity
/// @MISSION Verify Asterisk PBX availability and responsiveness.
/// @THREAT Service disruption detection.
/// @COUNTERMEASURE Health monitoring.
/// @AUDIT Health checks are logged.
#[utoipa::path(
    get,
    path = "/api/v1/voip/asterisk/health",
    responses(
        (status = 200, description = "Asterisk is healthy"),
        (status = 503, description = "Asterisk is unhealthy", body = ErrorResponse)
    )
)]
pub async fn asterisk_health_check(
    asterisk_client: Arc<AsteriskClient>,
) -> Result<impl Reply, warp::Rejection> {
    match asterisk_client.health_check().await {
        Ok(true) => Ok(warp::reply::with_status("Asterisk is healthy", StatusCode::OK)),
        Ok(false) => {
            let error_response = ErrorResponse {
                error: "Asterisk unhealthy".to_string(),
                message: "Asterisk PBX is not responding".to_string(),
            };
            let response = warp::reply::json(&error_response);
            Ok(warp::reply::with_status(response, StatusCode::SERVICE_UNAVAILABLE))
        }
        Err(err) => {
            let error_response = ErrorResponse {
                error: "Health check failed".to_string(),
                message: err,
            };
            let response = warp::reply::json(&error_response);
            Ok(warp::reply::with_status(response, StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}