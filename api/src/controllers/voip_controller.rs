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

use warp::{Reply, reply};
use crate::services::voip_service::{VoipService, VoipCall, VoipRoom, SignalingMessage, CallType, RoomSettings, UserExtension, DeviceRegistration, PresenceStatus, EndpointType, PresenceState, FederatedOffice, FederationLink, FederationRoute, FederationLinkType, AsteriskFederationConfig};
use crate::core::asterisk_client::{AsteriskClient, AriChannel, AriBridge, AriEndpoint};
use std::sync::Arc;
use warp::http::StatusCode;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

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

/// [ASSIGN EXTENSION REQUEST] Assign Extension to User
#[derive(Deserialize, utoipa::ToSchema)]
pub struct AssignExtensionRequest {
    pub extension: String,
    pub display_name: Option<String>,
}

/// [REGISTER DEVICE REQUEST] Register VoIP Device

/// [EXTENSION WITH COUNTRY INFO] Extension with country information
#[derive(Serialize, utoipa::ToSchema)]
pub struct ExtensionWithCountryInfo {
    pub user_id: String,
    pub extension: String,
    pub display_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub enabled: bool,
    pub country_code: Option<String>,
    pub country_name: Option<String>,
}

/// [EXTENSION STRUCTURE INFO] Detailed extension structure breakdown
#[derive(Serialize, utoipa::ToSchema)]
pub struct ExtensionStructureInfo {
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub local_extension: String,
    pub full_extension: String,
    pub parts: Vec<String>,
}

/// [REGISTER OFFICE REQUEST] Register a new federated office
#[derive(Deserialize, utoipa::ToSchema)]
pub struct RegisterOfficeRequest {
    pub name: String,
    pub location: String,
    pub office_prefix: String,
    pub asterisk_config: AsteriskFederationConfig,
}

/// [CREATE FEDERATION LINK REQUEST] Create federation link
#[derive(Deserialize, utoipa::ToSchema)]
pub struct CreateFederationLinkRequest {
    pub source_office_id: String,
    pub target_office_id: String,
    pub link_type: FederationLinkType,
    pub priority: u8,
}

/// [CREATE FEDERATION ROUTE REQUEST] Create federation route
#[derive(Deserialize, utoipa::ToSchema)]
pub struct CreateFederationRouteRequest {
    pub source_office_prefix: String,
    pub destination_pattern: String,
    pub target_office_id: String,
    pub cost_priority: u8,
}
#[derive(Deserialize, utoipa::ToSchema)]
pub struct RegisterDeviceRequest {
    pub device_name: String,
    pub endpoint_type: String,
    pub endpoint_uri: String,
}

/// [UPDATE PRESENCE REQUEST] Update User Presence
#[derive(Deserialize, utoipa::ToSchema)]
pub struct UpdatePresenceRequest {
    pub status: String,
    pub status_message: Option<String>,
    pub current_device: Option<String>,
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
            Ok(reply::with_status(response, StatusCode::CREATED))
        }
        Err(err) => {
            let error_response = ErrorResponse {
                error: "Call initiation failed".to_string(),
                message: err,
            };
            let response = warp::reply::json(&error_response);
            Ok(reply::with_status(response, StatusCode::BAD_REQUEST))
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
        Ok(_) => Ok(reply::with_status("Call accepted", StatusCode::OK)),
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
        Ok(_) => Ok(reply::with_status("Call ended", StatusCode::OK)),
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
            Ok(reply::with_status(response, StatusCode::OK))
        }
        Err(err) => {
            let error_response = ErrorResponse {
                error: "Call retrieval failed".to_string(),
                message: err,
            };
            let response = warp::reply::json(&error_response);
            Ok(reply::with_status(response, StatusCode::NOT_FOUND))
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
    Ok(reply::with_status(response, StatusCode::OK))
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
            Ok(reply::with_status(response, StatusCode::CREATED))
        }
        Err(err) => {
            let error_response = ErrorResponse {
                error: "Room creation failed".to_string(),
                message: err,
            };
            let response = warp::reply::json(&error_response);
            Ok(reply::with_status(response, StatusCode::BAD_REQUEST))
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
        Ok(_) => Ok(reply::with_status("Joined room", StatusCode::OK)),
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
            Ok(reply::with_status(response, StatusCode::OK))
        }
        Err(err) => {
            let error_response = ErrorResponse {
                error: "Room retrieval failed".to_string(),
                message: err,
            };
            let response = warp::reply::json(&error_response);
            Ok(reply::with_status(response, StatusCode::NOT_FOUND))
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
    Ok(reply::with_status(response, StatusCode::OK))
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
            return Ok(reply::with_status(response, StatusCode::BAD_REQUEST));
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
        Ok(_) => Ok(reply::with_status("Signaling message sent", StatusCode::OK)),
        Err(err) => {
            let error_response = ErrorResponse {
                error: "Signaling failed".to_string(),
                message: err,
            };
            let response = warp::reply::json(&error_response);
            Ok(reply::with_status(response, StatusCode::BAD_REQUEST))
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
            Ok(reply::with_status(response, StatusCode::OK))
        }
        Err(err) => {
            let error_response = ErrorResponse {
                error: "Signaling retrieval failed".to_string(),
                message: err,
            };
            let response = warp::reply::json(&error_response);
            Ok(reply::with_status(response, StatusCode::BAD_REQUEST))
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
            Ok(reply::with_status(response, StatusCode::OK))
        }
        Err(err) => {
            let error_response = ErrorResponse {
                error: "Failed to retrieve Asterisk channels".to_string(),
                message: err,
            };
            let response = warp::reply::json(&error_response);
            Ok(reply::with_status(response, StatusCode::INTERNAL_SERVER_ERROR))
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
            Ok(reply::with_status(response, StatusCode::OK))
        }
        Err(err) => {
            let error_response = ErrorResponse {
                error: "Failed to retrieve Asterisk channel".to_string(),
                message: err.to_string(),
            };
            let response = warp::reply::json(&error_response);
            let status = if err.to_string().contains("not found") {
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
            Ok(reply::with_status(response, StatusCode::OK))
        }
        Err(err) => {
            let error_response = ErrorResponse {
                error: "Failed to retrieve Asterisk bridges".to_string(),
                message: err,
            };
            let response = warp::reply::json(&error_response);
            Ok(reply::with_status(response, StatusCode::INTERNAL_SERVER_ERROR))
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
            Ok(reply::with_status(response, StatusCode::OK))
        }
        Err(err) => {
            let error_response = ErrorResponse {
                error: "Failed to retrieve Asterisk endpoints".to_string(),
                message: err,
            };
            let response = warp::reply::json(&error_response);
            Ok(reply::with_status(response, StatusCode::INTERNAL_SERVER_ERROR))
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
            Ok(reply::with_status(response, StatusCode::OK))
        }
        Err(err) => {
            let error_response = ErrorResponse {
                error: "Failed to retrieve Asterisk endpoint".to_string(),
                message: err.to_string(),
            };
            let response = warp::reply::json(&error_response);
            let status = if err.to_string().contains("not found") {
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
            Ok(reply::with_status(response, StatusCode::OK))
        }
        Err(err) => {
            let error_response = ErrorResponse {
                error: "Failed to retrieve Asterisk information".to_string(),
                message: err,
            };
            let response = warp::reply::json(&error_response);
            Ok(reply::with_status(response, StatusCode::INTERNAL_SERVER_ERROR))
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
        Ok(true) => Ok(reply::with_status("Asterisk is healthy", StatusCode::OK)),
        Ok(false) => {
            let error_response = ErrorResponse {
                error: "Asterisk unhealthy".to_string(),
                message: "Asterisk PBX is not responding".to_string(),
            };
            let response = warp::reply::json(&error_response);
            Ok(reply::with_status(response, StatusCode::SERVICE_UNAVAILABLE))
        }
        Err(err) => {
            let error_response = ErrorResponse {
                error: "Health check failed".to_string(),
                message: err,
            };
            let response = warp::reply::json(&error_response);
            Ok(reply::with_status(response, StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}

/// [ASSIGN USER EXTENSION] Assign extension number to user
/// @MISSION Create user extension mapping for roaming access.
/// @THREAT Extension conflicts, unauthorized assignment.
/// @COUNTERMEASURE Validation and uniqueness checks.
/// @AUDIT Extension assignments are logged.
#[utoipa::path(
    post,
    path = "/api/v1/voip/extensions",
    request_body = AssignExtensionRequest,
    responses(
        (status = 201, description = "Extension assigned successfully", body = UserExtension),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 409, description = "Extension already assigned", body = ErrorResponse)
    )
)]
pub async fn assign_user_extension(
    voip_service: Arc<VoipService>,
    user_id: String,
    req: AssignExtensionRequest,
) -> Result<impl Reply, warp::Rejection> {
    match voip_service.assign_user_extension(&user_id, &req.extension, req.display_name).await {
        Ok(extension) => {
            let response = warp::reply::json(&extension);
            Ok(reply::with_status(response, StatusCode::CREATED))
        }
        Err(err) => {
            let status = if err.contains("already assigned") {
                StatusCode::CONFLICT
            } else {
                StatusCode::BAD_REQUEST
            };
            let error_response = ErrorResponse {
                error: "Extension assignment failed".to_string(),
                message: err,
            };
            let response = warp::reply::json(&error_response);
            Ok(warp::reply::with_status(response, status))
        }
    }
}

/// [GET USER EXTENSION] Retrieve user's extension information
/// @MISSION Get current extension assignment for user.
#[utoipa::path(
    get,
    path = "/api/v1/voip/extensions",
    responses(
        (status = 200, description = "Extension retrieved", body = UserExtension),
        (status = 404, description = "No extension assigned", body = ErrorResponse)
    )
)]
pub async fn get_user_extension(
    voip_service: Arc<VoipService>,
    user_id: String,
) -> Result<impl Reply, warp::Rejection> {
    match voip_service.get_user_extension(&user_id).await {
        Some(extension) => {
            let response = warp::reply::json(&extension);
            Ok(reply::with_status(response, StatusCode::OK))
        }
        None => {
            let error_response = ErrorResponse {
                error: "No extension assigned".to_string(),
                message: "User has no assigned extension".to_string(),
            };
            let response = warp::reply::json(&error_response);
            Ok(reply::with_status(response, StatusCode::NOT_FOUND))
        }
    }
}

/// [GET EXTENSIONS BY COUNTRY] Get all extensions for a specific country
/// @MISSION Administrative function to list extensions by country.
/// @THREAT Information disclosure.
/// @COUNTERMEASURE Admin-only access.
#[utoipa::path(
    get,
    path = "/api/v1/voip/extensions/country/{country_code}",
    params(
        ("country_code" = String, Path, description = "Country code (e.g., '32' for Belgium)")
    ),
    responses(
        (status = 200, description = "Extensions retrieved", body = Vec<UserExtension>),
        (status = 400, description = "Invalid country code", body = ErrorResponse)
    )
)]
pub async fn get_extensions_by_country(
    voip_service: Arc<VoipService>,
    country_code: String,
) -> Result<impl Reply, warp::Rejection> {
    // Validate country code exists
    if !crate::services::voip_service::COUNTRY_CODES.iter().any(|(code, _)| *code == country_code) {
        let error_response = ErrorResponse {
            error: "Invalid country code".to_string(),
            message: format!("Country code '{}' is not valid", country_code),
        };
        let response = warp::reply::json(&error_response);
        return Ok(reply::with_status(response, StatusCode::BAD_REQUEST));
    }

    let extensions = voip_service.get_extensions_by_country(&country_code).await;
    let response = warp::reply::json(&extensions);
    Ok(reply::with_status(response, StatusCode::OK))
}

/// [GET ALL EXTENSIONS WITH COUNTRY INFO] Get all extensions with country information
/// @MISSION Administrative function to list all extensions with country details.
/// @THREAT Information disclosure.
/// @COUNTERMEASURE Admin-only access.
#[utoipa::path(
    get,
    path = "/api/v1/voip/extensions/with-country-info",
    responses(
        (status = 200, description = "Extensions retrieved", body = Vec<ExtensionWithCountryInfo>)
    )
)]
pub async fn get_all_extensions_with_country_info(
    voip_service: Arc<VoipService>,
) -> Result<impl Reply, warp::Rejection> {
    let extensions_with_info = voip_service.get_all_extensions_with_country_info().await;
    let response_data: Vec<ExtensionWithCountryInfo> = extensions_with_info
        .into_iter()
        .map(|(ext, country_code, country_name)| ExtensionWithCountryInfo {
            user_id: ext.user_id,
            extension: ext.extension,
            display_name: ext.display_name,
            created_at: ext.created_at,
            enabled: ext.enabled,
            country_code,
            country_name,
        })
        .collect();

    let response = warp::reply::json(&response_data);
    Ok(reply::with_status(response, StatusCode::OK))
}

/// [GET COUNTRY CODES] Get list of supported country codes
/// @MISSION Provide list of valid country codes for UI/client validation.
#[utoipa::path(
    get,
    path = "/api/v1/voip/country-codes",
    responses(
        (status = 200, description = "Country codes retrieved", body = Vec<(String, String)>)
    )
)]
pub async fn get_country_codes() -> Result<impl Reply, warp::Rejection> {
    let country_codes: Vec<(String, String)> = crate::services::voip_service::COUNTRY_CODES
        .iter()
        .map(|(code, name)| (code.to_string(), name.to_string()))
        .collect();

    let response = warp::reply::json(&country_codes);
    Ok(reply::with_status(response, StatusCode::OK))
}

/// [PARSE EXTENSION STRUCTURE] Parse and analyze extension structure
/// @MISSION Provide detailed breakdown of extension components for validation/debugging.
#[utoipa::path(
    get,
    path = "/api/v1/voip/extensions/parse/{extension}",
    params(
        ("extension" = String, Path, description = "Extension to parse (e.g., '32-001-00-00-00')")
    ),
    responses(
        (status = 200, description = "Extension structure parsed", body = ExtensionStructureInfo),
        (status = 400, description = "Invalid extension format", body = ErrorResponse)
    )
)]
pub async fn parse_extension_structure(
    extension: String,
) -> Result<impl Reply, warp::Rejection> {
    // Validate the extension format first
    if !crate::services::voip_service::validate_extension_format(&extension) {
        let error_response = ErrorResponse {
            error: "Invalid extension format".to_string(),
            message: format!("Extension '{}' does not follow the expected format", extension),
        };
        let response = warp::reply::json(&error_response);
        return Ok(reply::with_status(response, StatusCode::BAD_REQUEST));
    }

    let structure = crate::services::voip_service::parse_extension_structure(&extension);
    let response_data = ExtensionStructureInfo {
        country_code: structure.country_code,
        country_name: structure.country_name,
        local_extension: structure.local_extension,
        full_extension: structure.full_extension,
        parts: structure.parts,
    };

    let response = warp::reply::json(&response_data);
    Ok(reply::with_status(response, StatusCode::OK))
}

/// [REGISTER FEDERATED OFFICE] Register a new office in the federation
/// @MISSION Add a new federated office with its Asterisk configuration.
/// @THREAT Unauthorized office registration.
/// @COUNTERMEASURE Admin authentication, validation.
#[utoipa::path(
    post,
    path = "/api/v1/voip/federation/offices",
    request_body = RegisterOfficeRequest,
    responses(
        (status = 201, description = "Office registered successfully", body = FederatedOffice),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 409, description = "Office prefix already exists", body = ErrorResponse)
    )
)]
pub async fn register_federated_office(
    voip_service: Arc<VoipService>,
    req: RegisterOfficeRequest,
) -> Result<impl Reply, warp::Rejection> {
    match voip_service.register_federated_office(
        &req.name,
        &req.location,
        &req.office_prefix,
        req.asterisk_config,
    ).await {
        Ok(office) => {
            let response = warp::reply::json(&office);
            Ok(reply::with_status(response, StatusCode::CREATED))
        }
        Err(err) => {
            let status = if err.contains("already exists") {
                StatusCode::CONFLICT
            } else {
                StatusCode::BAD_REQUEST
            };
            let error_response = ErrorResponse {
                error: "Office registration failed".to_string(),
                message: err,
            };
            let response = warp::reply::json(&error_response);
            Ok(warp::reply::with_status(response, status))
        }
    }
}

/// [GET FEDERATED OFFICES] List all federated offices
/// @MISSION Provide administrative view of federation offices.
/// @THREAT Information disclosure.
/// @COUNTERMEASURE Admin access control.
#[utoipa::path(
    get,
    path = "/api/v1/voip/federation/offices",
    responses(
        (status = 200, description = "Offices retrieved", body = Vec<FederatedOffice>)
    )
)]
pub async fn get_federated_offices(
    voip_service: Arc<VoipService>,
) -> Result<impl Reply, warp::Rejection> {
    let offices = voip_service.get_federated_offices().await;
    let response = warp::reply::json(&offices);
    Ok(reply::with_status(response, StatusCode::OK))
}

/// [CREATE FEDERATION LINK] Create secure link between offices
/// @MISSION Establish VoIP trunk between federated offices.
/// @THREAT Link configuration errors.
/// @COUNTERMEASURE Validation, admin access.
#[utoipa::path(
    post,
    path = "/api/v1/voip/federation/links",
    request_body = CreateFederationLinkRequest,
    responses(
        (status = 201, description = "Link created successfully", body = FederationLink),
        (status = 400, description = "Invalid request", body = ErrorResponse)
    )
)]
pub async fn create_federation_link(
    voip_service: Arc<VoipService>,
    req: CreateFederationLinkRequest,
) -> Result<impl Reply, warp::Rejection> {
    match voip_service.create_federation_link(
        &req.source_office_id,
        &req.target_office_id,
        req.link_type,
        req.priority,
    ).await {
        Ok(link) => {
            let response = warp::reply::json(&link);
            Ok(reply::with_status(response, StatusCode::CREATED))
        }
        Err(err) => {
            let error_response = ErrorResponse {
                error: "Link creation failed".to_string(),
                message: err,
            };
            let response = warp::reply::json(&error_response);
            Ok(reply::with_status(response, StatusCode::BAD_REQUEST))
        }
    }
}

/// [GET FEDERATION LINKS] List all federation links
/// @MISSION Provide view of inter-office connections.
/// @THREAT Information disclosure.
/// @COUNTERMEASURE Admin access control.
#[utoipa::path(
    get,
    path = "/api/v1/voip/federation/links",
    responses(
        (status = 200, description = "Links retrieved", body = Vec<FederationLink>)
    )
)]
pub async fn get_federation_links(
    voip_service: Arc<VoipService>,
) -> Result<impl Reply, warp::Rejection> {
    let links = voip_service.get_federation_links().await;
    let response = warp::reply::json(&links);
    Ok(reply::with_status(response, StatusCode::OK))
}

/// [CREATE FEDERATION ROUTE] Define routing rule for inter-office calls
/// @MISSION Set up call routing between federated offices.
/// @THREAT Routing configuration errors.
/// @COUNTERMEASURE Validation, admin access.
#[utoipa::path(
    post,
    path = "/api/v1/voip/federation/routes",
    request_body = CreateFederationRouteRequest,
    responses(
        (status = 201, description = "Route created successfully", body = FederationRoute),
        (status = 400, description = "Invalid request", body = ErrorResponse)
    )
)]
pub async fn create_federation_route(
    voip_service: Arc<VoipService>,
    req: CreateFederationRouteRequest,
) -> Result<impl Reply, warp::Rejection> {
    match voip_service.create_federation_route(
        &req.source_office_prefix,
        &req.destination_pattern,
        &req.target_office_id,
        req.cost_priority,
    ).await {
        Ok(route) => {
            let response = warp::reply::json(&route);
            Ok(reply::with_status(response, StatusCode::CREATED))
        }
        Err(err) => {
            let error_response = ErrorResponse {
                error: "Route creation failed".to_string(),
                message: err,
            };
            let response = warp::reply::json(&error_response);
            Ok(reply::with_status(response, StatusCode::BAD_REQUEST))
        }
    }
}

/// [REGISTER DEVICE] Register a new VoIP device for user
/// @MISSION Allow users to register multiple VoIP endpoints.
/// @THREAT Device spoofing, unauthorized registration.
/// @COUNTERMEASURE User validation and device verification.
#[utoipa::path(
    post,
    path = "/api/v1/voip/devices",
    request_body = RegisterDeviceRequest,
    responses(
        (status = 201, description = "Device registered successfully", body = DeviceRegistration),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 409, description = "Device name already exists", body = ErrorResponse)
    )
)]
pub async fn register_device(
    voip_service: Arc<VoipService>,
    user_id: String,
    req: RegisterDeviceRequest,
) -> Result<impl Reply, warp::Rejection> {
    let endpoint_type = match req.endpoint_type.as_str() {
        "sip" => EndpointType::Sip,
        "webrtc" => EndpointType::Webrtc,
        "mobile" => EndpointType::Mobile,
        "desktop" => EndpointType::Desktop,
        _ => {
            let error_response = ErrorResponse {
                error: "Invalid endpoint type".to_string(),
                message: "Supported types: sip, webrtc, mobile, desktop".to_string(),
            };
            let response = warp::reply::json(&error_response);
            return Ok(reply::with_status(response, StatusCode::BAD_REQUEST));
        }
    };

    match voip_service.register_device(&user_id, &req.device_name, endpoint_type, &req.endpoint_uri).await {
        Ok(device) => {
            let response = warp::reply::json(&device);
            Ok(reply::with_status(response, StatusCode::CREATED))
        }
        Err(err) => {
            let status = if err.to_string().contains("already exists") {
                StatusCode::CONFLICT
            } else {
                StatusCode::BAD_REQUEST
            };
            let error_response = ErrorResponse {
                error: "Device registration failed".to_string(),
                message: err,
            };
            let response = warp::reply::json(&error_response);
            Ok(reply::with_status(response, StatusCode::BAD_REQUEST))
        }
    }
}

/// [GET USER DEVICES] List all registered devices for user
/// @MISSION Retrieve user's VoIP device registrations.
#[utoipa::path(
    get,
    path = "/api/v1/voip/devices",
    responses(
        (status = 200, description = "Devices retrieved", body = Vec<DeviceRegistration>)
    )
)]
pub async fn get_user_devices(
    voip_service: Arc<VoipService>,
    user_id: String,
) -> Result<impl Reply, warp::Rejection> {
    let devices = voip_service.get_user_devices(&user_id).await;
    let response = warp::reply::json(&devices);
    Ok(reply::with_status(response, StatusCode::OK))
}

/// [UPDATE DEVICE PRESENCE] Update device online status
/// @MISSION Track device connectivity for call routing.
#[utoipa::path(
    put,
    path = "/api/v1/voip/devices/{device_id}/presence",
    responses(
        (status = 200, description = "Presence updated"),
        (status = 404, description = "Device not found", body = ErrorResponse)
    )
)]
pub async fn update_device_presence(
    voip_service: Arc<VoipService>,
    user_id: String,
    device_id: String,
    is_online: bool,
) -> Result<impl Reply, warp::Rejection> {
    match voip_service.update_device_presence(&user_id, &device_id, is_online).await {
        Ok(()) => Ok(reply::with_status("Presence updated", StatusCode::OK)),
        Err(err) => {
            let error_response = ErrorResponse {
                error: "Presence update failed".to_string(),
                message: err,
            };
            let response = warp::reply::json(&error_response);
            Ok(reply::with_status(response, StatusCode::NOT_FOUND))
        }
    }
}

/// [UPDATE PRESENCE STATUS] Set user presence status
/// @MISSION Update user's availability for presence information.
#[utoipa::path(
    put,
    path = "/api/v1/voip/presence",
    request_body = UpdatePresenceRequest,
    responses(
        (status = 200, description = "Presence updated"),
        (status = 400, description = "Invalid status", body = ErrorResponse)
    )
)]
pub async fn update_presence_status(
    voip_service: Arc<VoipService>,
    user_id: String,
    req: UpdatePresenceRequest,
) -> Result<impl Reply, warp::Rejection> {
    let status = match req.status.as_str() {
        "online" => PresenceState::Online,
        "away" => PresenceState::Away,
        "busy" => PresenceState::Busy,
        "offline" => PresenceState::Offline,
        "do_not_disturb" => PresenceState::DoNotDisturb,
        _ => {
            let error_response = ErrorResponse {
                error: "Invalid presence status".to_string(),
                message: "Supported statuses: online, away, busy, offline, do_not_disturb".to_string(),
            };
            let response = warp::reply::json(&error_response);
            return Ok(reply::with_status(response, StatusCode::BAD_REQUEST));
        }
    };

    match voip_service.update_presence_status(&user_id, status, req.status_message, req.current_device).await {
        Ok(()) => Ok(reply::with_status("Presence updated", StatusCode::OK)),
        Err(err) => {
            let error_response = ErrorResponse {
                error: "Presence update failed".to_string(),
                message: err,
            };
            let response = warp::reply::json(&error_response);
            Ok(reply::with_status(response, StatusCode::BAD_REQUEST))
        }
    }
}

/// [GET PRESENCE STATUS] Get user's presence information
/// @MISSION Retrieve current presence status.
#[utoipa::path(
    get,
    path = "/api/v1/voip/presence",
    responses(
        (status = 200, description = "Presence retrieved", body = PresenceStatus),
        (status = 404, description = "No presence set", body = ErrorResponse)
    )
)]
pub async fn get_presence_status(
    voip_service: Arc<VoipService>,
    user_id: String,
) -> Result<impl Reply, warp::Rejection> {
    match voip_service.get_presence_status(&user_id).await {
        Some(presence) => {
            let response = warp::reply::json(&presence);
            Ok(reply::with_status(response, StatusCode::OK))
        }
        None => {
            let error_response = ErrorResponse {
                error: "No presence set".to_string(),
                message: "User has not set presence status".to_string(),
            };
            let response = warp::reply::json(&error_response);
            Ok(reply::with_status(response, StatusCode::NOT_FOUND))
        }
    }
}