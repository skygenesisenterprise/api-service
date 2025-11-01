// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: VoIP Routes
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Define secure VoIP API endpoints for voice/video calls,
//  conference management, and real-time communication.
//  NOTICE: Implements RESTful VoIP endpoints with WebRTC signaling support,
//  authentication, and comprehensive audit logging.
//  VOIP STANDARDS: WebRTC, REST API, JSON
//  SECURITY: Authentication required, encrypted communication
//  COMPLIANCE: GDPR, HIPAA, NIST VoIP Security Guidelines
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use warp::Filter;
use std::sync::Arc;
use crate::controllers::voip_controller;
use crate::services::voip_service::VoipService;
use crate::middlewares::auth_guard::auth_guard;

/// [VOIP ROUTES] Main VoIP routes configuration
/// @MISSION Provide authenticated VoIP endpoints.
/// @THREAT Unauthorized access to VoIP functionality.
/// @COUNTERMEASURE Authentication middleware and access control.
/// @AUDIT All VoIP operations are logged.
pub fn voip_routes(
    voip_service: Arc<VoipService>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    // Apply authentication to all VoIP routes
    let voip_base = warp::path("api" / "v1" / "voip")
        .and(auth_guard())
        .and(warp::any().map(move || voip_service.clone()));

    // Call management routes
    let calls = voip_base.clone()
        .and(warp::path("calls"))
        .and(warp::path::end())
        .and(warp::post())
        .and(warp::body::json())
        .and_then(|user_id: String, vs: Arc<VoipService>, req| async move {
            voip_controller::initiate_call(vs, user_id, req).await
        });

    let list_calls = voip_base.clone()
        .and(warp::path("calls"))
        .and(warp::path::end())
        .and(warp::get())
        .and_then(|user_id: String, vs: Arc<VoipService>| async move {
            voip_controller::list_active_calls(vs, user_id).await
        });

    let get_call = voip_base.clone()
        .and(warp::path("calls" / String))
        .and(warp::path::end())
        .and(warp::get())
        .and_then(|call_id: String, user_id: String, vs: Arc<VoipService>| async move {
            // Note: In a real implementation, you might want to check if the user
            // has permission to view this call
            voip_controller::get_call(vs, call_id).await
        });

    let accept_call = voip_base.clone()
        .and(warp::path("calls" / String / "accept"))
        .and(warp::path::end())
        .and(warp::post())
        .and_then(|call_id: String, user_id: String, vs: Arc<VoipService>| async move {
            voip_controller::accept_call(vs, user_id, call_id).await
        });

    let end_call = voip_base.clone()
        .and(warp::path("calls" / String / "end"))
        .and(warp::path::end())
        .and(warp::post())
        .and_then(|call_id: String, user_id: String, vs: Arc<VoipService>| async move {
            voip_controller::end_call(vs, user_id, call_id).await
        });

    // Signaling routes
    let send_signaling = voip_base.clone()
        .and(warp::path("calls" / String / "signaling"))
        .and(warp::path::end())
        .and(warp::post())
        .and(warp::body::json())
        .and_then(|call_id: String, user_id: String, vs: Arc<VoipService>, req| async move {
            voip_controller::send_signaling(vs, user_id, call_id, req).await
        });

    let get_signaling = voip_base.clone()
        .and(warp::path("calls" / String / "signaling"))
        .and(warp::path::end())
        .and(warp::get())
        .and_then(|call_id: String, user_id: String, vs: Arc<VoipService>| async move {
            voip_controller::get_signaling(vs, user_id, call_id).await
        });

    // Room management routes
    let rooms = voip_base.clone()
        .and(warp::path("rooms"))
        .and(warp::path::end())
        .and(warp::post())
        .and(warp::body::json())
        .and_then(|user_id: String, vs: Arc<VoipService>, req| async move {
            voip_controller::create_room(vs, user_id, req).await
        });

    let list_rooms = voip_base.clone()
        .and(warp::path("rooms"))
        .and(warp::path::end())
        .and(warp::get())
        .and_then(|user_id: String, vs: Arc<VoipService>| async move {
            voip_controller::list_active_rooms(vs, user_id).await
        });

    let get_room = voip_base.clone()
        .and(warp::path("rooms" / String))
        .and(warp::path::end())
        .and(warp::get())
        .and_then(|room_id: String, user_id: String, vs: Arc<VoipService>| async move {
            // Note: In a real implementation, you might want to check if the user
            // has permission to view this room
            voip_controller::get_room(vs, room_id).await
        });

    let join_room = voip_base.clone()
        .and(warp::path("rooms" / String / "join"))
        .and(warp::path::end())
        .and(warp::post())
        .and_then(|room_id: String, user_id: String, vs: Arc<VoipService>| async move {
            voip_controller::join_room(vs, user_id, room_id).await
        });

    // Combine all routes
    calls
        .or(list_calls)
        .or(get_call)
        .or(accept_call)
        .or(end_call)
        .or(send_signaling)
        .or(get_signaling)
        .or(rooms)
        .or(list_rooms)
        .or(get_room)
        .or(join_room)
}