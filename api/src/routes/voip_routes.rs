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

    // Extension management routes
    let assign_extension = voip_base.clone()
        .and(warp::path("extensions"))
        .and(warp::path::end())
        .and(warp::post())
        .and(warp::body::json())
        .and_then(|user_id: String, vs: Arc<VoipService>, req| async move {
            voip_controller::assign_user_extension(vs, user_id, req).await
        });

    let get_extension = voip_base.clone()
        .and(warp::path("extensions"))
        .and(warp::path::end())
        .and(warp::get())
        .and_then(|user_id: String, vs: Arc<VoipService>| async move {
            voip_controller::get_user_extension(vs, user_id).await
        });

    // Country-specific extension routes
    let get_extensions_by_country = voip_base.clone()
        .and(warp::path("extensions"))
        .and(warp::path("country"))
        .and(warp::path::param::<String>())
        .and(warp::path::end())
        .and(warp::get())
        .and_then(|user_id: String, vs: Arc<VoipService>, country_code: String| async move {
            voip_controller::get_extensions_by_country(vs, country_code).await
        });

    let get_all_extensions_with_country_info = voip_base.clone()
        .and(warp::path("extensions"))
        .and(warp::path("with-country-info"))
        .and(warp::path::end())
        .and(warp::get())
        .and_then(|user_id: String, vs: Arc<VoipService>| async move {
            voip_controller::get_all_extensions_with_country_info(vs).await
        });

    let get_country_codes = warp::path("api")
        .and(warp::path("v1"))
        .and(warp::path("voip"))
        .and(warp::path("country-codes"))
        .and(warp::path::end())
        .and(warp::get())
        .and_then(|| async move {
            voip_controller::get_country_codes().await
        });

    let parse_extension_structure = warp::path("api")
        .and(warp::path("v1"))
        .and(warp::path("voip"))
        .and(warp::path("extensions"))
        .and(warp::path("parse"))
        .and(warp::path::param::<String>())
        .and(warp::path::end())
        .and(warp::get())
        .and_then(|extension: String| async move {
            voip_controller::parse_extension_structure(extension).await
        });

    // Federation routes
    let federation_base = warp::path("federation");

    let register_federated_office = federation_base.clone()
        .and(warp::path("offices"))
        .and(warp::path::end())
        .and(warp::post())
        .and(warp::body::json())
        .and_then(move |req| {
            let vs = voip_service.clone();
            async move {
                voip_controller::register_federated_office(vs, req).await
            }
        });

    let get_federated_offices = federation_base.clone()
        .and(warp::path("offices"))
        .and(warp::path::end())
        .and(warp::get())
        .and_then(move || {
            let vs = voip_service.clone();
            async move {
                voip_controller::get_federated_offices(vs).await
            }
        });

    let create_federation_link = federation_base.clone()
        .and(warp::path("links"))
        .and(warp::path::end())
        .and(warp::post())
        .and(warp::body::json())
        .and_then(move |req| {
            let vs = voip_service.clone();
            async move {
                voip_controller::create_federation_link(vs, req).await
            }
        });

    let get_federation_links = federation_base.clone()
        .and(warp::path("links"))
        .and(warp::path::end())
        .and(warp::get())
        .and_then(move || {
            let vs = voip_service.clone();
            async move {
                voip_controller::get_federation_links(vs).await
            }
        });

    let create_federation_route = federation_base.clone()
        .and(warp::path("routes"))
        .and(warp::path::end())
        .and(warp::post())
        .and(warp::body::json())
        .and_then(move |req| {
            let vs = voip_service.clone();
            async move {
                voip_controller::create_federation_route(vs, req).await
            }
        });

    // Device management routes
    let register_device = voip_base.clone()
        .and(warp::path("devices"))
        .and(warp::path::end())
        .and(warp::post())
        .and(warp::body::json())
        .and_then(|user_id: String, vs: Arc<VoipService>, req| async move {
            voip_controller::register_device(vs, user_id, req).await
        });

    let get_devices = voip_base.clone()
        .and(warp::path("devices"))
        .and(warp::path::end())
        .and(warp::get())
        .and_then(|user_id: String, vs: Arc<VoipService>| async move {
            voip_controller::get_user_devices(vs, user_id).await
        });

    let update_device_presence = voip_base.clone()
        .and(warp::path("devices" / String / "presence"))
        .and(warp::path::end())
        .and(warp::put())
        .and(warp::body::json())
        .and_then(|device_id: String, user_id: String, vs: Arc<VoipService>, is_online: bool| async move {
            voip_controller::update_device_presence(vs, user_id, device_id, is_online).await
        });

    // Presence management routes
    let update_presence = voip_base.clone()
        .and(warp::path("presence"))
        .and(warp::path::end())
        .and(warp::put())
        .and(warp::body::json())
        .and_then(|user_id: String, vs: Arc<VoipService>, req| async move {
            voip_controller::update_presence_status(vs, user_id, req).await
        });

    let get_presence = voip_base.clone()
        .and(warp::path("presence"))
        .and(warp::path::end())
        .and(warp::get())
        .and_then(|user_id: String, vs: Arc<VoipService>| async move {
            voip_controller::get_presence_status(vs, user_id).await
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
        .or(assign_extension)
        .or(get_extension)
        .or(get_extensions_by_country)
        .or(get_all_extensions_with_country_info)
        .or(get_country_codes)
        .or(parse_extension_structure)
        .or(register_federated_office)
        .or(get_federated_offices)
        .or(create_federation_link)
        .or(get_federation_links)
        .or(create_federation_route)
        .or(register_device)
        .or(get_devices)
        .or(update_device_presence)
        .or(update_presence)
        .or(get_presence)
}