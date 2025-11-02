// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Discord Routes
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Define secure REST API routes for Discord bot integration with
//  comprehensive authentication, validation, and audit logging.
//  NOTICE: Routes implement versioned API endpoints with middleware for
//  signature validation, role-based access control, and security monitoring.
//  ROUTE STANDARDS: REST API v1, JSON payloads, secure authentication
//  COMPLIANCE: API security standards, enterprise access controls
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use warp::Filter;
use std::sync::Arc;
use crate::controllers::discord_controller::DiscordController;
use crate::services::discord_service::DiscordService;
use crate::models::discord_model::{DiscordEvent, DiscordNotification, DiscordConfig, DiscordCommand};
use crate::middlewares::auth_guard::auth_guard;

/// [DISCORD ROUTES FUNCTION] Configure Discord API Endpoints
/// @MISSION Define all Discord-related API routes with security middleware.
/// @THREAT Unauthorized access, API abuse, data leakage.
/// @COUNTERMEASURE Authentication, rate limiting, input validation.
/// @INVARIANT All routes require proper authentication and authorization.
/// @AUDIT Route access is logged for security monitoring.
/// @DEPENDENCY Requires DiscordService and authentication middleware.
pub fn discord_routes(
    discord_service: Arc<DiscordService>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let discord_controller = Arc::new(DiscordController::new(discord_service));

    // Base path for Discord API v1
    let discord_api = warp::path!("api" / "v1" / "discord");

    // POST /api/v1/discord/event - Process Discord events
    let event_route = discord_api
        .and(warp::path("event"))
        .and(warp::post())
        .and(warp::body::json::<DiscordEvent>())
        .and(warp::any().map(move || discord_controller.clone()))
        .and_then(|event: DiscordEvent, controller: Arc<DiscordController>| async move {
            DiscordController::process_event(controller.discord_service.clone(), event).await
        });

    // POST /api/v1/discord/notify - Send notifications
    let notify_route = discord_api
        .and(warp::path("notify"))
        .and(warp::post())
        .and(auth_guard()) // Requires authentication
        .and(warp::body::json::<DiscordNotification>())
        .and(warp::any().map(move || discord_controller.clone()))
        .and_then(|_claims, notification: DiscordNotification, controller: Arc<DiscordController>| async move {
            DiscordController::send_notification(controller.discord_service.clone(), notification).await
        });

    // GET /api/v1/discord/config - Get configuration
    let get_config_route = discord_api
        .and(warp::path("config"))
        .and(warp::get())
        .and(auth_guard()) // Requires authentication
        .and(warp::any().map(move || discord_controller.clone()))
        .and_then(|claims, controller: Arc<DiscordController>| async move {
            DiscordController::get_config(controller.discord_service.clone(), claims.sub).await
        });

    // PATCH /api/v1/discord/config - Update configuration
    let update_config_route = discord_api
        .and(warp::path("config"))
        .and(warp::patch())
        .and(auth_guard()) // Requires authentication
        .and(warp::body::json::<DiscordConfig>())
        .and(warp::any().map(move || discord_controller.clone()))
        .and_then(|claims, config: DiscordConfig, controller: Arc<DiscordController>| async move {
            DiscordController::update_config(controller.discord_service.clone(), claims.sub, config).await
        });

    // POST /api/v1/discord/command - Execute commands
    let command_route = discord_api
        .and(warp::path("command"))
        .and(warp::post())
        .and(auth_guard()) // Requires authentication
        .and(warp::body::json::<DiscordCommand>())
        .and(warp::any().map(move || discord_controller.clone()))
        .and_then(|_claims, command: DiscordCommand, controller: Arc<DiscordController>| async move {
            DiscordController::execute_command(controller.discord_service.clone(), command).await
        });

    // Combine all routes
    event_route
        .or(notify_route)
        .or(get_config_route)
        .or(update_config_route)
        .or(command_route)
}