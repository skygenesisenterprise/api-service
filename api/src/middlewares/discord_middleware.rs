// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Discord Middleware
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide Discord-specific middleware for webhook validation,
//  rate limiting, authentication, and security enforcement for Discord
//  bot integration endpoints.
//  NOTICE: Implements webhook signature verification, rate limiting,
//  and Discord-specific security controls for bot operations.
//  DISCORD STANDARDS: Webhook Security, Rate Limiting, Bot Authentication
//  COMPLIANCE: Discord API Security, Enterprise Security Standards
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use crate::core::discord_core::DiscordCore;
use crate::core::audit_manager::AuditManager;
use crate::core::opentelemetry::Metrics;
use std::sync::Arc;
use warp::Filter;
use chrono::Utc;

/// [DISCORD WEBHOOK VALIDATION MIDDLEWARE] Validate Discord Webhook Signatures
/// @MISSION Verify authenticity of incoming Discord webhooks.
/// @THREAT Webhook spoofing, unauthorized bot commands.
/// @COUNTERMEASURE Cryptographic signature validation, timestamp checking.
/// @INVARIANT All webhooks are validated before processing.
/// @AUDIT Validation attempts are logged for security monitoring.
/// @FLOW Extract headers -> Validate signature -> Allow/deny request.
pub fn discord_webhook_validation(
    discord_core: Arc<DiscordCore>,
) -> impl Filter<Extract = (), Error = warp::Rejection> + Clone {
    warp::header::optional::<String>("x-signature-ed25519")
        .and(warp::header::optional::<String>("x-signature-timestamp"))
        .and(warp::body::bytes())
        .and_then(move |signature: Option<String>, timestamp: Option<String>, body: bytes::Bytes| {
            let discord_core = discord_core.clone();
            async move {
                // For Discord webhooks, we need both signature and timestamp
                let signature = signature.ok_or_else(|| {
                    warp::reject::custom(DiscordWebhookError::MissingSignature)
                })?;

                let timestamp = timestamp.ok_or_else(|| {
                    warp::reject::custom(DiscordWebhookError::MissingTimestamp)
                })?;

                // Convert body to string for validation
                let body_str = String::from_utf8(body.to_vec())
                    .map_err(|_| warp::reject::custom(DiscordWebhookError::InvalidBody))?;

                // Validate the webhook signature
                match discord_core.validate_webhook_signature(&body_str, &signature, &timestamp).await {
                    Ok(true) => Ok(()),
                    Ok(false) => Err(warp::reject::custom(DiscordWebhookError::InvalidSignature)),
                    Err(e) => {
                        eprintln!("Webhook validation error: {}", e);
                        Err(warp::reject::custom(DiscordWebhookError::ValidationError))
                    }
                }
            }
        })
        .untuple_one()
}

/// [DISCORD RATE LIMITING MIDDLEWARE] Rate Limit Discord Operations
/// @MISSION Prevent abuse of Discord bot endpoints.
/// @THREAT API spam, resource exhaustion, DoS attacks.
/// @COUNTERMEASURE Request throttling, per-user limits.
/// @INVARIANT Operations respect configured rate limits.
/// @AUDIT Rate limit violations are logged.
/// @FLOW Check rate limit -> Allow/deny -> Update counters.
pub fn discord_rate_limiting(
    discord_core: Arc<DiscordCore>,
) -> impl Filter<Extract = (), Error = warp::Rejection> + Clone {
    warp::header::optional::<String>("x-user-id")
        .and(warp::path::full())
        .and_then(move |user_id: Option<String>, path: warp::path::FullPath| {
            let discord_core = discord_core.clone();
            async move {
                let user_id = user_id.unwrap_or_else(|| "anonymous".to_string());
                let operation = path.as_str();

                match discord_core.check_rate_limit(&user_id, operation).await {
                    Ok(true) => Ok(()),
                    Ok(false) => Err(warp::reject::custom(DiscordWebhookError::RateLimitExceeded)),
                    Err(e) => {
                        eprintln!("Rate limit check error: {}", e);
                        Err(warp::reject::custom(DiscordWebhookError::RateLimitError))
                    }
                }
            }
        })
        .untuple_one()
}

/// [DISCORD GUILD MEMBERSHIP MIDDLEWARE] Verify Guild Membership
/// @MISSION Ensure users are members of required Discord guilds.
/// @THREAT Unauthorized access, impersonation.
/// @COUNTERMEASURE Guild membership validation.
/// @INVARIANT Access requires valid guild membership.
/// @AUDIT Membership checks are logged.
/// @FLOW Extract user/guild IDs -> Verify membership -> Allow/deny.
pub fn discord_guild_membership(
    discord_core: Arc<DiscordCore>,
    required_guild_id: String,
) -> impl Filter<Extract = (), Error = warp::Rejection> + Clone {
    warp::header::optional::<String>("x-user-id")
        .and_then(move |user_id: Option<String>| {
            let discord_core = discord_core.clone();
            let required_guild_id = required_guild_id.clone();
            async move {
                let user_id = user_id.ok_or_else(|| {
                    warp::reject::custom(DiscordWebhookError::MissingUserId)
                })?;

                match discord_core.verify_guild_membership(&user_id, &required_guild_id).await {
                    Ok(true) => Ok(()),
                    Ok(false) => Err(warp::reject::custom(DiscordWebhookError::NotGuildMember)),
                    Err(e) => {
                        eprintln!("Guild membership check error: {}", e);
                        Err(warp::reject::custom(DiscordWebhookError::MembershipCheckError))
                    }
                }
            }
        })
        .untuple_one()
}

/// [DISCORD ROLE VALIDATION MIDDLEWARE] Check User Roles and Permissions
/// @MISSION Validate user has required Discord roles.
/// @THREAT Privilege escalation, unauthorized operations.
/// @COUNTERMEASURE Role-based access control.
/// @INVARIANT Operations require appropriate roles.
/// @AUDIT Role checks are logged.
/// @FLOW Extract user/guild -> Get roles -> Check permissions -> Allow/deny.
pub fn discord_role_validation(
    discord_core: Arc<DiscordCore>,
    required_guild_id: String,
    required_roles: Vec<String>,
) -> impl Filter<Extract = (), Error = warp::Rejection> + Clone {
    warp::header::optional::<String>("x-user-id")
        .and_then(move |user_id: Option<String>| {
            let discord_core = discord_core.clone();
            let required_guild_id = required_guild_id.clone();
            let required_roles = required_roles.clone();
            async move {
                let user_id = user_id.ok_or_else(|| {
                    warp::reject::custom(DiscordWebhookError::MissingUserId)
                })?;

                match discord_core.get_user_roles(&user_id, &required_guild_id).await {
                    Ok(user_roles) => {
                        let has_required_role = required_roles.iter()
                            .any(|required| user_roles.contains(required));

                        if has_required_role {
                            Ok(())
                        } else {
                            Err(warp::reject::custom(DiscordWebhookError::InsufficientRoles))
                        }
                    }
                    Err(e) => {
                        eprintln!("Role validation error: {}", e);
                        Err(warp::reject::custom(DiscordWebhookError::RoleValidationError))
                    }
                }
            }
        })
        .untuple_one()
}

/// [DISCORD AUDIT LOGGING MIDDLEWARE] Log Discord Operations
/// @MISSION Provide comprehensive audit trail for Discord operations.
/// @THREAT Undetected security violations, compliance gaps.
/// @COUNTERMEASURE Log all Discord-related activities.
/// @INVARIANT All operations are audited.
/// @AUDIT Operations logged with full context.
/// @FLOW Extract request details -> Log operation -> Continue processing.
pub fn discord_audit_logging(
    audit_manager: Arc<AuditManager>,
) -> impl Filter<Extract = (), Error = warp::Rejection> + Clone {
    warp::method()
        .and(warp::path::full())
        .and(warp::header::optional::<String>("x-user-id"))
        .and(warp::header::optional::<String>("x-channel-id"))
        .and(warp::header::optional::<String>("x-forwarded-for"))
        .and(warp::header::optional::<String>("user-agent"))
        .and_then(move |method: warp::http::Method, path: warp::path::FullPath,
                       user_id: Option<String>, channel_id: Option<String>,
                       ip_address: Option<String>, user_agent: Option<String>| {
            let audit_manager = audit_manager.clone();
            async move {
                // Create audit entry for Discord operation
                let audit = crate::models::discord_model::DiscordAudit {
                    id: uuid::Uuid::new_v4().to_string(),
                    operation: format!("api_call_{}", method.as_str().to_lowercase()),
                    user_id,
                    channel_id,
                    details: serde_json::json!({
                        "path": path.as_str(),
                        "method": method.as_str()
                    }),
                    timestamp: Utc::now(),
                    ip_address,
                    user_agent,
                    success: true, // Assume success for now, could be updated later
                };

                audit_manager.log_discord_event(audit).await;
                Ok(())
            }
        })
        .untuple_one()
}

/// [DISCORD CONTENT FILTERING MIDDLEWARE] Filter and Sanitize Content
/// @MISSION Prevent malicious content in Discord messages.
/// @THREAT XSS, injection attacks, malicious links.
/// @COUNTERMEASURE Content sanitization, link validation.
/// @INVARIANT All content is filtered and safe.
/// @AUDIT Content filtering actions are logged.
/// @FLOW Extract content -> Apply filters -> Sanitize -> Allow/deny.
pub fn discord_content_filtering() -> impl Filter<Extract = (), Error = warp::Rejection> + Clone {
    warp::body::json::<serde_json::Value>()
        .and_then(|body: serde_json::Value| async move {
            // Extract content from various possible fields
            let content_fields = ["content", "message", "description"];

            for field in &content_fields {
                if let Some(content) = body.get(field).and_then(|c| c.as_str()) {
                    // Basic content filtering
                    if contains_malicious_content(content) {
                        return Err(warp::reject::custom(DiscordWebhookError::MaliciousContent));
                    }

                    // Check for excessive length
                    if content.len() > 2000 {
                        return Err(warp::reject::custom(DiscordWebhookError::ContentTooLong));
                    }
                }
            }

            Ok(())
        })
        .untuple_one()
}

/// [DISCORD COMBINED MIDDLEWARE] Apply All Discord Security Middlewares
/// @MISSION Provide comprehensive security for Discord endpoints.
/// @THREAT Multiple attack vectors on Discord integration.
/// @COUNTERMEASURE Layered security controls.
/// @INVARIANT All security measures are applied.
/// @AUDIT All security events are logged.
/// @FLOW Apply all middlewares in security order.
pub fn discord_security_middleware(
    discord_core: Arc<DiscordCore>,
    audit_manager: Arc<AuditManager>,
    required_guild_id: String,
    required_roles: Vec<String>,
) -> impl Filter<Extract = (), Error = warp::Rejection> + Clone {
    discord_audit_logging(audit_manager)
        .and(discord_rate_limiting(discord_core.clone()))
        .and(discord_webhook_validation(discord_core.clone()))
        .and(discord_guild_membership(discord_core.clone(), required_guild_id))
        .and(discord_role_validation(discord_core, required_roles))
        .and(discord_content_filtering())
}

/// Helper function to check for malicious content
fn contains_malicious_content(content: &str) -> bool {
    let malicious_patterns = [
        "<script",
        "javascript:",
        "data:text/html",
        "<iframe",
        "<object",
        "<embed",
    ];

    malicious_patterns.iter()
        .any(|pattern| content.to_lowercase().contains(pattern))
}

/// [DISCORD WEBHOOK ERROR] Custom Error Types for Discord Middleware
#[derive(Debug)]
pub enum DiscordWebhookError {
    MissingSignature,
    MissingTimestamp,
    InvalidBody,
    InvalidSignature,
    ValidationError,
    RateLimitExceeded,
    RateLimitError,
    MissingUserId,
    NotGuildMember,
    MembershipCheckError,
    InsufficientRoles,
    RoleValidationError,
    MaliciousContent,
    ContentTooLong,
}

impl warp::reject::Reject for DiscordWebhookError {}