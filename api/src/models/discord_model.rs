// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Discord Model
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Define Discord bot integration data structures for secure
//  communication with internal services and command execution.
//  NOTICE: Discord models implement secure event handling, command validation,
//  and audit logging for bot operations with enterprise security standards.
//  DISCORD STANDARDS: Event Processing, Command Security, Audit Trails
//  COMPLIANCE: Data Protection, API Security, Audit Standards
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// [DISCORD EVENT STRUCT] Incoming Discord Event Model
/// @MISSION Define structure for Discord events (slash commands, messages, reactions).
/// @THREAT Event spoofing, unauthorized commands, data injection.
/// @COUNTERMEASURE Signature validation, role verification, input sanitization.
/// @INVARIANT Events are validated and authenticated before processing.
/// @AUDIT All events are logged with user and action details.
#[derive(Debug, Serialize, Deserialize, Clone, utoipa::ToSchema)]
pub struct DiscordEvent {
    pub event_type: String, // "slash_command", "message", "reaction"
    pub user_id: String,
    pub channel_id: String,
    pub guild_id: Option<String>,
    pub content: Option<String>,
    pub command: Option<String>,
    pub args: Option<Vec<String>>,
    pub timestamp: DateTime<Utc>,
    pub signature: String, // For webhook signature validation
}

/// [DISCORD NOTIFICATION STRUCT] Outgoing Notification Model
/// @MISSION Define structure for sending notifications to Discord channels.
/// @THREAT Unauthorized notifications, information leakage.
/// @COUNTERMEASURE Permission validation, content filtering, audit logging.
/// @INVARIANT Notifications are sent only to authorized channels.
/// @AUDIT Notification sends are logged with content and recipient details.
#[derive(Debug, Serialize, Deserialize, Clone, utoipa::ToSchema)]
pub struct DiscordNotification {
    pub channel_id: String,
    pub message: String,
    pub embed: Option<DiscordEmbed>,
    pub urgent: bool,
    pub service: String, // "mail", "search", "vault", "vpn", etc.
}

/// [DISCORD EMBED STRUCT] Rich Message Embed Model
#[derive(Debug, Serialize, Deserialize, Clone, utoipa::ToSchema)]
pub struct DiscordEmbed {
    pub title: Option<String>,
    pub description: Option<String>,
    pub color: Option<u32>,
    pub fields: Option<Vec<EmbedField>>,
    pub timestamp: Option<DateTime<Utc>>,
}

/// [EMBED FIELD STRUCT] Embed Field Model
#[derive(Debug, Serialize, Deserialize, Clone, utoipa::ToSchema)]
pub struct EmbedField {
    pub name: String,
    pub value: String,
    pub inline: Option<bool>,
}

/// [DISCORD CONFIG STRUCT] Bot Configuration Model
/// @MISSION Define Discord bot configuration settings.
/// @THREAT Configuration tampering, unauthorized changes.
/// @COUNTERMEASURE Access control, validation, audit logging.
/// @INVARIANT Configuration changes require proper authorization.
/// @AUDIT Configuration modifications are logged.
#[derive(Debug, Serialize, Deserialize, Clone, utoipa::ToSchema)]
pub struct DiscordConfig {
    pub channels: Vec<ChannelConfig>,
    pub roles: Vec<RoleConfig>,
    pub permissions: Vec<PermissionConfig>,
    pub commands: Vec<CommandConfig>,
    pub webhooks: Vec<WebhookConfig>,
    pub vpn_required: bool,
    pub audit_enabled: bool,
}

/// [CHANNEL CONFIG STRUCT] Channel Configuration
#[derive(Debug, Serialize, Deserialize, Clone, utoipa::ToSchema)]
pub struct ChannelConfig {
    pub id: String,
    pub name: String,
    pub purpose: String, // "notifications", "commands", "logs", "admin"
    pub permissions: Vec<String>,
}

/// [ROLE CONFIG STRUCT] Role Configuration
#[derive(Debug, Serialize, Deserialize, Clone, utoipa::ToSchema)]
pub struct RoleConfig {
    pub id: String,
    pub name: String,
    pub permissions: Vec<String>,
    pub vpn_access: bool,
}

/// [PERMISSION CONFIG STRUCT] Permission Configuration
#[derive(Debug, Serialize, Deserialize, Clone, utoipa::ToSchema)]
pub struct PermissionConfig {
    pub name: String,
    pub description: String,
    pub roles: Vec<String>,
}

/// [COMMAND CONFIG STRUCT] Command Configuration
#[derive(Debug, Serialize, Deserialize, Clone, utoipa::ToSchema)]
pub struct CommandConfig {
    pub name: String,
    pub description: String,
    pub permissions: Vec<String>,
    pub vpn_required: bool,
    pub audit_level: String, // "none", "basic", "detailed"
}

/// [WEBHOOK CONFIG STRUCT] Webhook Configuration
#[derive(Debug, Serialize, Deserialize, Clone, utoipa::ToSchema)]
pub struct WebhookConfig {
    pub id: String,
    pub url: String,
    pub events: Vec<String>,
    pub secret: String,
}

/// [DISCORD COMMAND STRUCT] Remote Command Execution Model
/// @MISSION Define structure for executing admin/DevOps commands via Discord.
/// @THREAT Unauthorized command execution, privilege escalation.
/// @COUNTERMEASURE Role validation, command whitelisting, audit logging.
/// @INVARIANT Commands are executed only by authorized users.
/// @AUDIT Command executions are logged with full details.
#[derive(Debug, Serialize, Deserialize, Clone, utoipa::ToSchema)]
pub struct DiscordCommand {
    pub command: String, // "status", "deploy", "logs", "restart", "vpn_peers", "announce"
    pub args: Option<Vec<String>>,
    pub user_id: String,
    pub channel_id: String,
    pub service: Option<String>, // Target service for deploy/restart
    pub urgent: bool,
}

/// [COMMAND RESPONSE STRUCT] Command Execution Response
#[derive(Debug, Serialize, Deserialize, Clone, utoipa::ToSchema)]
pub struct CommandResponse {
    pub success: bool,
    pub output: Option<String>,
    pub error: Option<String>,
    pub execution_time: Option<i64>, // milliseconds
    pub timestamp: DateTime<Utc>,
}

/// [DISCORD AUDIT STRUCT] Audit Log Entry for Discord Operations
/// @MISSION Track all Discord-related operations for compliance.
/// @THREAT Audit log tampering, missing audit trails.
/// @COUNTERMEASURE Immutable logging, secure storage, integrity checks.
/// @INVARIANT All operations are recorded and tamper-proof.
/// @AUDIT Audit logs are themselves audited.
#[derive(Debug, Serialize, Deserialize, Clone, utoipa::ToSchema)]
pub struct DiscordAudit {
    pub id: String,
    pub operation: String, // "event_received", "notification_sent", "command_executed", "config_changed"
    pub user_id: Option<String>,
    pub channel_id: Option<String>,
    pub details: serde_json::Value,
    pub timestamp: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub success: bool,
}