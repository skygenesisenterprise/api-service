// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Git Model
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Define GitHub webhook integration data structures for secure
//  automation and event processing with enterprise security standards.
//  NOTICE: Git models implement webhook signature validation, event processing,
//  and audit logging for GitHub operations with enterprise security standards.
//  GITHUB STANDARDS: Webhook Security, Event Processing, Audit Trails
//  COMPLIANCE: Data Protection, API Security, Audit Standards
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// [GITHUB WEBHOOK EVENT STRUCT] Incoming GitHub Webhook Event Model
/// @MISSION Define structure for GitHub webhook events (push, pull_request, etc.).
/// @THREAT Webhook spoofing, unauthorized events, data injection.
/// @COUNTERMEASURE Signature validation, event verification, input sanitization.
/// @INVARIANT Events are validated and authenticated before processing.
/// @AUDIT All events are logged with repository and action details.
#[derive(Debug, Serialize, Deserialize, Clone, utoipa::ToSchema)]
pub struct GitHubWebhookEvent {
    pub action: Option<String>, // "opened", "closed", "push", etc.
    pub event_type: String, // "push", "pull_request", "issues", etc.
    pub repository: Repository,
    pub sender: User,
    pub payload: serde_json::Value, // Raw payload for flexibility
    pub signature: Option<String>, // X-Hub-Signature-256 header
    pub delivery_id: Option<String>, // X-GitHub-Delivery header
    pub timestamp: DateTime<Utc>,
}

/// [REPOSITORY STRUCT] GitHub Repository Information
#[derive(Debug, Serialize, Deserialize, Clone, utoipa::ToSchema)]
pub struct Repository {
    pub id: u64,
    pub name: String,
    pub full_name: String,
    pub owner: User,
    pub private: bool,
    pub html_url: String,
    pub description: Option<String>,
    pub fork: bool,
    pub url: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub pushed_at: Option<DateTime<Utc>>,
    pub git_url: String,
    pub ssh_url: String,
    pub clone_url: String,
    pub language: Option<String>,
}

/// [USER STRUCT] GitHub User Information
#[derive(Debug, Serialize, Deserialize, Clone, utoipa::ToSchema)]
pub struct User {
    pub id: u64,
    pub login: String,
    pub avatar_url: String,
    pub html_url: String,
    pub name: Option<String>,
    pub email: Option<String>,
}

/// [GIT CONFIG STRUCT] GitHub Integration Configuration
/// @MISSION Define GitHub integration configuration settings.
/// @THREAT Configuration tampering, unauthorized changes.
/// @COUNTERMEASURE Access control, validation, audit logging.
/// @INVARIANT Configuration changes require proper authorization.
/// @AUDIT Configuration modifications are logged.
#[derive(Debug, Serialize, Deserialize, Clone, utoipa::ToSchema)]
pub struct GitConfig {
    pub webhooks: Vec<WebhookConfig>,
    pub repositories: Vec<RepositoryConfig>,
    pub automations: Vec<AutomationConfig>,
    pub audit_enabled: bool,
}

/// [WEBHOOK CONFIG STRUCT] Webhook Configuration
#[derive(Debug, Serialize, Deserialize, Clone, utoipa::ToSchema)]
pub struct WebhookConfig {
    pub id: String,
    pub repository: String, // "owner/repo"
    pub events: Vec<String>, // ["push", "pull_request", "issues"]
    pub secret: String,
    pub active: bool,
}

/// [REPOSITORY CONFIG STRUCT] Repository Configuration
#[derive(Debug, Serialize, Deserialize, Clone, utoipa::ToSchema)]
pub struct RepositoryConfig {
    pub name: String, // "owner/repo"
    pub permissions: Vec<String>,
    pub automations: Vec<String>, // IDs of enabled automations
}

/// [AUTOMATION CONFIG STRUCT] Automation Configuration
#[derive(Debug, Serialize, Deserialize, Clone, utoipa::ToSchema)]
pub struct AutomationConfig {
    pub id: String,
    pub name: String,
    pub description: String,
    pub event_types: Vec<String>,
    pub actions: Vec<String>, // What to do when triggered
    pub enabled: bool,
}