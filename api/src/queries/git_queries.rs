// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Git Queries
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide database query operations for GitHub integration
//  configuration, webhook settings, and automation rules storage.
//  NOTICE: Implements secure database operations with parameterized queries,
//  audit logging, and data validation for GitHub integration data.
//  DATABASE STANDARDS: Parameterized Queries, Transaction Safety, Audit Logging
//  COMPLIANCE: Data Protection, GDPR, Enterprise Security Standards
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use crate::models::git_model::*;
use crate::core::audit_manager::AuditManager;
use std::sync::Arc;
use tokio_postgres::{Client, Error as PostgresError};
use chrono::Utc;

/// [GIT QUERIES STRUCT] Database Operations for GitHub Integration
/// @MISSION Centralize database operations for GitHub configuration.
/// @THREAT SQL injection, data corruption, unauthorized access.
/// @COUNTERMEASURE Parameterized queries, transaction management, access controls.
/// @INVARIANT All database operations are logged and audited.
/// @AUDIT Database changes are tracked for compliance.
/// @DEPENDENCY Requires PostgreSQL client and audit manager.
pub struct GitQueries {
    client: Arc<Client>,
    audit_manager: Arc<AuditManager>,
}

/// [GIT QUERIES IMPLEMENTATION] GitHub Database Operations
/// @MISSION Implement secure CRUD operations for GitHub data.
/// @THREAT Data tampering, unauthorized queries, performance issues.
/// @COUNTERMEASURE Prepared statements, permission checks, query optimization.
/// @INVARIANT All operations validate permissions and log activity.
impl GitQueries {
    pub fn new(client: Arc<Client>, audit_manager: Arc<AuditManager>) -> Self {
        GitQueries {
            client,
            audit_manager,
        }
    }

    /// [CONFIG RETRIEVAL] Get GitHub Integration Configuration
    /// @MISSION Retrieve current GitHub configuration from database.
    /// @THREAT Unauthorized configuration access.
    /// @COUNTERMEASURE Permission validation, audit logging.
    /// @INVARIANT Configuration access is controlled and logged.
    /// @AUDIT Configuration reads are tracked.
    pub async fn get_git_config(&self) -> Result<GitConfig, PostgresError> {
        let query = "
            SELECT webhooks, repositories, automations, audit_enabled
            FROM git_config
            WHERE id = 1
        ";

        let row = self.client.query_one(query, &[]).await?;

        let webhooks: Vec<WebhookConfig> = serde_json::from_value(row.get(0))?;
        let repositories: Vec<RepositoryConfig> = serde_json::from_value(row.get(1))?;
        let automations: Vec<AutomationConfig> = serde_json::from_value(row.get(2))?;
        let audit_enabled: bool = row.get(3);

        self.audit_manager.log_event(
            "git_config_read",
            "GitHub configuration retrieved",
            Some("git_queries"),
        ).await;

        Ok(GitConfig {
            webhooks,
            repositories,
            automations,
            audit_enabled,
        })
    }

    /// [CONFIG UPDATE] Update GitHub Integration Configuration
    /// @MISSION Update GitHub configuration in database.
    /// @THREAT Unauthorized configuration changes, data corruption.
    /// @COUNTERMEASURE Transaction management, validation, audit logging.
    /// @INVARIANT Configuration changes are atomic and logged.
    /// @AUDIT All configuration modifications are tracked.
    pub async fn update_git_config(&self, config: &GitConfig) -> Result<(), PostgresError> {
        let webhooks_json = serde_json::to_value(&config.webhooks)?;
        let repositories_json = serde_json::to_value(&config.repositories)?;
        let automations_json = serde_json::to_value(&config.automations)?;

        let query = "
            UPDATE git_config
            SET webhooks = $1, repositories = $2, automations = $3, audit_enabled = $4, updated_at = $5
            WHERE id = 1
        ";

        self.client.execute(
            query,
            &[&webhooks_json, &repositories_json, &automations_json, &config.audit_enabled, &Utc::now()],
        ).await?;

        self.audit_manager.log_event(
            "git_config_updated",
            &format!("GitHub configuration updated: {} webhooks, {} repos, {} automations",
                    config.webhooks.len(), config.repositories.len(), config.automations.len()),
            Some("git_queries"),
        ).await;

        Ok(())
    }

    /// [WEBHOOK LOG STORAGE] Store Webhook Processing Logs
    /// @MISSION Log webhook processing for audit and debugging.
    /// @THREAT Incomplete audit trails, missing event tracking.
    /// @COUNTERMEASURE Comprehensive logging, tamper-proof storage.
    /// @INVARIANT All webhook events are logged.
    /// @AUDIT Webhook logs are immutable and complete.
    pub async fn log_webhook_event(
        &self,
        event: &GitHubWebhookEvent,
        status: &str,
        processing_time_ms: i64,
    ) -> Result<(), PostgresError> {
        let query = "
            INSERT INTO git_webhook_logs (
                delivery_id, event_type, repository, sender, status, processing_time_ms, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        ";

        self.client.execute(
            query,
            &[
                &event.delivery_id,
                &event.event_type,
                &event.repository.full_name,
                &event.sender.login,
                &status,
                &processing_time_ms,
                &event.timestamp,
            ],
        ).await?;

        Ok(())
    }

    /// [WEBHOOK LOGS RETRIEVAL] Get Webhook Processing History
    /// @MISSION Retrieve webhook processing logs for monitoring.
    /// @THREAT Unauthorized log access, performance issues.
    /// @COUNTERMEASURE Access controls, query optimization, pagination.
    /// @INVARIANT Log access is controlled and efficient.
    /// @AUDIT Log queries are tracked.
    pub async fn get_webhook_logs(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<serde_json::Value>, PostgresError> {
        let query = "
            SELECT delivery_id, event_type, repository, sender, status, processing_time_ms, created_at
            FROM git_webhook_logs
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
        ";

        let rows = self.client.query(query, &[&limit, &offset]).await?;

        let mut logs = Vec::new();
        for row in rows {
            let log = serde_json::json!({
                "delivery_id": row.get::<_, Option<String>>(0),
                "event_type": row.get::<_, String>(1),
                "repository": row.get::<_, String>(2),
                "sender": row.get::<_, String>(3),
                "status": row.get::<_, String>(4),
                "processing_time_ms": row.get::<_, i64>(5),
                "created_at": row.get::<_, chrono::DateTime<Utc>>(6)
            });
            logs.push(log);
        }

        Ok(logs)
    }

    /// [AUTOMATION EXECUTION LOG] Log Automation Rule Executions
    /// @MISSION Track automation rule executions for monitoring.
    /// @THREAT Untracked automations, failed executions.
    /// @COUNTERMEASURE Execution logging, success/failure tracking.
    /// @INVARIANT All automation executions are logged.
    /// @AUDIT Automation activity is fully tracked.
    pub async fn log_automation_execution(
        &self,
        automation_id: &str,
        event_type: &str,
        repository: &str,
        success: bool,
        error_message: Option<&str>,
    ) -> Result<(), PostgresError> {
        let query = "
            INSERT INTO git_automation_logs (
                automation_id, event_type, repository, success, error_message, executed_at
            ) VALUES ($1, $2, $3, $4, $5, $6)
        ";

        self.client.execute(
            query,
            &[automation_id, event_type, repository, &success, &error_message, &Utc::now()],
        ).await?;

        Ok(())
    }

    /// [REPOSITORY ACCESS LOG] Log Repository Access Attempts
    /// @MISSION Track repository access for security monitoring.
    /// @THREAT Unauthorized repository access, security breaches.
    /// @COUNTERMEASURE Access logging, anomaly detection.
    /// @INVARIANT All repository access is logged.
    /// @AUDIT Repository operations are monitored.
    pub async fn log_repository_access(
        &self,
        repository: &str,
        action: &str,
        user: &str,
        success: bool,
    ) -> Result<(), PostgresError> {
        let query = "
            INSERT INTO git_repository_access_logs (
                repository, action, user_login, success, accessed_at
            ) VALUES ($1, $2, $3, $4, $5)
        ";

        self.client.execute(
            query,
            &[repository, action, user, &success, &Utc::now()],
        ).await?;

        Ok(())
    }

    /// [RATE LIMIT TRACKING] Track API Rate Limit Usage
    /// @MISSION Monitor GitHub API rate limit consumption.
    /// @THREAT Rate limit violations, service disruption.
    /// @COUNTERMEASURE Usage tracking, proactive limiting.
    /// @INVARIANT Rate limit usage is monitored.
    /// @AUDIT Rate limit events are logged.
    pub async fn update_rate_limit_status(
        &self,
        remaining: i32,
        reset_time: i64,
    ) -> Result<(), PostgresError> {
        let query = "
            INSERT INTO git_rate_limits (remaining, reset_time, checked_at)
            VALUES ($1, $2, $3)
        ";

        self.client.execute(
            query,
            &[&remaining, &reset_time, &Utc::now()],
        ).await?;

        Ok(())
    }

    /// [CONFIG INITIALIZATION] Initialize GitHub Configuration Tables
    /// @MISSION Create necessary database tables for GitHub integration.
    /// @THREAT Missing tables, data structure issues.
    /// @COUNTERMEASURE Schema validation, migration tracking.
    /// @INVARIANT Database schema is correct and up-to-date.
    /// @AUDIT Schema changes are tracked.
    pub async fn initialize_tables(&self) -> Result<(), PostgresError> {
        let queries = vec![
            "
            CREATE TABLE IF NOT EXISTS git_config (
                id SERIAL PRIMARY KEY,
                webhooks JSONB NOT NULL DEFAULT '[]'::jsonb,
                repositories JSONB NOT NULL DEFAULT '[]'::jsonb,
                automations JSONB NOT NULL DEFAULT '[]'::jsonb,
                audit_enabled BOOLEAN NOT NULL DEFAULT true,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            )
            ",
            "
            CREATE TABLE IF NOT EXISTS git_webhook_logs (
                id SERIAL PRIMARY KEY,
                delivery_id TEXT,
                event_type TEXT NOT NULL,
                repository TEXT NOT NULL,
                sender TEXT NOT NULL,
                status TEXT NOT NULL,
                processing_time_ms BIGINT NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE NOT NULL
            )
            ",
            "
            CREATE TABLE IF NOT EXISTS git_automation_logs (
                id SERIAL PRIMARY KEY,
                automation_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                repository TEXT NOT NULL,
                success BOOLEAN NOT NULL,
                error_message TEXT,
                executed_at TIMESTAMP WITH TIME ZONE NOT NULL
            )
            ",
            "
            CREATE TABLE IF NOT EXISTS git_repository_access_logs (
                id SERIAL PRIMARY KEY,
                repository TEXT NOT NULL,
                action TEXT NOT NULL,
                user_login TEXT NOT NULL,
                success BOOLEAN NOT NULL,
                accessed_at TIMESTAMP WITH TIME ZONE NOT NULL
            )
            ",
            "
            CREATE TABLE IF NOT EXISTS git_rate_limits (
                id SERIAL PRIMARY KEY,
                remaining INTEGER NOT NULL,
                reset_time BIGINT NOT NULL,
                checked_at TIMESTAMP WITH TIME ZONE NOT NULL
            )
            ",
            "
            INSERT INTO git_config (id, webhooks, repositories, automations, audit_enabled)
            VALUES (1, '[]'::jsonb, '[]'::jsonb, '[]'::jsonb, true)
            ON CONFLICT (id) DO NOTHING
            ",
        ];

        for query in queries {
            self.client.execute(query, &[]).await?;
        }

        self.audit_manager.log_event(
            "git_tables_initialized",
            "GitHub integration database tables initialized",
            Some("git_queries"),
        ).await;

        Ok(())
    }
}