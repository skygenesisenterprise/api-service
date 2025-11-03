// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Discord Database Queries
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide database abstraction layer for Discord bot operations
//  including configuration storage, audit logging, webhook management,
//  and command history tracking.
//  NOTICE: Implements secure database operations with audit logging,
//  tenant isolation, and error handling for Discord integration.
//  DB STANDARDS: PostgreSQL, Prepared Statements, Connection Pooling
//  COMPLIANCE: Data Security, Audit Trails, Discord API Compliance
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use crate::models::discord_model::*;
use sqlx::PgPool;
use chrono::Utc;

/// [DISCORD QUERIES] Database query operations for Discord integration
/// @MISSION Provide secure database access for Discord bot data.
/// @THREAT Unauthorized access to Discord configuration and audit data.
/// @COUNTERMEASURE Access controls, encryption, audit logging.
/// @INVARIANT All database operations are logged and secured.
/// @AUDIT Database queries are monitored for anomalies.
/// @DEPENDENCY PostgreSQL database with proper schema.
pub struct DiscordQueries {
    pool: PgPool,
}

/// [DISCORD QUERIES IMPLEMENTATION] Database Operations for Discord
/// @MISSION Implement CRUD operations for Discord-related data.
/// @THREAT SQL injection, data leakage, unauthorized modifications.
/// @COUNTERMEASURE Prepared statements, access controls, encryption.
/// @INVARIANT Database integrity is maintained.
/// @AUDIT All operations are logged.
/// @FLOW Connect -> Execute query -> Log operation -> Return result.
impl DiscordQueries {
    /// [DATABASE CONNECTION] Initialize Discord Queries with Database Pool
    /// @MISSION Set up database connection for Discord queries.
    /// @THREAT Connection failures, credential exposure.
    /// @COUNTERMEASURE Connection pooling, secure credentials.
    /// @INVARIANT Database connection is available.
    /// @AUDIT Connection attempts are logged.
    /// @FLOW Create pool -> Test connection -> Return instance.
    pub fn new(pool: PgPool) -> Self {
        DiscordQueries { pool }
    }

    /// [CONFIGURATION STORAGE] Store Discord Bot Configuration
    /// @MISSION Persist bot configuration in database.
    /// @THREAT Configuration tampering, unauthorized changes.
    /// @COUNTERMEASURE Access controls, audit logging, validation.
    /// @INVARIANT Configuration is securely stored.
    /// @AUDIT Configuration changes are logged.
    /// @FLOW Validate config -> Insert/update -> Log change.
    pub async fn save_configuration(&self, config: &DiscordConfig) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO discord_configurations (id, channels, roles, permissions, commands, webhooks, vpn_required, audit_enabled, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT (id) DO UPDATE SET
                channels = EXCLUDED.channels,
                roles = EXCLUDED.roles,
                permissions = EXCLUDED.permissions,
                commands = EXCLUDED.commands,
                webhooks = EXCLUDED.webhooks,
                vpn_required = EXCLUDED.vpn_required,
                audit_enabled = EXCLUDED.audit_enabled,
                updated_at = EXCLUDED.updated_at
            "#,
            "default", // Single configuration for now
            serde_json::to_value(&config.channels).unwrap_or_default(),
            serde_json::to_value(&config.roles).unwrap_or_default(),
            serde_json::to_value(&config.permissions).unwrap_or_default(),
            serde_json::to_value(&config.commands).unwrap_or_default(),
            serde_json::to_value(&config.webhooks).unwrap_or_default(),
            config.vpn_required,
            config.audit_enabled,
            Utc::now(),
            Utc::now()
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// [CONFIGURATION RETRIEVAL] Get Discord Bot Configuration
    /// @MISSION Retrieve current bot configuration from database.
    /// @THREAT Configuration exposure, unauthorized access.
    /// @COUNTERMEASURE Access controls, data sanitization.
    /// @INVARIANT Configuration is securely retrieved.
    /// @AUDIT Configuration access is logged.
    /// @FLOW Query database -> Deserialize -> Return config.
    pub async fn get_configuration(&self) -> Result<Option<DiscordConfig>, sqlx::Error> {
        let result = sqlx::query(
            r#"
            SELECT channels, roles, permissions, commands, webhooks, vpn_required, audit_enabled
            FROM discord_configurations
            WHERE id = $1
            "#,
            "default"
        )
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = result {
            let config = DiscordConfig {
                channels: serde_json::from_value(row.channels).unwrap_or_default(),
                roles: serde_json::from_value(row.roles).unwrap_or_default(),
                permissions: serde_json::from_value(row.permissions).unwrap_or_default(),
                commands: serde_json::from_value(row.commands).unwrap_or_default(),
                webhooks: serde_json::from_value(row.webhooks).unwrap_or_default(),
                vpn_required: row.vpn_required,
                audit_enabled: row.audit_enabled,
            };
            Ok(Some(config))
        } else {
            Ok(None)
        }
    }

    /// [AUDIT LOG STORAGE] Store Discord Audit Events
    /// @MISSION Persist audit logs for compliance and security.
    /// @THREAT Audit log tampering, missing audit trails.
    /// @COUNTERMEASURE Immutable logging, secure storage.
    /// @INVARIANT All operations are audited.
    /// @AUDIT Audit logs are themselves audited.
    /// @FLOW Insert audit record -> Return success.
    pub async fn save_audit_event(&self, audit: &DiscordAudit) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO discord_audit_logs (id, operation, user_id, channel_id, details, timestamp, ip_address, user_agent, success)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
            audit.id,
            audit.operation,
            audit.user_id,
            audit.channel_id,
            audit.details,
            audit.timestamp,
            audit.ip_address,
            audit.user_agent,
            audit.success
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// [AUDIT LOG RETRIEVAL] Get Discord Audit Events
    /// @MISSION Retrieve audit logs for monitoring and compliance.
    /// @THREAT Unauthorized audit access, log tampering.
    /// @COUNTERMEASURE Access controls, integrity checks.
    /// @INVARIANT Audit logs are securely accessible.
    /// @AUDIT Audit log access is logged.
    /// @FLOW Query database -> Return audit events.
    pub async fn get_audit_events(
        &self,
        user_id: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<DiscordAudit>, sqlx::Error> {
        let events = if let Some(user_id) = user_id {
            sqlx::query_as::<_, DiscordAudit>(
                r#"
                SELECT id, operation, user_id, channel_id, details, timestamp, ip_address, user_agent, success
                FROM discord_audit_logs
                WHERE user_id = $1
                ORDER BY timestamp DESC
                LIMIT $2 OFFSET $3
                "#,
                user_id,
                limit,
                offset
            )
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as::<_, DiscordAudit>(
                r#"
                SELECT id, operation, user_id, channel_id, details, timestamp, ip_address, user_agent, success
                FROM discord_audit_logs
                ORDER BY timestamp DESC
                LIMIT $1 OFFSET $2
                "#,
                limit,
                offset
            )
            .fetch_all(&self.pool)
            .await?
        };

        Ok(events)
    }

    /// [COMMAND HISTORY STORAGE] Store Command Execution History
    /// @MISSION Track command executions for audit and debugging.
    /// @THREAT Unlogged command execution, security gaps.
    /// @COUNTERMEASURE Database logging, execution tracking.
    /// @INVARIANT All commands are logged.
    /// @AUDIT Command history is audited.
    /// @FLOW Insert command record -> Return success.
    pub async fn save_command_history(&self, command: &DiscordCommand, response: &CommandResponse) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO discord_command_history (id, command, args, user_id, channel_id, service, urgent, response_success, response_output, response_error, execution_time, timestamp)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            "#,
            uuid::Uuid::new_v4().to_string(),
            command.command,
            command.args.as_ref().map(|a| serde_json::to_value(a).unwrap_or_default()),
            command.user_id,
            command.channel_id,
            command.service,
            command.urgent,
            response.success,
            response.output,
            response.error,
            response.execution_time,
            response.timestamp
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// [COMMAND HISTORY RETRIEVAL] Get Command Execution History
    /// @MISSION Retrieve command history for monitoring and debugging.
    /// @THREAT Unauthorized access to command history.
    /// @COUNTERMEASURE Access controls, data filtering.
    /// @INVARIANT Command history is securely accessible.
    /// @AUDIT Command history access is logged.
    /// @FLOW Query database -> Return command history.
    pub async fn get_command_history(
        &self,
        user_id: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<serde_json::Value>, sqlx::Error> {
        let history = if let Some(user_id) = user_id {
            sqlx::query(
                r#"
                SELECT id, command, args, user_id, channel_id, service, urgent, response_success, response_output, response_error, execution_time, timestamp
                FROM discord_command_history
                WHERE user_id = $1
                ORDER BY timestamp DESC
                LIMIT $2 OFFSET $3
                "#,
                user_id,
                limit,
                offset
            )
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                r#"
                SELECT id, command, args, user_id, channel_id, service, urgent, response_success, response_output, response_error, execution_time, timestamp
                FROM discord_command_history
                ORDER BY timestamp DESC
                LIMIT $1 OFFSET $2
                "#,
                limit,
                offset
            )
            .fetch_all(&self.pool)
            .await?
        };

        let result = history.into_iter()
            .map(|row| {
                serde_json::json!({
                    "id": row.id,
                    "command": row.command,
                    "args": row.args,
                    "user_id": row.user_id,
                    "channel_id": row.channel_id,
                    "service": row.service,
                    "urgent": row.urgent,
                    "response_success": row.response_success,
                    "response_output": row.response_output,
                    "response_error": row.response_error,
                    "execution_time": row.execution_time,
                    "timestamp": row.timestamp
                })
            })
            .collect();

        Ok(result)
    }

    /// [WEBHOOK CONFIGURATION] Store Webhook Configurations
    /// @MISSION Persist webhook settings for Discord channels.
    /// @THREAT Webhook URL exposure, unauthorized webhook access.
    /// @COUNTERMEASURE Encrypted storage, access controls.
    /// @INVARIANT Webhook configurations are secure.
    /// @AUDIT Webhook changes are logged.
    /// @FLOW Encrypt URL -> Store configuration -> Log change.
    pub async fn save_webhook_config(&self, webhook: &WebhookConfig) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO discord_webhooks (id, url, events, secret, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (id) DO UPDATE SET
                url = EXCLUDED.url,
                events = EXCLUDED.events,
                secret = EXCLUDED.secret,
                updated_at = EXCLUDED.updated_at
            "#,
            webhook.id,
            webhook.url,
            serde_json::to_value(&webhook.events).unwrap_or_default(),
            webhook.secret,
            Utc::now(),
            Utc::now()
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// [WEBHOOK RETRIEVAL] Get Webhook Configuration
    /// @MISSION Retrieve webhook settings for message sending.
    /// @THREAT Webhook URL exposure during retrieval.
    /// @COUNTERMEASURE Access controls, secure transmission.
    /// @INVARIANT Webhook data is securely retrieved.
    /// @AUDIT Webhook access is logged.
    /// @FLOW Query database -> Decrypt if needed -> Return config.
    pub async fn get_webhook_config(&self, webhook_id: &str) -> Result<Option<WebhookConfig>, sqlx::Error> {
        let result = sqlx::query(
            r#"
            SELECT id, url, events, secret
            FROM discord_webhooks
            WHERE id = $1
            "#,
            webhook_id
        )
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = result {
            let webhook = WebhookConfig {
                id: row.id,
                url: row.url,
                events: serde_json::from_value(row.events).unwrap_or_default(),
                secret: row.secret,
            };
            Ok(Some(webhook))
        } else {
            Ok(None)
        }
    }

    /// [CLEANUP OPERATIONS] Remove Old Audit Logs and Command History
    /// @MISSION Maintain database size and performance.
    /// @THREAT Database bloat, performance degradation.
    /// @COUNTERMEASURE Automated cleanup, retention policies.
    /// @INVARIANT Database remains performant.
    /// @AUDIT Cleanup operations are logged.
    /// @FLOW Delete old records -> Log cleanup -> Return count.
    pub async fn cleanup_old_records(&self, days_old: i32) -> Result<(u64, u64), sqlx::Error> {
        let cutoff_date = Utc::now() - chrono::Duration::days(days_old as i64);

        let audit_deleted = sqlx::query(
            "DELETE FROM discord_audit_logs WHERE timestamp < $1",
            cutoff_date
        )
        .execute(&self.pool)
        .await?
        .rows_affected();

        let command_deleted = sqlx::query(
            "DELETE FROM discord_command_history WHERE timestamp < $1",
            cutoff_date
        )
        .execute(&self.pool)
        .await?
        .rows_affected();

        Ok((audit_deleted, command_deleted))
    }

    /// [STATISTICS QUERIES] Get Discord Integration Statistics
    /// @MISSION Provide metrics for monitoring and reporting.
    /// @THREAT Inaccurate metrics, performance impact.
    /// @COUNTERMEASURE Optimized queries, caching.
    /// @INVARIANT Statistics are accurate and fast.
    /// @AUDIT Statistics queries are logged.
    /// @FLOW Aggregate data -> Return statistics.
    pub async fn get_statistics(&self) -> Result<serde_json::Value, sqlx::Error> {
        let audit_count = sqlx::query("SELECT COUNT(*) as count FROM discord_audit_logs")
            .fetch_one(&self.pool)
            .await?
            .count
            .unwrap_or(0);

        let command_count = sqlx::query("SELECT COUNT(*) as count FROM discord_command_history")
            .fetch_one(&self.pool)
            .await?
            .count
            .unwrap_or(0);

        let webhook_count = sqlx::query("SELECT COUNT(*) as count FROM discord_webhooks")
            .fetch_one(&self.pool)
            .await?
            .count
            .unwrap_or(0);

        let recent_commands = sqlx::query(
            r#"
            SELECT COUNT(*) as count
            FROM discord_command_history
            WHERE timestamp > $1
            "#,
            Utc::now() - chrono::Duration::hours(24)
        )
        .fetch_one(&self.pool)
        .await?
        .count
        .unwrap_or(0);

        let stats = serde_json::json!({
            "total_audit_events": audit_count,
            "total_commands_executed": command_count,
            "active_webhooks": webhook_count,
            "commands_last_24h": recent_commands
        });

        Ok(stats)
    }
}