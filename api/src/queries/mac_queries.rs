// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: MAC Identity Database Queries
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | SENSITIVE
//  MISSION: Provide type-safe database query abstractions for MAC identity
//  operations, ensuring secure data access with audit logging and tenant isolation.
//  NOTICE: Implements prepared statements, connection pooling, and security
//  controls for all MAC identity database operations.
//  STANDARDS: PostgreSQL, Prepared Statements, Connection Pooling
//  COMPLIANCE: Data Security, Audit Requirements, Tenant Isolation
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use std::collections::HashMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use sqlx::PgPool;

use crate::models::data_model::{MacIdentity, MacStatus};
use crate::core::audit_manager::{AuditManager, AuditEventType, AuditSeverity};

/// [MAC QUERIES] Database query operations for MAC identities
/// @MISSION Provide secure, audited database operations for MAC management.
/// @THREAT SQL injection or unauthorized data access.
/// @COUNTERMEASURE Prepared statements and organization isolation.
/// @AUDIT All database operations logged with user context.
/// @DEPENDENCY PostgreSQL connection pool and audit manager.
pub struct MacQueries {
    pool: PgPool,
    audit_manager: AuditManager,
}

impl MacQueries {
    /// Create new MAC queries instance
    pub fn new(pool: PgPool, audit_manager: AuditManager) -> Self {
        Self { pool, audit_manager }
    }

    /// Insert new MAC identity
    pub async fn insert_mac_identity(
        &self,
        mac: &MacIdentity,
        user_id: &str,
    ) -> Result<(), String> {
        sqlx::query(
            r#"
            INSERT INTO mac_identities (
                id, sge_mac, standard_mac, ip_address, owner, fingerprint,
                status, organization_id, metadata, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
            mac.id,
            mac.sge_mac,
            mac.standard_mac,
            mac.ip_address,
            mac.owner,
            mac.fingerprint,
            mac.status as MacStatus,
            mac.organization_id,
            mac.metadata,
            mac.created_at,
            mac.updated_at,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Database error: {}", e))?;

        self.audit_manager.audit_event(
            AuditEventType::Security,
            AuditSeverity::Info,
            Some(user_id),
            "mac_queries",
            &format!("MAC identity inserted: {}", mac.sge_mac),
            Some(serde_json::json!({
                "mac_id": mac.id,
                "sge_mac": mac.sge_mac,
                "organization_id": mac.organization_id
            })),
        ).await;

        Ok(())
    }

    /// Get MAC identity by SGE-MAC address
    pub async fn get_mac_by_address(
        &self,
        sge_mac: &str,
        organization_id: Uuid,
        user_id: &str,
    ) -> Result<MacIdentity, String> {
        let mac = sqlx::query_as::<_, MacIdentity>(
            r#"
            SELECT id, sge_mac, standard_mac, ip_address, owner, fingerprint,
                   status as "status: MacStatus", organization_id, metadata,
                   created_at, updated_at
            FROM mac_identities
            WHERE sge_mac = $1 AND organization_id = $2
            "#,
            sge_mac,
            organization_id,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| format!("Database error: {}", e))?
        .ok_or_else(|| "MAC identity not found".to_string())?;

        self.audit_manager.audit_event(
            AuditEventType::Access,
            AuditSeverity::Info,
            Some(user_id),
            "mac_queries",
            &format!("MAC identity retrieved: {}", sge_mac),
            Some(serde_json::json!({
                "mac_id": mac.id,
                "sge_mac": sge_mac,
                "organization_id": organization_id
            })),
        ).await;

        Ok(mac)
    }

    /// Get MAC identity by fingerprint
    pub async fn get_mac_by_fingerprint(
        &self,
        fingerprint: &str,
        organization_id: Uuid,
        user_id: &str,
    ) -> Result<MacIdentity, String> {
        let mac = sqlx::query_as::<_, MacIdentity>(
            r#"
            SELECT id, sge_mac, standard_mac, ip_address, owner, fingerprint,
                   status as "status: MacStatus", organization_id, metadata,
                   created_at, updated_at
            FROM mac_identities
            WHERE fingerprint = $1 AND organization_id = $2
            "#,
            fingerprint,
            organization_id,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| format!("Database error: {}", e))?
        .ok_or_else(|| "MAC identity not found for fingerprint".to_string())?;

        self.audit_manager.audit_event(
            AuditEventType::Access,
            AuditSeverity::Info,
            Some(user_id),
            "mac_queries",
            &format!("MAC identity retrieved by fingerprint: {}", mac.sge_mac),
            Some(serde_json::json!({
                "mac_id": mac.id,
                "fingerprint": fingerprint,
                "organization_id": organization_id
            })),
        ).await;

        Ok(mac)
    }

    /// Get MAC identity by IP address
    pub async fn get_mac_by_ip(
        &self,
        ip_address: &str,
        organization_id: Uuid,
        user_id: &str,
    ) -> Result<MacIdentity, String> {
        let mac = sqlx::query_as::<_, MacIdentity>(
            r#"
            SELECT id, sge_mac, standard_mac, ip_address, owner, fingerprint,
                   status as "status: MacStatus", organization_id, metadata,
                   created_at, updated_at
            FROM mac_identities
            WHERE ip_address = $1 AND organization_id = $2 AND status = $3
            "#,
            ip_address,
            organization_id,
            MacStatus::Active as MacStatus,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| format!("Database error: {}", e))?
        .ok_or_else(|| "No active MAC found for IP address".to_string())?;

        self.audit_manager.audit_event(
            AuditEventType::Access,
            AuditSeverity::Info,
            Some(user_id),
            "mac_queries",
            &format!("MAC identity resolved by IP: {} -> {}", ip_address, mac.sge_mac),
            Some(serde_json::json!({
                "mac_id": mac.id,
                "ip_address": ip_address,
                "sge_mac": mac.sge_mac,
                "organization_id": organization_id
            })),
        ).await;

        Ok(mac)
    }

    /// List MAC identities with pagination and filters
    pub async fn list_mac_identities(
        &self,
        organization_id: Uuid,
        page: u32,
        per_page: u32,
        status_filter: Option<MacStatus>,
        user_id: &str,
    ) -> Result<(Vec<MacIdentity>, i64), String> {
        let offset = (page - 1) * per_page;

        let (macs, total_count) = if let Some(status) = status_filter {
            let macs = sqlx::query_as::<_, MacIdentity>(
                r#"
                SELECT id, sge_mac, standard_mac, ip_address, owner, fingerprint,
                       status as "status: MacStatus", organization_id, metadata,
                       created_at, updated_at
                FROM mac_identities
                WHERE organization_id = $1 AND status = $2
                ORDER BY created_at DESC
                LIMIT $3 OFFSET $4
                "#,
                organization_id,
                status as MacStatus,
                per_page as i64,
                offset as i64,
            )
            .fetch_all(&self.pool)
            .await
            .map_err(|e| format!("Database error: {}", e))?;

            let count = sqlx::query_scalar(
                r#"
                SELECT COUNT(*) as count
                FROM mac_identities
                WHERE organization_id = $1 AND status = $2
                "#,
                organization_id,
                status as MacStatus,
            )
            .fetch_one(&self.pool)
            .await
            .map_err(|e| format!("Database error: {}", e))?
            .unwrap_or(0);

            (macs, count)
        } else {
            let macs = sqlx::query_as::<_, MacIdentity>(
                r#"
                SELECT id, sge_mac, standard_mac, ip_address, owner, fingerprint,
                   status as "status: MacStatus", organization_id, metadata,
                   created_at, updated_at
                FROM mac_identities
                WHERE organization_id = $1
                ORDER BY created_at DESC
                LIMIT $2 OFFSET $3
                "#,
                organization_id,
                per_page as i64,
                offset as i64,
            )
            .fetch_all(&self.pool)
            .await
            .map_err(|e| format!("Database error: {}", e))?;

            let count = sqlx::query_scalar(
                r#"
                SELECT COUNT(*) as count
                FROM mac_identities
                WHERE organization_id = $1
                "#,
                organization_id,
            )
            .fetch_one(&self.pool)
            .await
            .map_err(|e| format!("Database error: {}", e))?
            .unwrap_or(0);

            (macs, count)
        };

        self.audit_manager.audit_event(
            AuditEventType::Access,
            AuditSeverity::Info,
            Some(user_id),
            "mac_queries",
            &format!("Listed {} MAC identities", macs.len()),
            Some(serde_json::json!({
                "organization_id": organization_id,
                "page": page,
                "per_page": per_page,
                "total_count": total_count,
                "status_filter": status_filter.map(|s| format!("{:?}", s))
            })),
        ).await;

        Ok((macs, total_count))
    }

    /// Update MAC identity
    pub async fn update_mac_identity(
        &self,
        sge_mac: &str,
        organization_id: Uuid,
        ip_address: Option<String>,
        status: Option<MacStatus>,
        metadata: Option<HashMap<String, String>>,
        user_id: &str,
    ) -> Result<MacIdentity, String> {
        let updated_mac = sqlx::query_as::<_, MacIdentity>(
            r#"
            UPDATE mac_identities
            SET ip_address = COALESCE($1, ip_address),
                status = COALESCE($2, status),
                metadata = COALESCE($3, metadata),
                updated_at = NOW()
            WHERE sge_mac = $4 AND organization_id = $5
            RETURNING id, sge_mac, standard_mac, ip_address, owner, fingerprint,
                      status as "status: MacStatus", organization_id, metadata,
                      created_at, updated_at
            "#,
            ip_address,
            status as Option<MacStatus>,
            metadata,
            sge_mac,
            organization_id,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| format!("Database error: {}", e))?
        .ok_or_else(|| "MAC identity not found".to_string())?;

        self.audit_manager.audit_event(
            AuditEventType::Security,
            AuditSeverity::Info,
            Some(user_id),
            "mac_queries",
            &format!("MAC identity updated: {}", sge_mac),
            Some(serde_json::json!({
                "mac_id": updated_mac.id,
                "sge_mac": sge_mac,
                "organization_id": organization_id,
                "changes": {
                    "ip_address": ip_address.is_some(),
                    "status": status.is_some(),
                    "metadata": metadata.is_some()
                }
            })),
        ).await;

        Ok(updated_mac)
    }

    /// Delete MAC identity
    pub async fn delete_mac_identity(
        &self,
        sge_mac: &str,
        organization_id: Uuid,
        user_id: &str,
    ) -> Result<(), String> {
        let result = sqlx::query(
            r#"
            DELETE FROM mac_identities
            WHERE sge_mac = $1 AND organization_id = $2
            "#,
            sge_mac,
            organization_id,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Database error: {}", e))?;

        if result.rows_affected() == 0 {
            return Err("MAC identity not found".to_string());
        }

        self.audit_manager.audit_event(
            AuditEventType::Security,
            AuditSeverity::Warning,
            Some(user_id),
            "mac_queries",
            &format!("MAC identity deleted: {}", sge_mac),
            Some(serde_json::json!({
                "sge_mac": sge_mac,
                "organization_id": organization_id
            })),
        ).await;

        Ok(())
    }

    /// Check if SGE-MAC exists
    pub async fn mac_exists(
        &self,
        sge_mac: &str,
        organization_id: Uuid,
    ) -> Result<bool, String> {
        let count = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) as count
            FROM mac_identities
            WHERE sge_mac = $1 AND organization_id = $2
            "#,
            sge_mac,
            organization_id,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| format!("Database error: {}", e))?
        .unwrap_or(0);

        Ok(count > 0)
    }

    /// Get MAC statistics for organization
    pub async fn get_mac_statistics(
        &self,
        organization_id: Uuid,
        user_id: &str,
    ) -> Result<MacStatistics, String> {
        let stats = sqlx::query(
            r#"
            SELECT
                COUNT(*) as total_macs,
                COUNT(CASE WHEN status = 'Active' THEN 1 END) as active_macs,
                COUNT(CASE WHEN status = 'Inactive' THEN 1 END) as inactive_macs,
                COUNT(CASE WHEN status = 'Revoked' THEN 1 END) as revoked_macs,
                COUNT(DISTINCT ip_address) as unique_ips,
                MAX(created_at) as latest_registration
            FROM mac_identities
            WHERE organization_id = $1
            "#,
            organization_id,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| format!("Database error: {}", e))?;

        let statistics = MacStatistics {
            total_macs: stats.total_macs.unwrap_or(0),
            active_macs: stats.active_macs.unwrap_or(0),
            inactive_macs: stats.inactive_macs.unwrap_or(0),
            revoked_macs: stats.revoked_macs.unwrap_or(0),
            unique_ips: stats.unique_ips.unwrap_or(0),
            latest_registration: stats.latest_registration,
        };

        self.audit_manager.audit_event(
            AuditEventType::Access,
            AuditSeverity::Info,
            Some(user_id),
            "mac_queries",
            "MAC statistics retrieved",
            Some(serde_json::json!({
                "organization_id": organization_id,
                "statistics": statistics
            })),
        ).await;

        Ok(statistics)
    }
}

/// MAC statistics structure
#[derive(Debug, serde::Serialize)]
pub struct MacStatistics {
    pub total_macs: i64,
    pub active_macs: i64,
    pub inactive_macs: i64,
    pub revoked_macs: i64,
    pub unique_ips: i64,
    pub latest_registration: Option<DateTime<Utc>>,
}