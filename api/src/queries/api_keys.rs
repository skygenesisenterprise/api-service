// ============================================================================
// Sky Genesis Enterprise API - API Key Database Queries
// ============================================================================

use sqlx::{PgPool, Row};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use crate::models::api_keys::{ApiKey, ApiKeyRow, KeyType, KeyStatus, DatabaseType};
use anyhow::Result;

// ============================================================================
// API Key Query Builder
// ============================================================================

pub struct ApiKeyQueries {
    pool: PgPool,
}

impl ApiKeyQueries {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // ============================================================================
    // Basic CRUD Queries
    // ============================================================================

    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<ApiKeyRow>> {
        let row = sqlx::query_as!(
            ApiKeyRow,
            r#"
            SELECT * FROM api_keys 
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    pub async fn find_by_id_and_org(&self, id: Uuid, organization_id: Uuid) -> Result<Option<ApiKeyRow>> {
        let row = sqlx::query_as!(
            ApiKeyRow,
            r#"
            SELECT * FROM api_keys 
            WHERE id = $1 AND organization_id = $2
            "#,
            id,
            organization_id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    pub async fn find_by_key_value(&self, key_value: &str) -> Result<Option<ApiKeyRow>> {
        let row = sqlx::query_as!(
            ApiKeyRow,
            r#"
            SELECT * FROM api_keys 
            WHERE key_value = $1
            "#,
            key_value
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    pub async fn find_by_organization(
        &self,
        organization_id: Uuid,
        key_type: Option<KeyType>,
        status: Option<KeyStatus>,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<ApiKeyRow>> {
        let mut query = "SELECT * FROM api_keys WHERE organization_id = $1".to_string();
        let mut param_count = 2;

        if let Some(kt) = &key_type {
            query.push_str(&format!(" AND key_type = ${}", param_count));
            param_count += 1;
        }

        if let Some(st) = &status {
            query.push_str(&format!(" AND status = ${}", param_count));
            param_count += 1;
        }

        query.push_str(" ORDER BY created_at DESC");

        if let Some(limit_val) = limit {
            query.push_str(&format!(" LIMIT {}", limit_val));
        }

        if let Some(offset_val) = offset {
            query.push_str(&format!(" OFFSET {}", offset_val));
        }

        let mut query_builder = sqlx::query_as::<_, ApiKeyRow>(&query)
            .bind(organization_id);

        if let Some(kt) = &key_type {
            query_builder = query_builder.bind(kt.to_string());
        }

        if let Some(st) = &status {
            query_builder = query_builder.bind(st.to_string());
        }

        let rows = query_builder.fetch_all(&self.pool).await?;
        Ok(rows)
    }

    // ============================================================================
    // Insert Queries
    // ============================================================================

    pub async fn insert_client_key(
        &self,
        id: Uuid,
        organization_id: Uuid,
        key_value: &str,
        label: Option<&str>,
        permissions: &[String],
        quota_limit: i32,
        client_origin: Option<&str>,
        client_scopes: Option<&[String]>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<ApiKeyRow> {
        let row = sqlx::query_as!(
            ApiKeyRow,
            r#"
            INSERT INTO api_keys (
                id, organization_id, key_value, key_type, label, permissions,
                quota_limit, usage_count, status, client_origin, client_scopes,
                expires_at, created_at, updated_at
            ) VALUES ($1, $2, $3, 'client', $4, $5, $6, 0, 'active', $7, $8, $9, NOW(), NOW())
            RETURNING *
            "#,
            id,
            organization_id,
            key_value,
            label,
            permissions,
            quota_limit,
            client_origin,
            client_scopes,
            expires_at
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    pub async fn insert_server_key(
        &self,
        id: Uuid,
        organization_id: Uuid,
        key_value: &str,
        label: Option<&str>,
        permissions: &[String],
        quota_limit: i32,
        server_endpoint: &str,
        server_region: Option<&str>,
    ) -> Result<ApiKeyRow> {
        let row = sqlx::query_as!(
            ApiKeyRow,
            r#"
            INSERT INTO api_keys (
                id, organization_id, key_value, key_type, label, permissions,
                quota_limit, usage_count, status, server_endpoint, server_region,
                created_at, updated_at
            ) VALUES ($1, $2, $3, 'server', $4, $5, $6, 0, 'active', $7, $8, NOW(), NOW())
            RETURNING *
            "#,
            id,
            organization_id,
            key_value,
            label,
            permissions,
            quota_limit,
            server_endpoint,
            server_region
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    pub async fn insert_database_key(
        &self,
        id: Uuid,
        organization_id: Uuid,
        key_value: &str,
        label: Option<&str>,
        permissions: &[String],
        quota_limit: i32,
        db_type: &DatabaseType,
        db_host: &str,
        db_port: i32,
        db_name: &str,
        db_username: &str,
        db_password_encrypted: &str,
    ) -> Result<ApiKeyRow> {
        let row = sqlx::query_as!(
            ApiKeyRow,
            r#"
            INSERT INTO api_keys (
                id, organization_id, key_value, key_type, label, permissions,
                quota_limit, usage_count, status, db_type, db_host, db_port,
                db_name, db_username, db_password_encrypted, created_at, updated_at
            ) VALUES ($1, $2, $3, 'database', $4, $5, $6, 0, 'active', $7, $8, $9, $10, $11, $12, NOW(), NOW())
            RETURNING *
            "#,
            id,
            organization_id,
            key_value,
            label,
            permissions,
            quota_limit,
            db_type.to_string(),
            db_host,
            db_port,
            db_name,
            db_username,
            db_password_encrypted
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    // ============================================================================
    // Update Queries
    // ============================================================================

    pub async fn update_key(
        &self,
        id: Uuid,
        organization_id: Uuid,
        label: Option<Option<&str>>,
        permissions: Option<&[String]>,
        quota_limit: Option<i32>,
        status: Option<&KeyStatus>,
        client_origin: Option<Option<&str>>,
        client_scopes: Option<&[String]>,
        server_endpoint: Option<Option<&str>>,
        server_region: Option<Option<&str>>,
        expires_at: Option<Option<DateTime<Utc>>>,
    ) -> Result<Option<ApiKeyRow>> {
        let row = sqlx::query_as!(
            ApiKeyRow,
            r#"
            UPDATE api_keys 
            SET 
                label = COALESCE($3, label),
                permissions = COALESCE($4, permissions),
                quota_limit = COALESCE($5, quota_limit),
                status = COALESCE($6, status),
                client_origin = COALESCE($7, client_origin),
                client_scopes = COALESCE($8, client_scopes),
                server_endpoint = COALESCE($9, server_endpoint),
                server_region = COALESCE($10, server_region),
                expires_at = COALESCE($11, expires_at),
                updated_at = NOW()
            WHERE id = $1 AND organization_id = $2
            RETURNING *
            "#,
            id,
            organization_id,
            label,
            permissions,
            quota_limit,
            status.as_ref().map(|s| s.to_string()),
            client_origin,
            client_scopes,
            server_endpoint,
            server_region,
            expires_at
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    pub async fn update_usage_count(&self, id: Uuid) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE api_keys 
            SET usage_count = usage_count + 1, last_used_at = NOW()
            WHERE id = $1
            "#,
            id
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn update_status(&self, id: Uuid, organization_id: Uuid, status: &KeyStatus) -> Result<bool> {
        let result = sqlx::query!(
            r#"
            UPDATE api_keys 
            SET status = $1, updated_at = NOW()
            WHERE id = $2 AND organization_id = $3
            "#,
            status.to_string(),
            id,
            organization_id
        )
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    // ============================================================================
    // Delete Queries
    // ============================================================================

    pub async fn delete_by_id(&self, id: Uuid, organization_id: Uuid) -> Result<bool> {
        let result = sqlx::query!(
            r#"
            DELETE FROM api_keys 
            WHERE id = $1 AND organization_id = $2
            "#,
            id,
            organization_id
        )
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    pub async fn delete_expired_keys(&self, before_date: DateTime<Utc>) -> Result<u64> {
        let result = sqlx::query!(
            r#"
            DELETE FROM api_keys 
            WHERE expires_at IS NOT NULL AND expires_at < $1
            "#,
            before_date
        )
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    // ============================================================================
    // Statistics Queries
    // ============================================================================

    pub async fn count_by_organization(&self, organization_id: Uuid) -> Result<i64> {
        let count = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as count FROM api_keys 
            WHERE organization_id = $1
            "#,
            organization_id
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(count.unwrap_or(0))
    }

    pub async fn count_by_organization_and_type(&self, organization_id: Uuid, key_type: &KeyType) -> Result<i64> {
        let count = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as count FROM api_keys 
            WHERE organization_id = $1 AND key_type = $2
            "#,
            organization_id,
            key_type.to_string()
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(count.unwrap_or(0))
    }

    pub async fn count_by_organization_and_status(&self, organization_id: Uuid, status: &KeyStatus) -> Result<i64> {
        let count = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as count FROM api_keys 
            WHERE organization_id = $1 AND status = $2
            "#,
            organization_id,
            status.to_string()
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(count.unwrap_or(0))
    }

    pub async fn get_usage_today(&self, organization_id: Uuid) -> Result<i64> {
        let usage = sqlx::query_scalar!(
            r#"
            SELECT COALESCE(SUM(usage_count), 0) as total FROM api_keys 
            WHERE organization_id = $1 AND DATE(last_used_at) = CURRENT_DATE
            "#,
            organization_id
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(usage.unwrap_or(0))
    }

    pub async fn get_top_used_keys(&self, organization_id: Uuid, limit: i64) -> Result<Vec<ApiKeyRow>> {
        let rows = sqlx::query_as!(
            ApiKeyRow,
            r#"
            SELECT * FROM api_keys 
            WHERE organization_id = $1 AND status = 'active'
            ORDER BY usage_count DESC, last_used_at DESC
            LIMIT $2
            "#,
            organization_id,
            limit
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    // ============================================================================
    // Advanced Queries
    // ============================================================================

    pub async fn find_keys_near_quota_limit(&self, organization_id: Uuid, threshold_percent: f64) -> Result<Vec<ApiKeyRow>> {
        let rows = sqlx::query_as!(
            ApiKeyRow,
            r#"
            SELECT * FROM api_keys 
            WHERE organization_id = $1 
            AND status = 'active'
            AND quota_limit > 0
            AND (usage_count::float / quota_limit::float) >= $2
            ORDER BY (usage_count::float / quota_limit::float) DESC
            "#,
            organization_id,
            threshold_percent / 100.0
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    pub async fn find_expired_keys(&self) -> Result<Vec<ApiKeyRow>> {
        let rows = sqlx::query_as!(
            ApiKeyRow,
            r#"
            SELECT * FROM api_keys 
            WHERE expires_at IS NOT NULL 
            AND expires_at < NOW()
            AND status != 'expired'
            ORDER BY expires_at ASC
            "#
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    pub async fn find_inactive_keys(&self, days_inactive: i32) -> Result<Vec<ApiKeyRow>> {
        let rows = sqlx::query_as!(
            ApiKeyRow,
            r#"
            SELECT * FROM api_keys 
            WHERE (last_used_at IS NULL OR last_used_at < NOW() - INTERVAL '1 day' * $1)
            AND status = 'active'
            ORDER BY last_used_at ASC NULLS FIRST
            "#,
            days_inactive
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    // ============================================================================
    // Database-specific Queries
    // ============================================================================

    pub async fn find_database_keys_by_type(&self, db_type: &DatabaseType) -> Result<Vec<ApiKeyRow>> {
        let rows = sqlx::query_as!(
            ApiKeyRow,
            r#"
            SELECT * FROM api_keys 
            WHERE key_type = 'database' 
            AND db_type = $1
            AND status = 'active'
            ORDER BY created_at DESC
            "#,
            db_type.to_string()
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    pub async fn test_database_connection(&self, key_id: Uuid) -> Result<bool> {
        // This would implement actual database connection testing
        // For now, just check if the key exists and is a database key
        let row = sqlx::query!(
            r#"
            SELECT id FROM api_keys 
            WHERE id = $1 AND key_type = 'database' AND status = 'active'
            "#,
            key_id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.is_some())
    }
}