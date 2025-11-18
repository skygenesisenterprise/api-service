// ============================================================================
// Sky Genesis Enterprise API - API Key Service
// ============================================================================

use crate::models::api_keys::{
    ApiKey, ApiKeyRow, ApiKeyResponse, ApiKeySecretResponse,
    CreateClientKeyRequest, CreateServerKeyRequest, CreateDatabaseKeyRequest,
    UpdateApiKeyRequest, KeyType, KeyStatus, DatabaseType, ApiKeyStats, ApiKeyUsageSummary
};
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;
use std::sync::Arc;
use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose};
use rand::Rng;

// ============================================================================
// API Key Service
// ============================================================================

pub struct ApiKeyService {
    db: Arc<PgPool>,
}

impl ApiKeyService {
    pub fn new(db: Arc<PgPool>) -> Self {
        Self { db }
    }

    // ============================================================================
    // Key Generation Utilities
    // ============================================================================

    fn generate_key_value(key_type: &KeyType) -> String {
        let prefix = match key_type {
            KeyType::Client => "sk_client",
            KeyType::Server => "sk_server", 
            KeyType::Database => "sk_db",
        };
        
        let random_bytes: [u8; 24] = rand::thread_rng().gen();
        let random_part = general_purpose::STANDARD.encode(random_bytes);
        
        format!("{}_{}", prefix, random_part)
    }

    // ============================================================================
    // Create API Keys
    // ============================================================================

    pub async fn create_client_key(
        &self,
        organization_id: Uuid,
        request: CreateClientKeyRequest,
    ) -> Result<(ApiKeyResponse, ApiKeySecretResponse)> {
        let key_value = Self::generate_key_value(&KeyType::Client);
        let key_id = Uuid::new_v4();
        let now = Utc::now();

        let api_key = ApiKey {
            id: key_id,
            organization_id,
            key_value: key_value.clone(),
            key_type: KeyType::Client,
            label: Some(request.label),
            permissions: request.permissions.clone(),
            quota_limit: request.quota_limit.unwrap_or(100000),
            usage_count: 0,
            status: KeyStatus::Active,
            public_key: None,
            private_key: None,
            certificate_type: None,
            certificate_fingerprint: None,
            private_key_path: None,
            db_type: None,
            db_host: None,
            db_port: None,
            db_name: None,
            db_username: None,
            db_password_encrypted: None,
            server_endpoint: None,
            server_region: None,
            client_origin: request.client_origin,
            client_scopes: request.client_scopes,
            expires_at: request.expires_at,
            last_used_at: None,
            created_at: now,
            updated_at: now,
        };

        // Save to database
        sqlx::query!(
            r#"
            INSERT INTO api_keys (
                id, organization_id, key_value, key_type, label, permissions,
                quota_limit, usage_count, status, client_origin, client_scopes,
                expires_at, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            "#,
            api_key.id,
            api_key.organization_id,
            api_key.key_value,
            api_key.key_type.to_string(),
            api_key.label,
            &api_key.permissions,
            api_key.quota_limit,
            api_key.usage_count,
            api_key.status.to_string(),
            api_key.client_origin,
            &api_key.client_scopes,
            api_key.expires_at,
            api_key.created_at,
            api_key.updated_at
        )
        .execute(&*self.db)
        .await?;

        let response = ApiKeyResponse {
            id: api_key.id,
            key_value: api_key.key_value.clone(),
            key_type: api_key.key_type,
            label: api_key.label,
            permissions: api_key.permissions,
            quota_limit: api_key.quota_limit,
            usage_count: api_key.usage_count,
            status: api_key.status,
            created_at: api_key.created_at,
            expires_at: api_key.expires_at,
            server_endpoint: None,
            server_region: None,
            db_type: None,
            db_host: None,
            client_origin: api_key.client_origin,
            client_scopes: api_key.client_scopes,
        };

        let secret_response = ApiKeySecretResponse {
            id: api_key.id,
            key_value: api_key.key_value,
            private_key: None,
            db_password: None,
        };

        Ok((response, secret_response))
    }

    pub async fn create_server_key(
        &self,
        organization_id: Uuid,
        request: CreateServerKeyRequest,
    ) -> Result<(ApiKeyResponse, ApiKeySecretResponse)> {
        let key_value = Self::generate_key_value(&KeyType::Server);
        let key_id = Uuid::new_v4();
        let now = Utc::now();

        let api_key = ApiKey {
            id: key_id,
            organization_id,
            key_value: key_value.clone(),
            key_type: KeyType::Server,
            label: Some(request.label),
            permissions: request.permissions.clone(),
            quota_limit: request.quota_limit.unwrap_or(1000000),
            usage_count: 0,
            status: KeyStatus::Active,
            public_key: None,
            private_key: None,
            certificate_type: None,
            certificate_fingerprint: None,
            private_key_path: None,
            db_type: None,
            db_host: None,
            db_port: None,
            db_name: None,
            db_username: None,
            db_password_encrypted: None,
            server_endpoint: Some(request.server_endpoint),
            server_region: request.server_region,
            client_origin: None,
            client_scopes: None,
            expires_at: None,
            last_used_at: None,
            created_at: now,
            updated_at: now,
        };

        // Save to database
        sqlx::query!(
            r#"
            INSERT INTO api_keys (
                id, organization_id, key_value, key_type, label, permissions,
                quota_limit, usage_count, status, server_endpoint, server_region,
                created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            "#,
            api_key.id,
            api_key.organization_id,
            api_key.key_value,
            api_key.key_type.to_string(),
            api_key.label,
            &api_key.permissions,
            api_key.quota_limit,
            api_key.usage_count,
            api_key.status.to_string(),
            api_key.server_endpoint,
            api_key.server_region,
            api_key.created_at,
            api_key.updated_at
        )
        .execute(&*self.db)
        .await?;

        let response = ApiKeyResponse {
            id: api_key.id,
            key_value: api_key.key_value.clone(),
            key_type: api_key.key_type,
            label: api_key.label,
            permissions: api_key.permissions,
            quota_limit: api_key.quota_limit,
            usage_count: api_key.usage_count,
            status: api_key.status,
            created_at: api_key.created_at,
            expires_at: api_key.expires_at,
            server_endpoint: api_key.server_endpoint,
            server_region: api_key.server_region,
            db_type: None,
            db_host: None,
            client_origin: None,
            client_scopes: None,
        };

        let secret_response = ApiKeySecretResponse {
            id: api_key.id,
            key_value: api_key.key_value,
            private_key: None,
            db_password: None,
        };

        Ok((response, secret_response))
    }

    pub async fn create_database_key(
        &self,
        organization_id: Uuid,
        request: CreateDatabaseKeyRequest,
    ) -> Result<(ApiKeyResponse, ApiKeySecretResponse)> {
        let key_value = Self::generate_key_value(&KeyType::Database);
        let key_id = Uuid::new_v4();
        let now = Utc::now();

        // Encrypt the database password (for now, simple encoding - in production use proper encryption)
        let db_password_encrypted = general_purpose::STANDARD.encode(request.db_password.as_bytes());

        let api_key = ApiKey {
            id: key_id,
            organization_id,
            key_value: key_value.clone(),
            key_type: KeyType::Database,
            label: Some(request.label),
            permissions: request.permissions.clone(),
            quota_limit: request.quota_limit.unwrap_or(500000),
            usage_count: 0,
            status: KeyStatus::Active,
            public_key: None,
            private_key: None,
            certificate_type: None,
            certificate_fingerprint: None,
            private_key_path: None,
            db_type: Some(request.db_type.clone()),
            db_host: Some(request.db_host),
            db_port: Some(request.db_port),
            db_name: Some(request.db_name),
            db_username: Some(request.db_username),
            db_password_encrypted: Some(db_password_encrypted),
            server_endpoint: None,
            server_region: None,
            client_origin: None,
            client_scopes: None,
            expires_at: None,
            last_used_at: None,
            created_at: now,
            updated_at: now,
        };

        // Save to database
        sqlx::query!(
            r#"
            INSERT INTO api_keys (
                id, organization_id, key_value, key_type, label, permissions,
                quota_limit, usage_count, status, db_type, db_host, db_port,
                db_name, db_username, db_password_encrypted, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
            "#,
            api_key.id,
            api_key.organization_id,
            api_key.key_value,
            api_key.key_type.to_string(),
            api_key.label,
            &api_key.permissions,
            api_key.quota_limit,
            api_key.usage_count,
            api_key.status.to_string(),
            api_key.db_type.as_ref().map(|t| t.to_string()),
            api_key.db_host,
            api_key.db_port,
            api_key.db_name,
            api_key.db_username,
            api_key.db_password_encrypted,
            api_key.created_at,
            api_key.updated_at
        )
        .execute(&*self.db)
        .await?;

        let response = ApiKeyResponse {
            id: api_key.id,
            key_value: api_key.key_value.clone(),
            key_type: api_key.key_type,
            label: api_key.label,
            permissions: api_key.permissions,
            quota_limit: api_key.quota_limit,
            usage_count: api_key.usage_count,
            status: api_key.status,
            created_at: api_key.created_at,
            expires_at: api_key.expires_at,
            server_endpoint: None,
            server_region: None,
            db_type: api_key.db_type,
            db_host: api_key.db_host,
            client_origin: None,
            client_scopes: None,
        };

        let secret_response = ApiKeySecretResponse {
            id: api_key.id,
            key_value: api_key.key_value,
            private_key: None,
            db_password: Some(request.db_password), // Return original password only once
        };

        Ok((response, secret_response))
    }

    // ============================================================================
    // Read Operations
    // ============================================================================

    pub async fn get_key_by_id(&self, key_id: Uuid, organization_id: Uuid) -> Result<Option<ApiKey>> {
        let row = sqlx::query_as!(
            ApiKeyRow,
            r#"
            SELECT * FROM api_keys 
            WHERE id = $1 AND organization_id = $2
            "#,
            key_id,
            organization_id
        )
        .fetch_optional(&*self.db)
        .await?;

        Ok(row.map(ApiKey::from))
    }

    pub async fn get_key_by_value(&self, key_value: &str) -> Result<Option<ApiKey>> {
        let row = sqlx::query_as!(
            ApiKeyRow,
            r#"
            SELECT * FROM api_keys 
            WHERE key_value = $1
            "#,
            key_value
        )
        .fetch_optional(&*self.db)
        .await?;

        Ok(row.map(ApiKey::from))
    }

    pub async fn list_keys(&self, organization_id: Uuid, key_type: Option<KeyType>) -> Result<Vec<ApiKey>> {
        let rows = if let Some(key_type) = key_type {
            sqlx::query_as!(
                ApiKeyRow,
                r#"
                SELECT * FROM api_keys 
                WHERE organization_id = $1 AND key_type = $2
                ORDER BY created_at DESC
                "#,
                organization_id,
                key_type.to_string()
            )
            .fetch_all(&*self.db)
            .await?
        } else {
            sqlx::query_as!(
                ApiKeyRow,
                r#"
                SELECT * FROM api_keys 
                WHERE organization_id = $1
                ORDER BY created_at DESC
                "#,
                organization_id
            )
            .fetch_all(&*self.db)
            .await?
        };

        Ok(rows.into_iter().map(ApiKey::from).collect())
    }

    // ============================================================================
    // Update Operations
    // ============================================================================

    pub async fn update_key(
        &self,
        key_id: Uuid,
        organization_id: Uuid,
        request: UpdateApiKeyRequest,
    ) -> Result<Option<ApiKey>> {
        // Build dynamic update query
        let mut query = "UPDATE api_keys SET updated_at = NOW()".to_string();
        let mut params = Vec::new();
        let mut param_count = 3; // Start from $3 since $1=key_id, $2=organization_id

        if let Some(label) = &request.label {
            query.push_str(&format!(", label = ${}", param_count));
            params.push(label.as_str());
            param_count += 1;
        }

        if let Some(permissions) = &request.permissions {
            query.push_str(&format!(", permissions = ${}", param_count));
            params.push(&permissions);
            param_count += 1;
        }

        if let Some(quota_limit) = request.quota_limit {
            query.push_str(&format!(", quota_limit = ${}", param_count));
            params.push(&quota_limit.to_string());
            param_count += 1;
        }

        if let Some(status) = &request.status {
            query.push_str(&format!(", status = ${}", param_count));
            params.push(&status.to_string());
            param_count += 1;
        }

        if let Some(client_origin) = &request.client_origin {
            query.push_str(&format!(", client_origin = ${}", param_count));
            params.push(client_origin.as_str());
            param_count += 1;
        }

        if let Some(client_scopes) = &request.client_scopes {
            query.push_str(&format!(", client_scopes = ${}", param_count));
            params.push(&client_scopes);
            param_count += 1;
        }

        if let Some(server_endpoint) = &request.server_endpoint {
            query.push_str(&format!(", server_endpoint = ${}", param_count));
            params.push(server_endpoint.as_str());
            param_count += 1;
        }

        if let Some(server_region) = &request.server_region {
            query.push_str(&format!(", server_region = ${}", param_count));
            params.push(server_region.as_str());
            param_count += 1;
        }

        if let Some(expires_at) = request.expires_at {
            query.push_str(&format!(", expires_at = ${}", param_count));
            params.push(&expires_at.to_string());
            param_count += 1;
        }

        query.push_str(&format!(" WHERE id = $1 AND organization_id = $2 RETURNING *"));

        // Execute the dynamic query (simplified approach - in production use query builder)
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
            key_id,
            organization_id,
            request.label,
            &request.permissions,
            request.quota_limit,
            request.status.as_ref().map(|s| s.to_string()),
            request.client_origin,
            &request.client_scopes,
            request.server_endpoint,
            request.server_region,
            request.expires_at
        )
        .fetch_optional(&*self.db)
        .await?;

        Ok(row.map(ApiKey::from))
    }

    // ============================================================================
    // Delete Operations
    // ============================================================================

    pub async fn revoke_key(&self, key_id: Uuid, organization_id: Uuid) -> Result<bool> {
        let result = sqlx::query!(
            r#"
            UPDATE api_keys 
            SET status = 'revoked', updated_at = NOW()
            WHERE id = $1 AND organization_id = $2
            "#,
            key_id,
            organization_id
        )
        .execute(&*self.db)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    pub async fn delete_key(&self, key_id: Uuid, organization_id: Uuid) -> Result<bool> {
        let result = sqlx::query!(
            r#"
            DELETE FROM api_keys 
            WHERE id = $1 AND organization_id = $2
            "#,
            key_id,
            organization_id
        )
        .execute(&*self.db)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    // ============================================================================
    // Usage Tracking
    // ============================================================================

    pub async fn increment_usage(&self, key_id: Uuid) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE api_keys 
            SET usage_count = usage_count + 1, last_used_at = NOW()
            WHERE id = $1
            "#,
            key_id
        )
        .execute(&*self.db)
        .await?;

        Ok(())
    }

    // ============================================================================
    // Statistics
    // ============================================================================

    pub async fn get_stats(&self, organization_id: Uuid) -> Result<ApiKeyStats> {
        let total_keys = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as count FROM api_keys 
            WHERE organization_id = $1
            "#,
            organization_id
        )
        .fetch_one(&*self.db)
        .await?
        .unwrap_or(0);

        let active_keys = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as count FROM api_keys 
            WHERE organization_id = $1 AND status = 'active'
            "#,
            organization_id
        )
        .fetch_one(&*self.db)
        .await?
        .unwrap_or(0);

        let client_keys = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as count FROM api_keys 
            WHERE organization_id = $1 AND key_type = 'client'
            "#,
            organization_id
        )
        .fetch_one(&*self.db)
        .await?
        .unwrap_or(0);

        let server_keys = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as count FROM api_keys 
            WHERE organization_id = $1 AND key_type = 'server'
            "#,
            organization_id
        )
        .fetch_one(&*self.db)
        .await?
        .unwrap_or(0);

        let database_keys = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as count FROM api_keys 
            WHERE organization_id = $1 AND key_type = 'database'
            "#,
            organization_id
        )
        .fetch_one(&*self.db)
        .await?
        .unwrap_or(0);

        let total_usage_today = sqlx::query_scalar!(
            r#"
            SELECT COALESCE(SUM(usage_count), 0) as total FROM api_keys 
            WHERE organization_id = $1 AND DATE(last_used_at) = CURRENT_DATE
            "#,
            organization_id
        )
        .fetch_one(&*self.db)
        .await?
        .unwrap_or(0);

        let top_used_keys_rows = sqlx::query_as!(
            ApiKeyRow,
            r#"
            SELECT * FROM api_keys 
            WHERE organization_id = $1 AND status = 'active'
            ORDER BY usage_count DESC, last_used_at DESC
            LIMIT 10
            "#,
            organization_id
        )
        .fetch_all(&*self.db)
        .await?;

        let top_used_keys = top_used_keys_rows
            .into_iter()
            .map(|row| ApiKeyUsageSummary {
                id: row.id,
                label: row.label,
                key_type: match row.key_type.as_str() {
                    "client" => KeyType::Client,
                    "server" => KeyType::Server,
                    "database" => KeyType::Database,
                    _ => KeyType::Client,
                },
                usage_count: row.usage_count,
                last_used_at: row.last_used_at,
            })
            .collect();

        Ok(ApiKeyStats {
            total_keys,
            active_keys,
            client_keys,
            server_keys,
            database_keys,
            total_usage_today,
            top_used_keys,
        })
    }
}