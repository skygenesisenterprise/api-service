use diesel::prelude::*;
use rand::Rng;
use std::error::Error;
use uuid::Uuid;

use crate::models::api_key::{ApiKey, NewApiKey, UpdateApiKey, ApiKeyResponse, ApiKeyInfo};
use crate::models::schema::api_keys;
use crate::utils::db::DbPooledConnection;

pub struct ApiKeyService;

impl ApiKeyService {
    pub fn validate_api_key(conn: &mut DbPooledConnection, api_key: &str) -> Result<ApiKey, Box<dyn Error>> {
        let key = api_keys::table
            .filter(api_keys::key_value.eq(api_key))
            .filter(api_keys::status.eq("active"))
            .first::<ApiKey>(conn)?;

        // Check quota
        if key.usage_count >= key.quota_limit {
            return Err("API quota exceeded".into());
        }

        // Increment usage count
        Self::increment_usage_count(conn, key.id)?;

        Ok(key)
    }

    pub fn increment_usage_count(conn: &mut DbPooledConnection, api_key_id: Uuid) -> Result<(), Box<dyn Error>> {
        diesel::update(api_keys::table.filter(api_keys::id.eq(api_key_id)))
            .set(api_keys::usage_count.eq(api_keys::usage_count + 1))
            .execute(conn)?;
        Ok(())
    }

    pub fn has_permission(api_key: &ApiKey, required_permission: &str) -> bool {
        api_key.permissions.contains(&"*".to_string()) ||
        api_key.permissions.contains(&required_permission.to_string())
    }

    pub fn create_api_key(
        conn: &mut DbPooledConnection,
        organization_id: Uuid,
        label: Option<&str>,
        permissions: Vec<String>,
    ) -> Result<ApiKeyResponse, Box<dyn Error>> {
        let key_value = Self::generate_api_key();

        let new_key = NewApiKey {
            organization_id,
            key_value: &key_value,
            label,
            permissions,
            quota_limit: 100000,
            status: "active",
        };

        let inserted_key = diesel::insert_into(api_keys::table)
            .values(&new_key)
            .get_result::<ApiKey>(conn)?;

        Ok(ApiKeyResponse {
            id: inserted_key.id,
            key_value: inserted_key.key_value,
            label: inserted_key.label,
            permissions: inserted_key.permissions,
            created_at: inserted_key.created_at,
        })
    }

    pub fn get_api_keys_for_organization(
        conn: &mut DbPooledConnection,
        organization_id: Uuid,
    ) -> Result<Vec<ApiKey>, Box<dyn Error>> {
        let keys = api_keys::table
            .filter(api_keys::organization_id.eq(organization_id))
            .order(api_keys::created_at.desc())
            .load::<ApiKey>(conn)?;
        Ok(keys)
    }

    pub fn revoke_api_key(
        conn: &mut DbPooledConnection,
        api_key_id: Uuid,
        organization_id: Uuid,
    ) -> Result<bool, Box<dyn Error>> {
        let count = diesel::update(
            api_keys::table
                .filter(api_keys::id.eq(api_key_id))
                .filter(api_keys::organization_id.eq(organization_id))
        )
        .set(api_keys::status.eq("revoked"))
        .execute(conn)?;

        Ok(count > 0)
    }

    fn generate_api_key() -> String {
        let mut rng = rand::thread_rng();
        let chars: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".chars().collect();
        let mut result = "sk_".to_string();

        for _ in 0..32 {
            let idx = rng.gen_range(0..chars.len());
            result.push(chars[idx]);
        }

        result
    }

    pub fn get_api_key_info(api_key: &ApiKey) -> ApiKeyInfo {
        ApiKeyInfo {
            organization_id: api_key.organization_id,
            permissions: api_key.permissions.clone(),
            quota_limit: api_key.quota_limit,
            usage_count: api_key.usage_count,
        }
    }
}