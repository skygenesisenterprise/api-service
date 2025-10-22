use chrono::NaiveDateTime;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::schema::api_keys;

#[derive(Queryable, Identifiable, Serialize, Deserialize, Debug, Clone)]
#[diesel(table_name = api_keys)]
pub struct ApiKey {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub key_value: String,
    pub label: Option<String>,
    pub permissions: Vec<String>,
    pub quota_limit: i32,
    pub usage_count: i32,
    pub status: String,
    pub public_key: Option<String>,
    pub private_key: Option<String>,
    pub created_at: NaiveDateTime,
}

#[derive(Insertable, Deserialize, Debug)]
#[diesel(table_name = api_keys)]
pub struct NewApiKey<'a> {
    pub organization_id: Uuid,
    pub key_value: &'a str,
    pub label: Option<&'a str>,
    pub permissions: Vec<String>,
    pub quota_limit: i32,
    pub status: &'a str,
    pub public_key: Option<&'a str>,
    pub private_key: Option<&'a str>,
}

#[derive(AsChangeset, Deserialize, Debug)]
#[diesel(table_name = api_keys)]
pub struct UpdateApiKey {
    pub status: Option<String>,
    pub usage_count: Option<i32>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiKeyResponse {
    pub id: Uuid,
    pub key_value: String,
    pub label: Option<String>,
    pub permissions: Vec<String>,
    pub public_key: Option<String>,
    pub created_at: NaiveDateTime,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiKeyInfo {
    pub organization_id: Uuid,
    pub permissions: Vec<String>,
    pub quota_limit: i32,
    pub usage_count: i32,
}