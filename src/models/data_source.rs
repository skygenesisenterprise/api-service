use chrono::NaiveDateTime;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::schema::data_sources;

#[derive(Queryable, Identifiable, Serialize, Deserialize, Debug)]
#[diesel(table_name = data_sources)]
pub struct DataSource {
    pub id: Uuid,
    pub name: String,
    pub db_type: String,
    pub host: String,
    pub port: i32,
    pub database_name: String,
    pub username: String,
    pub password_hash: String,
    pub organization_id: Uuid,
    pub status: String,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Insertable, Deserialize, Debug)]
#[diesel(table_name = data_sources)]
pub struct NewDataSource<'a> {
    pub name: &'a str,
    pub db_type: &'a str,
    pub host: &'a str,
    pub port: i32,
    pub database_name: &'a str,
    pub username: &'a str,
    pub password_hash: &'a str,
    pub organization_id: Uuid,
    pub status: &'a str,
}

#[derive(AsChangeset, Deserialize, Debug)]
#[diesel(table_name = data_sources)]
pub struct UpdateDataSource {
    pub name: Option<String>,
    pub db_type: Option<String>,
    pub host: Option<String>,
    pub port: Option<i32>,
    pub database_name: Option<String>,
    pub username: Option<String>,
    pub password_hash: Option<String>,
    pub status: Option<String>,
}