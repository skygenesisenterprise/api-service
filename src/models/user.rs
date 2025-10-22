use chrono::NaiveDateTime;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::schema::users;

#[derive(Queryable, Identifiable, Serialize, Deserialize, Debug)]
#[diesel(table_name = users)]
pub struct User {
    pub id: Uuid,
    pub organization_id: Option<Uuid>,
    pub email: String,
    pub full_name: Option<String>,
    pub password_hash: String,
    pub role: String,
    pub status: String,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Insertable, Deserialize, Debug)]
#[diesel(table_name = users)]
pub struct NewUser<'a> {
    pub organization_id: Option<Uuid>,
    pub email: &'a str,
    pub full_name: Option<&'a str>,
    pub password_hash: &'a str,
    pub role: &'a str,
    pub status: &'a str,
}

#[derive(AsChangeset, Deserialize, Debug)]
#[diesel(table_name = users)]
pub struct UpdateUser {
    pub full_name: Option<String>,
    pub role: Option<String>,
    pub status: Option<String>,
}