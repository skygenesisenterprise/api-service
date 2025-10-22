use diesel::prelude::*;
use std::error::Error;
use uuid::Uuid;

use crate::models::user::{User, NewUser, UpdateUser};
use crate::utils::db::{DbPool, DbPooledConnection};

pub struct UserService;

impl UserService {
    pub fn create_user(
        conn: &mut DbPooledConnection,
        organization_id: Option<Uuid>,
        email: &str,
        full_name: Option<&str>,
        password_hash: &str,
        role: &str,
        status: &str,
    ) -> Result<User, Box<dyn Error>> {
        let new_user = NewUser {
            organization_id,
            email,
            full_name,
            password_hash,
            role,
            status,
        };
        diesel::insert_into(crate::models::schema::users::table)
            .values(&new_user)
            .get_result(conn)
            .map_err(|e| Box::new(e) as Box<dyn Error>)
    }

    pub fn get_user(
        conn: &mut DbPooledConnection,
        user_id: Uuid,
    ) -> Result<User, Box<dyn Error>> {
        use crate::models::schema::users::dsl::*;
        users.find(user_id).first(conn).map_err(|e| Box::new(e) as Box<dyn Error>)
    }

    pub fn get_user_by_email(
        conn: &mut DbPooledConnection,
        user_email: &str,
    ) -> Result<User, Box<dyn Error>> {
        use crate::models::schema::users::dsl::*;
        users.filter(email.eq(user_email)).first(conn).map_err(|e| Box::new(e) as Box<dyn Error>)
    }

    pub fn get_users_by_organization(
        conn: &mut DbPooledConnection,
        org_id: Uuid,
    ) -> Result<Vec<User>, Box<dyn Error>> {
        use crate::models::schema::users::dsl::*;
        users.filter(organization_id.eq(org_id)).load(conn).map_err(|e| Box::new(e) as Box<dyn Error>)
    }

    pub fn update_user(
        conn: &mut DbPooledConnection,
        user_id: Uuid,
        update: UpdateUser,
    ) -> Result<User, Box<dyn Error>> {
        use crate::models::schema::users::dsl::*;
        diesel::update(users.find(user_id))
            .set(&update)
            .get_result(conn)
            .map_err(|e| Box::new(e) as Box<dyn Error>)
    }

    pub fn delete_user(
        conn: &mut DbPooledConnection,
        user_id: Uuid,
    ) -> Result<(), Box<dyn Error>> {
        use crate::models::schema::users::dsl::*;
        diesel::delete(users.find(user_id))
            .execute(conn)
            .map(|_| ())
            .map_err(|e| Box::new(e) as Box<dyn Error>)
    }
}