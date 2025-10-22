use diesel::prelude::*;
use std::error::Error;
use uuid::Uuid;

use crate::models::organization::{Organization, NewOrganization, UpdateOrganization};
use crate::utils::db::{DbPool, DbPooledConnection};

pub struct OrganizationService;

impl OrganizationService {
    pub fn create_organization(
        conn: &mut DbPooledConnection,
        name: &str,
        country_code: Option<&str>,
    ) -> Result<Organization, Box<dyn Error>> {
        let new_org = NewOrganization { name, country_code };
        diesel::insert_into(crate::models::schema::organizations::table)
            .values(&new_org)
            .get_result(conn)
            .map_err(|e| Box::new(e) as Box<dyn Error>)
    }

    pub fn get_organization(
        conn: &mut DbPooledConnection,
        org_id: Uuid,
    ) -> Result<Organization, Box<dyn Error>> {
        use crate::models::schema::organizations::dsl::*;
        organizations.find(org_id).first(conn).map_err(|e| Box::new(e) as Box<dyn Error>)
    }

    pub fn get_all_organizations(
        conn: &mut DbPooledConnection,
    ) -> Result<Vec<Organization>, Box<dyn Error>> {
        use crate::models::schema::organizations::dsl::*;
        organizations.load(conn).map_err(|e| Box::new(e) as Box<dyn Error>)
    }

    pub fn update_organization(
        conn: &mut DbPooledConnection,
        org_id: Uuid,
        update: UpdateOrganization,
    ) -> Result<Organization, Box<dyn Error>> {
        use crate::models::schema::organizations::dsl::*;
        diesel::update(organizations.find(org_id))
            .set(&update)
            .get_result(conn)
            .map_err(|e| Box::new(e) as Box<dyn Error>)
    }

    pub fn delete_organization(
        conn: &mut DbPooledConnection,
        org_id: Uuid,
    ) -> Result<(), Box<dyn Error>> {
        use crate::models::schema::organizations::dsl::*;
        diesel::delete(organizations.find(org_id))
            .execute(conn)
            .map(|_| ())
            .map_err(|e| Box::new(e) as Box<dyn Error>)
    }
}