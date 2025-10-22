use diesel::prelude::*;
use std::error::Error;
use uuid::Uuid;
use bcrypt::{hash, verify, DEFAULT_COST};
use diesel::sql_types::Text;

use crate::models::data_source::{DataSource, NewDataSource, UpdateDataSource};
use crate::utils::db::{DbPool, DbPooledConnection};

pub struct DataSourceService;

impl DataSourceService {
    pub fn create_data_source(
        conn: &mut DbPooledConnection,
        name: &str,
        db_type: &str,
        host: &str,
        port: i32,
        database_name: &str,
        username: &str,
        password: &str,
        organization_id: Uuid,
        status: &str,
    ) -> Result<DataSource, Box<dyn Error>> {
        let password_hash = hash(password, DEFAULT_COST)?;
        let new_ds = NewDataSource {
            name,
            db_type,
            host,
            port,
            database_name,
            username,
            password_hash: &password_hash,
            organization_id,
            status,
        };
        diesel::insert_into(crate::models::schema::data_sources::table)
            .values(&new_ds)
            .get_result(conn)
            .map_err(|e| Box::new(e) as Box<dyn Error>)
    }

    pub fn get_data_source(
        conn: &mut DbPooledConnection,
        ds_id: Uuid,
    ) -> Result<DataSource, Box<dyn Error>> {
        use crate::models::schema::data_sources::dsl::*;
        data_sources.find(ds_id).first(conn).map_err(|e| Box::new(e) as Box<dyn Error>)
    }

    pub fn get_data_sources_by_organization(
        conn: &mut DbPooledConnection,
        org_id: Uuid,
    ) -> Result<Vec<DataSource>, Box<dyn Error>> {
        use crate::models::schema::data_sources::dsl::*;
        data_sources.filter(organization_id.eq(org_id)).load(conn).map_err(|e| Box::new(e) as Box<dyn Error>)
    }

    pub fn update_data_source(
        conn: &mut DbPooledConnection,
        ds_id: Uuid,
        update: UpdateDataSource,
    ) -> Result<DataSource, Box<dyn Error>> {
        use crate::models::schema::data_sources::dsl::*;
        diesel::update(data_sources.find(ds_id))
            .set(&update)
            .get_result(conn)
            .map_err(|e| Box::new(e) as Box<dyn Error>)
    }

    pub fn delete_data_source(
        conn: &mut DbPooledConnection,
        ds_id: Uuid,
    ) -> Result<(), Box<dyn Error>> {
        use crate::models::schema::data_sources::dsl::*;
        diesel::delete(data_sources.find(ds_id))
            .execute(conn)
            .map(|_| ())
            .map_err(|e| Box::new(e) as Box<dyn Error>)
    }

    // Méthode pour exécuter une requête SQL sur la data source (simplifié pour l'exemple)
    pub async fn execute_query(
        ds: &DataSource,
        query: &str,
        _params: Vec<String>,
    ) -> Result<String, Box<dyn Error>> {
        // Pour sécurité, limiter à SELECT
        if !query.trim().to_uppercase().starts_with("SELECT") {
            return Err("Only SELECT queries allowed".into());
        }

        // Simulation : retourner un message de succès
        // En production, implémenter la connexion réelle et exécution sécurisée
        Ok(format!("Query executed on {}: {}", ds.name, query))
    }
}