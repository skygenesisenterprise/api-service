// Grafana dashboards table schema
pub mod dsl {
    use sqlx::postgres::PgRow;
    use sqlx::{Row, FromRow};
    
    pub struct GrafanaDashboards;
    
    impl GrafanaDashboards {
        pub fn table() -> &'static str {
            "api_service.grafana_dashboards"
        }
        
        pub fn all_columns() -> &'static str {
            "id, uid, title, slug, org_id, folder_id, created, updated, created_by, updated_by, version, data, schema_version"
        }
        
        pub fn id() -> &'static str {
            "id"
        }
        
        pub fn uid() -> &'static str {
            "uid"
        }
        
        pub fn title() -> &'static str {
            "title"
        }
        
        pub fn slug() -> &'static str {
            "slug"
        }
        
        pub fn org_id() -> &'static str {
            "org_id"
        }
        
        pub fn folder_id() -> &'static str {
            "folder_id"
        }
        
        pub fn created() -> &'static str {
            "created"
        }
        
        pub fn updated() -> &'static str {
            "updated"
        }
        
        pub fn created_by() -> &'static str {
            "created_by"
        }
        
        pub fn updated_by() -> &'static str {
            "updated_by"
        }
        
        pub fn version() -> &'static str {
            "version"
        }
        
        pub fn data() -> &'static str {
            "data"
        }
        
        pub fn schema_version() -> &'static str {
            "schema_version"
        }
    }
}