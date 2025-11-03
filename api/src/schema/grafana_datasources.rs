// Grafana datasources table schema
pub mod dsl {
    pub struct GrafanaDatasources;
    
    impl GrafanaDatasources {
        pub fn table() -> &'static str {
            "api_service.grafana_datasources"
        }
        
        pub fn all_columns() -> &'static str {
            "id, uid, org_id, name, type, access, url, database, user, password, secure_json_data, basic_auth, basic_auth_user, basic_auth_password, is_default, json_data, created, updated"
        }
        
        pub fn id() -> &'static str {
            "id"
        }
        
        pub fn uid() -> &'static str {
            "uid"
        }
        
        pub fn org_id() -> &'static str {
            "org_id"
        }
        
        pub fn name() -> &'static str {
            "name"
        }
        
        pub fn type_field() -> &'static str {
            "type"
        }
        
        pub fn access() -> &'static str {
            "access"
        }
        
        pub fn url() -> &'static str {
            "url"
        }
        
        pub fn database() -> &'static str {
            "database"
        }
        
        pub fn user() -> &'static str {
            "user"
        }
        
        pub fn password() -> &'static str {
            "password"
        }
        
        pub fn secure_json_data() -> &'static str {
            "secure_json_data"
        }
        
        pub fn basic_auth() -> &'static str {
            "basic_auth"
        }
        
        pub fn basic_auth_user() -> &'static str {
            "basic_auth_user"
        }
        
        pub fn basic_auth_password() -> &'static str {
            "basic_auth_password"
        }
        
        pub fn is_default() -> &'static str {
            "is_default"
        }
        
        pub fn json_data() -> &'static str {
            "json_data"
        }
        
        pub fn created() -> &'static str {
            "created"
        }
        
        pub fn updated() -> &'static str {
            "updated"
        }
    }
}