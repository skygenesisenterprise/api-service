// PowerAdmin zones table schema
pub mod dsl {
    pub struct PoweradminZones;
    
    impl PoweradminZones {
        pub fn table() -> &'static str {
            "api_service.poweradmin_zones"
        }
        
        pub fn all_columns() -> &'static str {
            "id, name, domain, type, master, serial, refresh, retry, expire, minimum, created_at, updated_at, created_by, updated_by"
        }
        
        pub fn id() -> &'static str {
            "id"
        }
        
        pub fn name() -> &'static str {
            "name"
        }
        
        pub fn domain() -> &'static str {
            "domain"
        }
        
        pub fn type_field() -> &'static str {
            "type"
        }
        
        pub fn master() -> &'static str {
            "master"
        }
        
        pub fn serial() -> &'static str {
            "serial"
        }
        
        pub fn refresh() -> &'static str {
            "refresh"
        }
        
        pub fn retry() -> &'static str {
            "retry"
        }
        
        pub fn expire() -> &'static str {
            "expire"
        }
        
        pub fn minimum() -> &'static str {
            "minimum"
        }
        
        pub fn created_at() -> &'static str {
            "created_at"
        }
        
        pub fn updated_at() -> &'static str {
            "updated_at"
        }
        
        pub fn created_by() -> &'static str {
            "created_by"
        }
        
        pub fn updated_by() -> &'static str {
            "updated_by"
        }
    }
}