// PowerAdmin records table schema
pub mod dsl {
    pub struct PoweradminRecords;
    
    impl PoweradminRecords {
        pub fn table() -> &'static str {
            "api_service.poweradmin_records"
        }
        
        pub fn all_columns() -> &'static str {
            "id, zone_id, name, type, content, ttl, priority, created_at, updated_at, created_by, updated_by"
        }
        
        pub fn id() -> &'static str {
            "id"
        }
        
        pub fn zone_id() -> &'static str {
            "zone_id"
        }
        
        pub fn name() -> &'static str {
            "name"
        }
        
        pub fn type_field() -> &'static str {
            "type"
        }
        
        pub fn content() -> &'static str {
            "content"
        }
        
        pub fn ttl() -> &'static str {
            "ttl"
        }
        
        pub fn priority() -> &'static str {
            "priority"
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