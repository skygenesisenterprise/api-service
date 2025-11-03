// PowerAdmin zone templates table schema
pub mod dsl {
    pub struct PoweradminZoneTemplates;
    
    impl PoweradminZoneTemplates {
        pub fn table() -> &'static str {
            "api_service.poweradmin_zone_templates"
        }
        
        pub fn all_columns() -> &'static str {
            "id, name, description, template_data, created_at, updated_at, created_by, updated_by"
        }
        
        pub fn id() -> &'static str {
            "id"
        }
        
        pub fn name() -> &'static str {
            "name"
        }
        
        pub fn description() -> &'static str {
            "description"
        }
        
        pub fn template_data() -> &'static str {
            "template_data"
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