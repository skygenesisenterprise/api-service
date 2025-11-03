// PowerAdmin operation logs table schema
pub mod dsl {
    pub struct PoweradminOperationLogs;
    
    impl PoweradminOperationLogs {
        pub fn table() -> &'static str {
            "api_service.poweradmin_operation_logs"
        }
        
        pub fn all_columns() -> &'static str {
            "id, zone_id, record_id, operation, user_id, timestamp, details, old_values, new_values"
        }
        
        pub fn id() -> &'static str {
            "id"
        }
        
        pub fn zone_id() -> &'static str {
            "zone_id"
        }
        
        pub fn record_id() -> &'static str {
            "record_id"
        }
        
        pub fn operation() -> &'static str {
            "operation"
        }
        
        pub fn user_id() -> &'static str {
            "user_id"
        }
        
        pub fn timestamp() -> &'static str {
            "timestamp"
        }
        
        pub fn details() -> &'static str {
            "details"
        }
        
        pub fn old_values() -> &'static str {
            "old_values"
        }
        
        pub fn new_values() -> &'static str {
            "new_values"
        }
    }
}