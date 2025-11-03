// Grafana audit logs table schema
pub mod dsl {
    pub struct GrafanaAuditLogs;
    
    impl GrafanaAuditLogs {
        pub fn table() -> &'static str {
            "api_service.grafana_audit_logs"
        }
        
        pub fn all_columns() -> &'static str {
            "id, org_id, user_id, action, created_at, new_state, previous_state, scope, scope_id"
        }
        
        pub fn id() -> &'static str {
            "id"
        }
        
        pub fn org_id() -> &'static str {
            "org_id"
        }
        
        pub fn user_id() -> &'static str {
            "user_id"
        }
        
        pub fn action() -> &'static str {
            "action"
        }
        
        pub fn created_at() -> &'static str {
            "created_at"
        }
        
        pub fn new_state() -> &'static str {
            "new_state"
        }
        
        pub fn previous_state() -> &'static str {
            "previous_state"
        }
        
        pub fn scope() -> &'static str {
            "scope"
        }
        
        pub fn scope_id() -> &'static str {
            "scope_id"
        }
    }
}