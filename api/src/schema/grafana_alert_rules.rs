// Grafana alert rules table schema
pub mod dsl {
    pub struct GrafanaAlertRules;
    
    impl GrafanaAlertRules {
        pub fn table() -> &'static str {
            "api_service.grafana_alert_rules"
        }
        
        pub fn all_columns() -> &'static str {
            "id, uid, org_id, folder_id, title, condition, data, no_data_state, exec_err_state, for_interval, annotations, labels, created, updated"
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
        
        pub fn folder_id() -> &'static str {
            "folder_id"
        }
        
        pub fn title() -> &'static str {
            "title"
        }
        
        pub fn condition() -> &'static str {
            "condition"
        }
        
        pub fn data() -> &'static str {
            "data"
        }
        
        pub fn no_data_state() -> &'static str {
            "no_data_state"
        }
        
        pub fn exec_err_state() -> &'static str {
            "exec_err_state"
        }
        
        pub fn for_interval() -> &'static str {
            "for_interval"
        }
        
        pub fn annotations() -> &'static str {
            "annotations"
        }
        
        pub fn labels() -> &'static str {
            "labels"
        }
        
        pub fn created() -> &'static str {
            "created"
        }
        
        pub fn updated() -> &'static str {
            "updated"
        }
    }
}