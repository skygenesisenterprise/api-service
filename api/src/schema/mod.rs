// Database schema module for SQLx queries
// This module provides database schema definitions for the API service

pub mod grafana_dashboards;
pub mod grafana_datasources;
pub mod grafana_alert_rules;
pub mod grafana_audit_logs;
pub mod grafana_templates;
pub mod poweradmin_zones;
pub mod poweradmin_records;
pub mod poweradmin_operation_logs;
pub mod poweradmin_zone_templates;

// Re-export all schema modules
pub use grafana_dashboards::*;
pub use grafana_datasources::*;
pub use grafana_alert_rules::*;
pub use grafana_audit_logs::*;
pub use grafana_templates::*;
pub use poweradmin_zones::*;
pub use poweradmin_records::*;
pub use poweradmin_operation_logs::*;
pub use poweradmin_zone_templates::*;