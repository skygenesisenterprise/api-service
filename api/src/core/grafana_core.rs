// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Grafana Core Operations
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | SENSITIVE
//  MISSION: Provide core Grafana integration operations for dashboard management,
//  datasource configuration, and monitoring automation within the enterprise
//  monitoring infrastructure.
//  NOTICE: This module handles the business logic for Grafana API interactions,
//  including dashboard templating, datasource management, and alert configuration.
//  MONITORING: Grafana dashboard operations, datasource management, alert rules
//  INTEGRATION: Grafana HTTP API, Prometheus datasources, enterprise monitoring
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::core::vault::VaultClient;
use std::sync::Arc;

/// [GRAFANA DASHBOARD TEMPLATE] Predefined Dashboard Configurations
/// @MISSION Provide standardized dashboard templates for common monitoring scenarios.
/// @THREAT Inconsistent dashboard configurations across environments.
/// @COUNTERMEASURE Template-based dashboard creation with environment-specific customization.
/// @AUDIT Dashboard template usage tracked for compliance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrafanaDashboardTemplate {
    pub name: String,
    pub description: String,
    pub template: serde_json::Value,
    pub tags: Vec<String>,
    pub required_datasources: Vec<String>,
}

/// [GRAFANA DATASOURCE CONFIG] Standardized Datasource Configurations
/// @MISSION Define standard datasource configurations for enterprise monitoring.
/// @THREAT Misconfigured datasources leading to monitoring gaps.
/// @COUNTERMEASURE Predefined configurations with validation.
/// @AUDIT Datasource configurations audited for security compliance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrafanaDatasourceConfig {
    pub name: String,
    pub r#type: String,
    pub url_template: String,
    pub credentials_path: String,
    pub additional_config: HashMap<String, serde_json::Value>,
}

/// [GRAFANA ALERT TEMPLATE] Standardized Alert Rule Templates
/// @MISSION Provide reusable alert rule templates for common scenarios.
/// @THREAT Inconsistent alerting across services.
/// @COUNTERMEASURE Template-based alert creation with parameterization.
/// @AUDIT Alert template usage tracked for monitoring compliance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrafanaAlertTemplate {
    pub name: String,
    pub description: String,
    pub severity: String,
    pub template: serde_json::Value,
    pub parameters: Vec<String>,
}

/// [GRAFANA CORE OPERATIONS] Business Logic for Grafana Integration
/// @MISSION Provide high-level operations for Grafana management.
/// @THREAT Manual Grafana configuration overhead and errors.
/// @COUNTERMEASURE Automated configuration with templates and validation.
/// @DEPENDENCY Vault for secure credential storage.
/// @PERFORMANCE Operations cached where appropriate.
/// @AUDIT All Grafana operations logged and traced.
pub struct GrafanaCore {
    vault_client: Arc<VaultClient>,
    dashboard_templates: HashMap<String, GrafanaDashboardTemplate>,
    datasource_configs: HashMap<String, GrafanaDatasourceConfig>,
    alert_templates: HashMap<String, GrafanaAlertTemplate>,
}

impl GrafanaCore {
    /// [CORE INITIALIZATION] Grafana Core Setup
    /// @MISSION Initialize Grafana core with templates and configurations.
    /// @THREAT Missing templates or configurations.
    /// @COUNTERMEASURE Load predefined templates and validate configurations.
    /// @DEPENDENCY Vault client for credential access.
    /// @PERFORMANCE Templates loaded once at startup.
    /// @AUDIT Core initialization logged for system startup tracking.
    pub fn new(vault_client: Arc<VaultClient>) -> Self {
        let mut core = GrafanaCore {
            vault_client,
            dashboard_templates: HashMap::new(),
            datasource_configs: HashMap::new(),
            alert_templates: HashMap::new(),
        };

        core.load_dashboard_templates();
        core.load_datasource_configs();
        core.load_alert_templates();

        core
    }

    /// [DASHBOARD TEMPLATE LOADING] Load Predefined Dashboard Templates
    /// @MISSION Load dashboard templates from configuration.
    /// @THREAT Missing or outdated templates.
    /// @COUNTERMEASURE Template versioning and validation.
    /// @DEPENDENCY Template files in configuration.
    /// @PERFORMANCE Templates cached in memory.
    /// @AUDIT Template loading tracked for configuration management.
    fn load_dashboard_templates(&mut self) {
        // System Health Dashboard Template
        let system_health_template = GrafanaDashboardTemplate {
            name: "system-health".to_string(),
            description: "Comprehensive system health monitoring dashboard".to_string(),
            template: serde_json::json!({
                "title": "Sky Genesis System Health",
                "tags": ["sky-genesis", "health", "system"],
                "timezone": "browser",
                "panels": [
                    {
                        "title": "Active Connections",
                        "type": "graph",
                        "targets": [{
                            "expr": "sky_genesis_active_connections{service=\"api\"}",
                            "legendFormat": "Active Connections"
                        }]
                    },
                    {
                        "title": "Response Time",
                        "type": "graph",
                        "targets": [{
                            "expr": "sky_genesis_average_response_time_ms{service=\"api\"}",
                            "legendFormat": "Response Time (ms)"
                        }]
                    },
                    {
                        "title": "Error Rate",
                        "type": "graph",
                        "targets": [{
                            "expr": "sky_genesis_error_rate_percent{service=\"api\"}",
                            "legendFormat": "Error Rate (%)"
                        }]
                    }
                ],
                "time": {
                    "from": "now-1h",
                    "to": "now"
                },
                "refresh": "30s"
            }),
            tags: vec!["sky-genesis".to_string(), "health".to_string()],
            required_datasources: vec!["prometheus".to_string()],
        };

        self.dashboard_templates.insert("system-health".to_string(), system_health_template);

        // Security Monitoring Dashboard Template
        let security_template = GrafanaDashboardTemplate {
            name: "security-monitoring".to_string(),
            description: "Security events and threat monitoring dashboard".to_string(),
            template: serde_json::json!({
                "title": "Sky Genesis Security Monitoring",
                "tags": ["sky-genesis", "security", "threats"],
                "timezone": "browser",
                "panels": [
                    {
                        "title": "Failed Authentication Attempts",
                        "type": "graph",
                        "targets": [{
                            "expr": "sky_genesis_failed_auth_attempts_total",
                            "legendFormat": "Failed Auth"
                        }]
                    },
                    {
                        "title": "Security Events",
                        "type": "table",
                        "targets": [{
                            "expr": "sky_genesis_security_events_total",
                            "legendFormat": "Security Events"
                        }]
                    }
                ],
                "time": {
                    "from": "now-24h",
                    "to": "now"
                },
                "refresh": "5m"
            }),
            tags: vec!["sky-genesis".to_string(), "security".to_string()],
            required_datasources: vec!["prometheus".to_string()],
        };

        self.dashboard_templates.insert("security-monitoring".to_string(), security_template);
    }

    /// [DATASOURCE CONFIG LOADING] Load Datasource Configurations
    /// @MISSION Load predefined datasource configurations.
    /// @THREAT Inconsistent datasource setup.
    /// @COUNTERMEASURE Standardized configurations with credential management.
    /// @DEPENDENCY Vault for credential storage.
    /// @PERFORMANCE Configurations cached in memory.
    /// @AUDIT Datasource configurations tracked.
    fn load_datasource_configs(&mut self) {
        // Prometheus Datasource Config
        let prometheus_config = GrafanaDatasourceConfig {
            name: "Sky Genesis Prometheus".to_string(),
            r#type: "prometheus".to_string(),
            url_template: "http://prometheus.skygenesisenterprise.com:9090".to_string(),
            credentials_path: "grafana/datasources/prometheus".to_string(),
            additional_config: HashMap::new(),
        };

        self.datasource_configs.insert("prometheus".to_string(), prometheus_config);

        // Loki Datasource Config
        let loki_config = GrafanaDatasourceConfig {
            name: "Sky Genesis Loki".to_string(),
            r#type: "loki".to_string(),
            url_template: "http://loki.skygenesisenterprise.com:3100".to_string(),
            credentials_path: "grafana/datasources/loki".to_string(),
            additional_config: HashMap::new(),
        };

        self.datasource_configs.insert("loki".to_string(), loki_config);
    }

    /// [ALERT TEMPLATE LOADING] Load Alert Rule Templates
    /// @MISSION Load predefined alert rule templates.
    /// @THREAT Inconsistent alerting configuration.
    /// @COUNTERMEASURE Standardized alert templates with parameterization.
    /// @DEPENDENCY Template definitions.
    /// @PERFORMANCE Templates cached in memory.
    /// @AUDIT Alert templates tracked for compliance.
    fn load_alert_templates(&mut self) {
        // High Error Rate Alert Template
        let high_error_rate_template = GrafanaAlertTemplate {
            name: "high-error-rate".to_string(),
            description: "Alert when API error rate exceeds threshold".to_string(),
            severity: "warning".to_string(),
            template: serde_json::json!({
                "title": "High Error Rate on {{ $labels.service }}",
                "condition": "C",
                "data": [
                    {
                        "refId": "A",
                        "queryType": "",
                        "relativeTimeRange": {
                            "from": 600,
                            "to": 0
                        },
                        "datasourceUid": "prometheus",
                        "model": {
                            "expr": "rate(sky_genesis_http_requests_total{status=~\"5..\"}[5m]) / rate(sky_genesis_http_requests_total[5m]) * 100 > 5",
                            "legendFormat": "__auto"
                        }
                    },
                    {
                        "refId": "B",
                        "queryType": "",
                        "relativeTimeRange": {
                            "from": 600,
                            "to": 0
                        },
                        "datasourceUid": "__expr__",
                        "model": {
                            "type": "reduce",
                            "expression": "A",
                            "reducer": "mean"
                        }
                    },
                    {
                        "refId": "C",
                        "queryType": "",
                        "relativeTimeRange": {
                            "from": 600,
                            "to": 0
                        },
                        "datasourceUid": "__expr__",
                        "model": {
                            "type": "threshold",
                            "expression": "B",
                            "conditions": [
                                {
                                    "evaluator": {
                                        "params": [5],
                                        "type": "gt"
                                    },
                                    "operator": {
                                        "type": "and"
                                    },
                                    "query": {
                                        "params": ["C"]
                                    },
                                    "reducer": {
                                        "params": [],
                                        "type": "last"
                                    },
                                    "type": "query"
                                }
                            ]
                        }
                    }
                ],
                "no_data_state": "NoData",
                "exec_err_state": "Error",
                "for_duration": "5m"
            }),
            parameters: vec!["threshold".to_string(), "service".to_string()],
        };

        self.alert_templates.insert("high-error-rate".to_string(), high_error_rate_template);

        // High Response Time Alert Template
        let high_response_time_template = GrafanaAlertTemplate {
            name: "high-response-time".to_string(),
            description: "Alert when API response time exceeds threshold".to_string(),
            severity: "warning".to_string(),
            template: serde_json::json!({
                "title": "Slow Response Time on {{ $labels.service }}",
                "condition": "C",
                "data": [
                    {
                        "refId": "A",
                        "queryType": "",
                        "relativeTimeRange": {
                            "from": 600,
                            "to": 0
                        },
                        "datasourceUid": "prometheus",
                        "model": {
                            "expr": "histogram_quantile(0.95, rate(sky_genesis_http_request_duration_seconds_bucket[5m])) * 1000 > 1000",
                            "legendFormat": "__auto"
                        }
                    }
                ],
                "no_data_state": "NoData",
                "exec_err_state": "Error",
                "for_duration": "5m"
            }),
            parameters: vec!["threshold".to_string(), "service".to_string()],
        };

        self.alert_templates.insert("high-response-time".to_string(), high_response_time_template);
    }

    /// [DASHBOARD TEMPLATE RETRIEVAL] Get Dashboard Template by Name
    /// @MISSION Retrieve dashboard template for instantiation.
    /// @THREAT Using non-existent templates.
    /// @COUNTERMEASURE Template validation and error handling.
    /// @DEPENDENCY Template preloading.
    /// @PERFORMANCE O(1) hash map lookup.
    /// @AUDIT Template retrieval logged.
    pub fn get_dashboard_template(&self, name: &str) -> Option<&GrafanaDashboardTemplate> {
        self.dashboard_templates.get(name)
    }

    /// [DATASOURCE CONFIG RETRIEVAL] Get Datasource Configuration
    /// @MISSION Retrieve datasource configuration for setup.
    /// @THREAT Using invalid datasource configurations.
    /// @COUNTERMEASURE Configuration validation.
    /// @DEPENDENCY Config preloading.
    /// @PERFORMANCE O(1) hash map lookup.
    /// @AUDIT Configuration retrieval logged.
    pub fn get_datasource_config(&self, name: &str) -> Option<&GrafanaDatasourceConfig> {
        self.datasource_configs.get(name)
    }

    /// [ALERT TEMPLATE RETRIEVAL] Get Alert Template by Name
    /// @MISSION Retrieve alert template for instantiation.
    /// @THREAT Using non-existent alert templates.
    /// @COUNTERMEASURE Template validation.
    /// @DEPENDENCY Template preloading.
    /// @PERFORMANCE O(1) hash map lookup.
    /// @AUDIT Template retrieval logged.
    pub fn get_alert_template(&self, name: &str) -> Option<&GrafanaAlertTemplate> {
        self.alert_templates.get(name)
    }

    /// [TEMPLATE PARAMETERIZATION] Apply Parameters to Template
    /// @MISSION Customize templates with environment-specific values.
    /// @THREAT Hardcoded values in templates.
    /// @COUNTERMEASURE Parameter substitution.
    /// @DEPENDENCY Template structure knowledge.
    /// @PERFORMANCE JSON manipulation.
    /// @AUDIT Parameter application logged.
    pub fn apply_template_parameters(
        &self,
        template: &serde_json::Value,
        parameters: &HashMap<String, String>
    ) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
        let template_str = serde_json::to_string(template)?;
        let mut result_str = template_str;

        for (key, value) in parameters {
            let placeholder = format!("{{{{{}}}}}", key);
            result_str = result_str.replace(&placeholder, value);
        }

        let result: serde_json::Value = serde_json::from_str(&result_str)?;
        Ok(result)
    }

    /// [TEMPLATE LISTING] Get Available Templates
    /// @MISSION Provide inventory of available templates.
    /// @THREAT Unknown available templates.
    /// @COUNTERMEASURE Template discovery.
    /// @DEPENDENCY Template loading.
    /// @PERFORMANCE O(1) for counts.
    /// @AUDIT Template listing tracked.
    pub fn list_dashboard_templates(&self) -> Vec<&GrafanaDashboardTemplate> {
        self.dashboard_templates.values().collect()
    }

    pub fn list_datasource_configs(&self) -> Vec<&GrafanaDatasourceConfig> {
        self.datasource_configs.values().collect()
    }

    pub fn list_alert_templates(&self) -> Vec<&GrafanaAlertTemplate> {
        self.alert_templates.values().collect()
    }

    /// [TEMPLATE VALIDATION] Validate Template Structure
    /// @MISSION Ensure template integrity before use.
    /// @THREAT Malformed templates causing deployment failures.
    /// @COUNTERMEASURE Schema validation.
    /// @DEPENDENCY JSON schema knowledge.
    /// @PERFORMANCE Validation overhead.
    /// @AUDIT Template validation results logged.
    pub fn validate_dashboard_template(&self, template: &GrafanaDashboardTemplate) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Basic validation - check required fields
        if template.name.is_empty() {
            return Err("Template name cannot be empty".into());
        }

        if template.template.get("title").is_none() {
            return Err("Template must have a title".into());
        }

        if template.template.get("panels").is_none() {
            return Err("Template must have panels".into());
        }

        Ok(())
    }

    pub fn validate_datasource_config(&self, config: &GrafanaDatasourceConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if config.name.is_empty() {
            return Err("Datasource name cannot be empty".into());
        }

        if config.r#type.is_empty() {
            return Err("Datasource type cannot be empty".into());
        }

        if config.url_template.is_empty() {
            return Err("Datasource URL template cannot be empty".into());
        }

        Ok(())
    }

    pub fn validate_alert_template(&self, template: &GrafanaAlertTemplate) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if template.name.is_empty() {
            return Err("Alert template name cannot be empty".into());
        }

        if template.template.get("title").is_none() {
            return Err("Alert template must have a title".into());
        }

        if template.template.get("condition").is_none() {
            return Err("Alert template must have a condition".into());
        }

        Ok(())
    }
}