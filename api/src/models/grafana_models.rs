// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Grafana Models
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | SENSITIVE
//  MISSION: Define data structures and models for Grafana integration,
//  providing type-safe representations of dashboards, datasources, alerts,
//  and monitoring configurations within the enterprise infrastructure.
//  NOTICE: Models implement serialization, validation, and type safety for
//  all Grafana-related data structures with enterprise security standards.
//  MODEL STANDARDS: Type Safety, Serialization, Validation, Documentation
//  COMPLIANCE: Data Protection, Type Safety, API Standards
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// [GRAFANA DASHBOARD MODEL] Complete Dashboard Representation
/// @MISSION Define the structure of a Grafana dashboard.
/// @THREAT Inconsistent dashboard data structures.
/// @COUNTERMEASURE Standardized dashboard model with validation.
/// @AUDIT Dashboard models used for audit logging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrafanaDashboard {
    pub id: Option<i64>,
    pub uid: Option<String>,
    pub title: String,
    pub tags: Vec<String>,
    pub timezone: String,
    pub panels: Vec<GrafanaPanel>,
    pub time: GrafanaTimeRange,
    pub timepicker: Option<GrafanaTimePicker>,
    pub templating: GrafanaTemplating,
    pub annotations: GrafanaAnnotations,
    pub refresh: String,
    pub schema_version: i32,
    pub version: i32,
    pub links: Vec<GrafanaLink>,
}

/// [GRAFANA PANEL MODEL] Individual Dashboard Panel
/// @MISSION Define the structure of a dashboard panel.
/// @THREAT Malformed panel configurations.
/// @COUNTERMEASURE Structured panel model with type safety.
/// @AUDIT Panel configurations audited.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrafanaPanel {
    pub id: Option<i64>,
    pub title: String,
    #[serde(rename = "type")]
    pub panel_type: String,
    pub grid_pos: GrafanaGridPos,
    pub targets: Vec<GrafanaTarget>,
    pub field_config: Option<GrafanaFieldConfig>,
    pub options: Option<serde_json::Value>,
    pub transformations: Vec<GrafanaTransformation>,
    pub transparent: bool,
}

/// [GRAFANA TARGET MODEL] Data Query Target
/// @MISSION Define data query structures for panels.
/// @THREAT Invalid query configurations.
/// @COUNTERMEASURE Type-safe query model.
/// @AUDIT Query targets validated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrafanaTarget {
    pub ref_id: String,
    pub query_type: String,
    pub relative_time_range: Option<GrafanaTimeRange>,
    pub datasource_uid: String,
    pub model: GrafanaQueryModel,
}

/// [GRAFANA QUERY MODEL] Query Configuration
/// @MISSION Define query model structures.
/// @THREAT Query injection or malformed queries.
/// @COUNTERMEASURE Structured query models.
/// @AUDIT Query models validated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrafanaQueryModel {
    pub expr: String,
    pub legend_format: String,
    pub interval: Option<String>,
    pub interval_factor: Option<i32>,
    pub format: Option<String>,
    pub instant: Option<bool>,
    pub range: Option<bool>,
}

/// [GRAFANA DATASOURCE MODEL] Datasource Configuration
/// @MISSION Define datasource connection parameters.
/// @THREAT Exposed credentials or misconfigurations.
/// @COUNTERMEASURE Secure datasource model.
/// @AUDIT Datasource configurations audited.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrafanaDatasource {
    pub id: Option<i64>,
    pub uid: Option<String>,
    pub name: String,
    #[serde(rename = "type")]
    pub datasource_type: String,
    pub url: String,
    pub access: String, // "proxy" or "direct"
    pub basic_auth: Option<bool>,
    pub basic_auth_user: Option<String>,
    pub secure_json_data: Option<HashMap<String, String>>,
    pub json_data: Option<serde_json::Value>,
    pub is_default: bool,
    pub read_only: bool,
}

/// [GRAFANA ALERT RULE MODEL] Alert Rule Definition
/// @MISSION Define alert rule structures.
/// @THREAT Incorrect alert configurations.
/// @COUNTERMEASURE Structured alert rules.
/// @AUDIT Alert rules validated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrafanaAlertRule {
    pub id: Option<i64>,
    pub uid: Option<String>,
    pub title: String,
    pub condition: String,
    pub data: Vec<GrafanaAlertQuery>,
    pub no_data_state: String,
    pub exec_err_state: String,
    pub for_duration: String,
    pub annotations: HashMap<String, String>,
    pub labels: HashMap<String, String>,
    pub is_paused: bool,
}

/// [GRAFANA ALERT QUERY MODEL] Alert Query Structure
/// @MISSION Define alert query structures.
/// @THREAT Malformed alert queries.
/// @COUNTERMEASURE Type-safe alert queries.
/// @AUDIT Alert queries validated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrafanaAlertQuery {
    pub ref_id: String,
    pub query_type: String,
    pub relative_time_range: GrafanaTimeRange,
    pub datasource_uid: String,
    pub model: GrafanaQueryModel,
}

/// [GRAFANA FOLDER MODEL] Dashboard Organization
/// @MISSION Define folder structures for organization.
/// @THREAT Unorganized dashboards.
/// @COUNTERMEASURE Folder-based organization.
/// @AUDIT Folder operations logged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrafanaFolder {
    pub id: Option<i64>,
    pub uid: Option<String>,
    pub title: String,
    pub url: Option<String>,
    pub has_acl: bool,
    pub can_save: bool,
    pub can_edit: bool,
    pub can_admin: bool,
    pub created_by: String,
    pub created: String,
    pub updated_by: String,
    pub updated: String,
    pub version: i32,
}

/// [GRAFANA USER MODEL] User Information
/// @MISSION Define user structures for Grafana.
/// @THREAT User data exposure.
/// @COUNTERMEASURE Secure user models.
/// @AUDIT User operations logged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrafanaUser {
    pub id: i64,
    pub email: String,
    pub name: String,
    pub login: String,
    pub theme: String,
    pub org_id: i64,
    pub is_grafana_admin: bool,
    pub is_disabled: bool,
    pub is_external: bool,
    pub auth_labels: Vec<String>,
    pub updated_at: String,
    pub created_at: String,
}

/// [GRAFANA ORGANIZATION MODEL] Organization Structure
/// @MISSION Define organization structures.
/// @THREAT Multi-tenant data leakage.
/// @COUNTERMEASURE Organization isolation.
/// @AUDIT Organization operations logged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrafanaOrganization {
    pub id: i64,
    pub name: String,
    pub address: GrafanaAddress,
}

/// [GRAFANA TEAM MODEL] Team Collaboration
/// @MISSION Define team structures for collaboration.
/// @THREAT Unauthorized team access.
/// @COUNTERMEASURE Team-based permissions.
/// @AUDIT Team operations logged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrafanaTeam {
    pub id: i64,
    pub org_id: i64,
    pub name: String,
    pub email: String,
    pub avatar_url: String,
    pub member_count: i64,
    pub permission: i32,
}

/// [GRAFANA PERMISSION MODEL] Access Control
/// @MISSION Define permission structures.
/// @THREAT Permission bypass.
/// @COUNTERMEASURE Granular permissions.
/// @AUDIT Permission changes logged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrafanaPermission {
    pub id: i64,
    pub role: String,
    pub permission: String,
    pub scope: String,
}

/// [UTILITY STRUCTURES] Supporting Data Structures
/// @MISSION Provide supporting structures for Grafana models.
/// @THREAT Incomplete model definitions.
/// @COUNTERMEASURE Comprehensive supporting structures.
/// @AUDIT Supporting structures validated.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrafanaGridPos {
    pub h: i32,
    pub w: i32,
    pub x: i32,
    pub y: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrafanaTimeRange {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrafanaTimePicker {
    pub refresh_intervals: Vec<String>,
    pub time_options: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrafanaTemplating {
    pub list: Vec<GrafanaTemplate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrafanaTemplate {
    pub name: String,
    pub r#type: String,
    pub datasource: Option<String>,
    pub query: Option<String>,
    pub options: Vec<GrafanaTemplateOption>,
    pub current: GrafanaTemplateOption,
    pub hide: i32,
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrafanaTemplateOption {
    pub text: String,
    pub value: String,
    pub selected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrafanaAnnotations {
    pub list: Vec<GrafanaAnnotation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrafanaAnnotation {
    pub name: String,
    pub datasource: String,
    pub enable: bool,
    pub hide: bool,
    pub icon_color: String,
    pub query: String,
    pub target: GrafanaTarget,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrafanaLink {
    pub title: String,
    pub r#type: String,
    pub url: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrafanaFieldConfig {
    pub defaults: GrafanaFieldConfigDefaults,
    pub overrides: Vec<GrafanaFieldConfigOverride>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrafanaFieldConfigDefaults {
    pub unit: String,
    pub decimals: Option<i32>,
    pub min: Option<f64>,
    pub max: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrafanaFieldConfigOverride {
    pub matcher: GrafanaMatcher,
    pub properties: Vec<GrafanaProperty>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrafanaMatcher {
    pub id: String,
    pub options: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrafanaProperty {
    pub id: String,
    pub value: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrafanaTransformation {
    pub id: String,
    pub options: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrafanaAddress {
    pub address1: String,
    pub address2: String,
    pub city: String,
    pub zip_code: String,
    pub state: String,
    pub country: String,
}

/// [VALIDATION TRAITS] Model Validation
/// @MISSION Provide validation for Grafana models.
/// @THREAT Invalid model data.
/// @COUNTERMEASURE Model validation traits.
/// @AUDIT Validation results logged.
pub trait GrafanaModelValidation {
    fn validate(&self) -> Result<(), GrafanaModelError>;
}

#[derive(Debug, Clone)]
pub enum GrafanaModelError {
    InvalidField(String),
    MissingRequiredField(String),
    InvalidFormat(String),
    ValidationError(String),
}

impl std::fmt::Display for GrafanaModelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GrafanaModelError::InvalidField(field) => write!(f, "Invalid field: {}", field),
            GrafanaModelError::MissingRequiredField(field) => write!(f, "Missing required field: {}", field),
            GrafanaModelError::InvalidFormat(format) => write!(f, "Invalid format: {}", format),
            GrafanaModelError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
        }
    }
}

impl std::error::Error for GrafanaModelError {}

impl GrafanaModelValidation for GrafanaDashboard {
    fn validate(&self) -> Result<(), GrafanaModelError> {
        if self.title.is_empty() {
            return Err(GrafanaModelError::MissingRequiredField("title".to_string()));
        }
        if self.panels.is_empty() {
            return Err(GrafanaModelError::ValidationError("Dashboard must have at least one panel".to_string()));
        }
        Ok(())
    }
}

impl GrafanaModelValidation for GrafanaDatasource {
    fn validate(&self) -> Result<(), GrafanaModelError> {
        if self.name.is_empty() {
            return Err(GrafanaModelError::MissingRequiredField("name".to_string()));
        }
        if self.datasource_type.is_empty() {
            return Err(GrafanaModelError::MissingRequiredField("type".to_string()));
        }
        if self.url.is_empty() {
            return Err(GrafanaModelError::MissingRequiredField("url".to_string()));
        }
        Ok(())
    }
}

impl GrafanaModelValidation for GrafanaAlertRule {
    fn validate(&self) -> Result<(), GrafanaModelError> {
        if self.title.is_empty() {
            return Err(GrafanaModelError::MissingRequiredField("title".to_string()));
        }
        if self.condition.is_empty() {
            return Err(GrafanaModelError::MissingRequiredField("condition".to_string()));
        }
        if self.data.is_empty() {
            return Err(GrafanaModelError::ValidationError("Alert rule must have at least one data query".to_string()));
        }
        Ok(())
    }
}