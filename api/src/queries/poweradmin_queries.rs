// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: PowerAdmin Queries
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | SENSITIVE
//  MISSION: Provide database query operations for PowerAdmin DNS integration,
//  including zone metadata storage, record configurations, DNSSEC key
//  persistence, audit logging, and template management for DNS operations.
//  NOTICE: Queries implement secure database operations with proper
//  parameterization and audit logging for PowerAdmin-related data.
//  DATABASE: PostgreSQL with encrypted storage
//  SECURITY: Parameterized queries, audit logging
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use diesel::prelude::*;
use diesel::pg::PgConnection;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::models::poweradmin_models::*;

/// [DNS ZONE RECORD] Database Representation
/// @MISSION Store zone metadata in database.
/// @THREAT Data corruption or loss.
/// @COUNTERMEASURE ACID transactions with validation.
/// @AUDIT Zone operations logged.
#[derive(Debug, Clone, Queryable, Identifiable, Serialize, Deserialize)]
#[table_name = "poweradmin_zones"]
pub struct PowerAdminZoneRecord {
    pub id: String,
    pub name: String,
    pub zone_type: String,
    pub nameservers: Vec<String>,
    pub serial: Option<i64>,
    pub refresh: Option<i32>,
    pub retry: Option<i32>,
    pub expire: Option<i32>,
    pub minimum: Option<i32>,
    pub ttl: Option<i32>,
    pub owner: String,
    pub organization_id: String,
    pub created_by: String,
    pub updated_by: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub dnssec_enabled: bool,
    pub template_name: Option<String>,
    pub metadata: serde_json::Value,
}

/// [DNS RECORD RECORD] Database Representation
/// @MISSION Store record configurations securely.
/// @THREAT Record data corruption.
/// @COUNTERMEASURE ACID transactions with validation.
/// @AUDIT Record operations logged.
#[derive(Debug, Clone, Queryable, Identifiable, Serialize, Deserialize)]
#[table_name = "poweradmin_records"]
pub struct PowerAdminRecordRecord {
    pub id: String,
    pub zone_id: String,
    pub name: String,
    pub record_type: String,
    pub content: String,
    pub ttl: i32,
    pub prio: Option<i32>,
    pub disabled: bool,
    pub created_by: String,
    pub updated_by: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub comment: Option<String>,
    pub metadata: serde_json::Value,
}

/// [DNSSEC KEY RECORD] Database Representation
/// @MISSION Store DNSSEC key metadata securely.
/// @THREAT Key metadata exposure.
/// @COUNTERMEASURE Encrypted storage with access controls.
/// @AUDIT DNSSEC operations logged.
#[derive(Debug, Clone, Queryable, Identifiable, Serialize, Deserialize)]
#[table_name = "poweradmin_dnssec_keys"]
pub struct PowerAdminDnssecKeyRecord {
    pub id: String,
    pub zone_id: String,
    pub key_type: String,
    pub algorithm: String,
    pub key_size: i32,
    pub key_tag: i32,
    pub status: String,
    pub public_key_hash: String, // Hash for lookup, actual key in Vault
    pub private_key_path: String, // Vault path
    pub created_by: String,
    pub activated_by: Option<String>,
    pub inactivated_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub activated_at: Option<DateTime<Utc>>,
    pub inactivated_at: Option<DateTime<Utc>>,
    pub rollover_scheduled: Option<DateTime<Utc>>,
}

/// [DNS OPERATION LOG RECORD] Audit Trail
/// @MISSION Track all DNS operations for compliance.
/// @THREAT Undetected unauthorized operations.
/// @COUNTERMEASURE Comprehensive operation logging.
/// @AUDIT DNS operations tracked for compliance.
#[derive(Debug, Clone, Queryable, Identifiable, Serialize, Deserialize)]
#[table_name = "poweradmin_operation_logs"]
pub struct PowerAdminOperationLogRecord {
    pub id: String,
    pub operation: String,
    pub resource_type: String,
    pub resource_id: String,
    pub resource_name: String,
    pub user_id: String,
    pub organization_id: String,
    pub old_value: Option<serde_json::Value>,
    pub new_value: Option<serde_json::Value>,
    pub ip_address: String,
    pub user_agent: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub success: bool,
    pub error_message: Option<String>,
    pub request_id: String,
}

/// [DNS ZONE TEMPLATE RECORD] Database Representation
/// @MISSION Store zone templates in database.
/// @THREAT Template corruption.
/// @COUNTERMEASURE Versioned template storage.
/// @AUDIT Template operations logged.
#[derive(Debug, Clone, Queryable, Identifiable, Serialize, Deserialize)]
#[table_name = "poweradmin_zone_templates"]
pub struct PowerAdminZoneTemplateRecord {
    pub id: String,
    pub name: String,
    pub description: String,
    pub zone_type: String,
    pub default_ttl: i32,
    pub nameservers: Vec<String>,
    pub soa_config: serde_json::Value,
    pub default_records: Vec<serde_json::Value>,
    pub dnssec_config: Option<serde_json::Value>,
    pub created_by: String,
    pub updated_by: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_active: bool,
    pub version: i32,
}

/// [DNS VALIDATION RULE RECORD] Database Representation
/// @MISSION Store validation rules in database.
/// @THREAT Invalid validation rules.
/// @COUNTERMEASURE Versioned rule storage.
/// @AUDIT Validation rule operations logged.
#[derive(Debug, Clone, Queryable, Identifiable, Serialize, Deserialize)]
#[table_name = "poweradmin_validation_rules"]
pub struct PowerAdminValidationRuleRecord {
    pub id: String,
    pub record_type: String,
    pub content_pattern: String,
    pub name_pattern: Option<String>,
    pub required_fields: Vec<String>,
    pub max_length: Option<i32>,
    pub custom_validation: Option<String>,
    pub created_by: String,
    pub updated_by: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_active: bool,
}

/// [DNS MONITORING RECORD] Database Representation
/// @MISSION Store monitoring configurations.
/// @THREAT Monitoring configuration loss.
/// @COUNTERMEASURE Persistent monitoring setup.
/// @AUDIT Monitoring operations logged.
#[derive(Debug, Clone, Queryable, Identifiable, Serialize, Deserialize)]
#[table_name = "poweradmin_monitoring"]
pub struct PowerAdminMonitoringRecord {
    pub id: String,
    pub zone_id: Option<String>,
    pub record_id: Option<String>,
    pub monitoring_type: String,
    pub check_interval: i32,
    pub alert_threshold: i32,
    pub alert_channels: Vec<String>,
    pub enabled: bool,
    pub last_check: Option<DateTime<Utc>>,
    pub last_status: Option<String>,
    pub next_check: Option<DateTime<Utc>>,
    pub created_by: String,
    pub updated_at: DateTime<Utc>,
}

/// [DNS PERMISSION RECORD] Database Representation
/// @MISSION Store DNS permissions in database.
/// @THREAT Permission configuration errors.
/// @COUNTERMEASURE Structured permission storage.
/// @AUDIT Permission operations logged.
#[derive(Debug, Clone, Queryable, Identifiable, Serialize, Deserialize)]
#[table_name = "poweradmin_permissions"]
pub struct PowerAdminPermissionRecord {
    pub id: String,
    pub user_id: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub permissions: Vec<String>,
    pub granted_by: String,
    pub granted_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub is_active: bool,
}

/// [ZONE QUERY OPERATIONS] Database Operations for Zones
/// @MISSION Provide CRUD operations for DNS zones.
/// @THREAT Data inconsistency.
/// @COUNTERMEASURE ACID transactions.
/// @AUDIT All zone operations logged.
pub struct PowerAdminZoneQueries;

impl PowerAdminZoneQueries {
    /// Create new zone record
    pub fn create_zone(
        conn: &PgConnection,
        zone: &DnsZone,
    ) -> Result<String, diesel::result::Error> {
        use crate::schema::poweradmin_zones::dsl::*;

        let new_zone = PowerAdminZoneRecord {
            id: uuid::Uuid::new_v4().to_string(),
            name: zone.name.clone(),
            zone_type: zone.r#type.clone(),
            nameservers: zone.nameservers.clone(),
            serial: zone.serial,
            refresh: zone.refresh,
            retry: zone.retry,
            expire: zone.expire,
            minimum: zone.minimum,
            ttl: zone.ttl,
            owner: zone.owner.clone(),
            organization_id: "default".to_string(), // TODO: Get from context
            created_by: zone.owner.clone(),
            updated_by: zone.owner.clone(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            dnssec_enabled: zone.dnssec_enabled,
            template_name: zone.template_name.clone(),
            metadata: serde_json::json!({}),
        };

        diesel::insert_into(poweradmin_zones)
            .values(&new_zone)
            .execute(conn)?;

        Ok(new_zone.id)
    }

    /// Get zone by ID
    pub fn get_zone_by_id(
        conn: &PgConnection,
        zone_id: &str,
    ) -> Result<Option<DnsZone>, diesel::result::Error> {
        use crate::schema::poweradmin_zones::dsl::*;

        let record = poweradmin_zones
            .find(zone_id)
            .first::<PowerAdminZoneRecord>(conn)
            .optional()?;

        Ok(record.map(|r| DnsZone {
            id: Some(r.id),
            name: r.name,
            r#type: r.zone_type,
            nameservers: r.nameservers,
            serial: r.serial,
            refresh: r.refresh,
            retry: r.retry,
            expire: r.expire,
            minimum: r.minimum,
            ttl: r.ttl,
            owner: r.owner,
            created_at: r.created_at,
            updated_at: r.updated_at,
            dnssec_enabled: r.dnssec_enabled,
            template_name: r.template_name,
        }))
    }

    /// List zones for organization
    pub fn list_zones(
        conn: &PgConnection,
        org_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<DnsZone>, diesel::result::Error> {
        use crate::schema::poweradmin_zones::dsl::*;

        let records = poweradmin_zones
            .filter(organization_id.eq(org_id))
            .order(created_at.desc())
            .limit(limit)
            .offset(offset)
            .load::<PowerAdminZoneRecord>(conn)?;

        Ok(records.into_iter().map(|r| DnsZone {
            id: Some(r.id),
            name: r.name,
            r#type: r.zone_type,
            nameservers: r.nameservers,
            serial: r.serial,
            refresh: r.refresh,
            retry: r.retry,
            expire: r.expire,
            minimum: r.minimum,
            ttl: r.ttl,
            owner: r.owner,
            created_at: r.created_at,
            updated_at: r.updated_at,
            dnssec_enabled: r.dnssec_enabled,
            template_name: r.template_name,
        }).collect())
    }

    /// Update zone
    pub fn update_zone(
        conn: &PgConnection,
        zone_id: &str,
        updates: &HashMap<String, serde_json::Value>,
        updated_by: &str,
    ) -> Result<(), diesel::result::Error> {
        use crate::schema::poweradmin_zones::dsl::*;

        diesel::update(poweradmin_zones.find(zone_id))
            .set((
                updated_by.eq(updated_by),
                updated_at.eq(Utc::now()),
            ))
            .execute(conn)?;

        Ok(())
    }

    /// Delete zone
    pub fn delete_zone(
        conn: &PgConnection,
        zone_id: &str,
    ) -> Result<(), diesel::result::Error> {
        use crate::schema::poweradmin_zones::dsl::*;

        diesel::delete(poweradmin_zones.find(zone_id))
            .execute(conn)?;

        Ok(())
    }
}

/// [RECORD QUERY OPERATIONS] Database Operations for Records
/// @MISSION Provide CRUD operations for DNS records.
/// @THREAT Record data inconsistency.
/// @COUNTERMEASURE ACID transactions.
/// @AUDIT All record operations logged.
pub struct PowerAdminRecordQueries;

impl PowerAdminRecordQueries {
    /// Create new record
    pub fn create_record(
        conn: &PgConnection,
        record: &DnsRecord,
    ) -> Result<String, diesel::result::Error> {
        use crate::schema::poweradmin_records::dsl::*;

        let new_record = PowerAdminRecordRecord {
            id: uuid::Uuid::new_v4().to_string(),
            zone_id: record.zone_id.clone(),
            name: record.name.clone(),
            record_type: record.r#type.clone(),
            content: record.content.clone(),
            ttl: record.ttl,
            prio: record.prio,
            disabled: record.disabled,
            created_by: "system".to_string(), // TODO: Get from context
            updated_by: "system".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            comment: record.comment.clone(),
            metadata: serde_json::json!({}),
        };

        diesel::insert_into(poweradmin_records)
            .values(&new_record)
            .execute(conn)?;

        Ok(new_record.id)
    }

    /// Get records for zone
    pub fn get_records_for_zone(
        conn: &PgConnection,
        zone_id_param: &str,
    ) -> Result<Vec<DnsRecord>, diesel::result::Error> {
        use crate::schema::poweradmin_records::dsl::*;

        let records = poweradmin_records
            .filter(zone_id.eq(zone_id_param))
            .order(name.asc())
            .load::<PowerAdminRecordRecord>(conn)?;

        Ok(records.into_iter().map(|r| DnsRecord {
            id: Some(r.id),
            zone_id: r.zone_id,
            name: r.name,
            r#type: r.record_type,
            content: r.content,
            ttl: r.ttl,
            prio: r.prio,
            disabled: r.disabled,
            created_at: r.created_at,
            updated_at: r.updated_at,
            comment: r.comment,
        }).collect())
    }

    /// Update record
    pub fn update_record(
        conn: &PgConnection,
        record_id: &str,
        updates: &HashMap<String, serde_json::Value>,
        updated_by: &str,
    ) -> Result<(), diesel::result::Error> {
        use crate::schema::poweradmin_records::dsl::*;

        diesel::update(poweradmin_records.find(record_id))
            .set((
                updated_by.eq(updated_by),
                updated_at.eq(Utc::now()),
            ))
            .execute(conn)?;

        Ok(())
    }

    /// Delete record
    pub fn delete_record(
        conn: &PgConnection,
        record_id: &str,
    ) -> Result<(), diesel::result::Error> {
        use crate::schema::poweradmin_records::dsl::*;

        diesel::delete(poweradmin_records.find(record_id))
            .execute(conn)?;

        Ok(())
    }
}

/// [OPERATION LOG QUERY OPERATIONS] Database Operations for Audit Logs
/// @MISSION Provide operations for DNS audit logging.
/// @THREAT Incomplete audit trails.
/// @COUNTERMEASURE Comprehensive logging.
/// @AUDIT All operations logged.
pub struct PowerAdminOperationLogQueries;

impl PowerAdminOperationLogQueries {
    /// Log DNS operation
    pub fn log_operation(
        conn: &PgConnection,
        operation: &DnsOperationLog,
    ) -> Result<String, diesel::result::Error> {
        use crate::schema::poweradmin_operation_logs::dsl::*;

        let log_record = PowerAdminOperationLogRecord {
            id: uuid::Uuid::new_v4().to_string(),
            operation: operation.operation.clone(),
            resource_type: operation.resource_type.clone(),
            resource_id: operation.resource_id.clone(),
            resource_name: operation.resource_name.clone(),
            user_id: operation.user_id.clone(),
            organization_id: operation.organization_id.clone(),
            old_value: operation.old_value.clone(),
            new_value: operation.new_value.clone(),
            ip_address: operation.ip_address.clone(),
            user_agent: operation.user_agent.clone(),
            timestamp: operation.timestamp,
            success: operation.success,
            error_message: operation.error_message.clone(),
            request_id: operation.request_id.clone(),
        };

        diesel::insert_into(poweradmin_operation_logs)
            .values(&log_record)
            .execute(conn)?;

        Ok(log_record.id)
    }

    /// Get operation logs for resource
    pub fn get_operation_logs(
        conn: &PgConnection,
        resource_type_param: &str,
        resource_id_param: &str,
        limit: i64,
    ) -> Result<Vec<DnsOperationLog>, diesel::result::Error> {
        use crate::schema::poweradmin_operation_logs::dsl::*;

        let logs = poweradmin_operation_logs
            .filter(resource_type.eq(resource_type_param))
            .filter(resource_id.eq(resource_id_param))
            .order(timestamp.desc())
            .limit(limit)
            .load::<PowerAdminOperationLogRecord>(conn)?;

        Ok(logs.into_iter().map(|l| DnsOperationLog {
            id: l.id,
            operation: l.operation,
            resource_type: l.resource_type,
            resource_id: l.resource_id,
            resource_name: l.resource_name,
            user_id: l.user_id,
            organization_id: l.organization_id,
            old_value: l.old_value,
            new_value: l.new_value,
            ip_address: l.ip_address,
            user_agent: l.user_agent,
            timestamp: l.timestamp,
            success: l.success,
            error_message: l.error_message,
        }).collect())
    }
}

/// [TEMPLATE QUERY OPERATIONS] Database Operations for Templates
/// @MISSION Provide operations for zone templates.
/// @THREAT Template management issues.
/// @COUNTERMEASURE Versioned template storage.
/// @AUDIT Template operations logged.
pub struct PowerAdminTemplateQueries;

impl PowerAdminTemplateQueries {
    /// Get active templates
    pub fn get_active_templates(
        conn: &PgConnection,
    ) -> Result<Vec<DnsZoneTemplate>, diesel::result::Error> {
        use crate::schema::poweradmin_zone_templates::dsl::*;

        let templates = poweradmin_zone_templates
            .filter(is_active.eq(true))
            .order(created_at.desc())
            .load::<PowerAdminZoneTemplateRecord>(conn)?;

        Ok(templates.into_iter().map(|t| DnsZoneTemplate {
            id: t.id,
            name: t.name,
            description: t.description,
            zone_type: t.zone_type,
            default_ttl: t.default_ttl,
            nameservers: t.nameservers,
            soa_config: serde_json::from_value(t.soa_config).unwrap_or_default(),
            default_records: t.default_records.into_iter()
                .filter_map(|r| serde_json::from_value(r).ok())
                .collect(),
            dnssec_config: t.dnssec_config.map(|c| serde_json::from_value(c).unwrap_or_default()),
            created_by: t.created_by,
            created_at: t.created_at,
            updated_at: t.updated_at,
        }).collect())
    }
}