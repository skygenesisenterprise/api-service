// ============================================================================
//  SKY GENESIS ENTERPRISE (SGE)
//  Sovereign Infrastructure Initiative
//  Project: Enterprise API Service
//  Module: Database Management Models
// ---------------------------------------------------------------------------
//  CLASSIFICATION: INTERNAL | HIGHLY-SENSITIVE
//  MISSION: Provide secure database connection management and access control
//  for multiple database types (PostgreSQL, MySQL, MariaDB, etc.).
//  NOTICE: Implements database abstraction layer with encryption and audit.
//  STANDARDS: Connection Pooling, Encryption, Multi-DB Support, Audit Logging
//  COMPLIANCE: Data Protection, Access Control, Encryption Standards
//  License: MIT (Open Source for Strategic Transparency)
// ============================================================================

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// [DATABASE TYPE ENUM] Supported Database Types
/// @MISSION Define all supported database backends.
/// @THREAT Unsupported database types.
/// @COUNTERMEASURE Validate database type before connection.
/// @COMPLIANCE Support enterprise-standard databases.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DatabaseType {
    PostgreSQL,
    MySQL,
    MariaDB,
    SQLite,
    MSSQL,
    Oracle,
}

/// [DATABASE STATUS ENUM] Connection and Operational Status
/// @MISSION Track database connection health and availability.
/// @THREAT Stale or failed connections.
/// @COUNTERMEASURE Regular health checks and status monitoring.
/// @AUDIT Status changes are logged.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DatabaseStatus {
    Active,
    Inactive,
    Maintenance,
    Error,
}

/// [DATABASE CONNECTION MODEL] Secure Database Connection Configuration
/// @MISSION Store encrypted database connection parameters.
/// @THREAT Credential exposure or weak encryption.
/// @COUNTERMEASURE Encrypt all sensitive data and validate connections.
/// @AUDIT Connection attempts are logged with user context.
/// @FLOW Create -> Validate -> Encrypt -> Store -> Audit
/// @DEPENDENCY Vault for credential encryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConnection {
    /// Unique identifier for the database connection
    pub id: Uuid,
    /// Human-readable name for the database
    pub name: String,
    /// Type of database (PostgreSQL, MySQL, etc.)
    pub db_type: DatabaseType,
    /// Database host or IP address
    pub host: String,
    /// Database port number
    pub port: u16,
    /// Database name/schema
    pub database_name: String,
    /// Encrypted username (stored in Vault)
    pub username: String,
    /// Encrypted password reference (stored in Vault)
    pub password_ref: String,
    /// Additional connection parameters
    pub connection_params: std::collections::HashMap<String, String>,
    /// Current operational status
    pub status: DatabaseStatus,
    /// Associated tenant/organization
    pub tenant: String,
    /// Maximum number of connections in pool
    pub max_connections: u32,
    /// Connection timeout in seconds
    pub connection_timeout: u32,
    /// Query timeout in seconds
    pub query_timeout: u32,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Last modified timestamp
    pub updated_at: DateTime<Utc>,
    /// Last health check timestamp
    pub last_health_check: Option<DateTime<Utc>>,
}

/// [DATABASE QUERY MODEL] Structured Database Query Request
/// @MISSION Provide type-safe query execution interface.
/// @THREAT SQL injection or unauthorized queries.
/// @COUNTERMEASURE Parameterized queries and permission validation.
/// @AUDIT All queries are logged with user and tenant context.
/// @FLOW Validate -> Parameterize -> Execute -> Audit -> Return
/// @DEPENDENCY Database connection and user permissions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseQuery {
    /// Target database connection ID
    pub connection_id: Uuid,
    /// SQL query string
    pub query: String,
    /// Query parameters (for prepared statements)
    pub parameters: Vec<serde_json::Value>,
    /// Query timeout override (optional)
    pub timeout: Option<u32>,
    /// Read-only flag for safety
    pub read_only: bool,
}

/// [DATABASE QUERY RESULT MODEL] Structured Query Response
/// @MISSION Return query results with metadata.
/// @THREAT Data leakage or incorrect result formatting.
/// @COUNTERMEASURE Validate results and enforce size limits.
/// @AUDIT Query results are logged for compliance.
/// @FLOW Execute -> Format -> Validate -> Return
/// @DEPENDENCY Query execution and result processing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseQueryResult {
    /// Query execution success flag
    pub success: bool,
    /// Number of affected rows (for INSERT/UPDATE/DELETE)
    pub affected_rows: Option<u64>,
    /// Column names for SELECT queries
    pub columns: Vec<String>,
    /// Query result rows
    pub rows: Vec<Vec<serde_json::Value>>,
    /// Execution time in milliseconds
    pub execution_time_ms: u64,
    /// Error message if query failed
    pub error: Option<String>,
}

/// [DATABASE HEALTH MODEL] Connection Health Check Response
/// @MISSION Monitor database connectivity and performance.
/// @THREAT Silent connection failures.
/// @COUNTERMEASURE Regular health checks with alerting.
/// @AUDIT Health status changes trigger alerts.
/// @FLOW Check -> Measure -> Report -> Alert
/// @DEPENDENCY Database connection and monitoring systems.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseHealth {
    /// Database connection ID
    pub connection_id: Uuid,
    /// Health check timestamp
    pub timestamp: DateTime<Utc>,
    /// Connection status
    pub status: DatabaseStatus,
    /// Response time in milliseconds
    pub response_time_ms: u64,
    /// Error message if health check failed
    pub error: Option<String>,
    /// Connection pool statistics
    pub pool_stats: DatabasePoolStats,
}

/// [DATABASE POOL STATISTICS MODEL] Connection Pool Metrics
/// @MISSION Monitor connection pool utilization.
/// @THREAT Connection pool exhaustion.
/// @COUNTERMEASURE Monitor and alert on pool metrics.
/// @AUDIT Pool statistics are tracked for capacity planning.
/// @FLOW Monitor -> Collect -> Report -> Alert
/// @DEPENDENCY Connection pool implementation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabasePoolStats {
    /// Total connections in pool
    pub total_connections: u32,
    /// Active connections
    pub active_connections: u32,
    /// Idle connections
    pub idle_connections: u32,
    /// Pending connection requests
    pub pending_requests: u32,
}

/// [ZTNA POLICY MODEL] Zero Trust Network Access Policies for Databases
/// @MISSION Implement fine-grained, context-aware access control.
/// @THREAT Unauthorized or inappropriate database access.
/// @COUNTERMEASURE Continuous verification, least privilege, context validation.
/// @AUDIT All access attempts logged with full context.
/// @FLOW Evaluate Context -> Check Policies -> Enforce Rules -> Audit
/// @DEPENDENCY Identity, device, and context information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZTNADatabasePolicy {
    /// Unique policy identifier
    pub id: Uuid,
    /// Policy name for management
    pub name: String,
    /// Associated tenant/organization
    pub tenant: String,
    /// Database connection this policy applies to
    pub connection_id: Uuid,
    /// Principals (users/roles) this policy applies to
    pub principals: Vec<String>,
    /// Allowed operations under this policy
    pub operations: Vec<DatabaseOperation>,
    /// Resource-level restrictions
    pub resource_filters: ZTNAResourceFilters,
    /// Context-based conditions
    pub conditions: ZTNAConditions,
    /// Policy priority (higher = more specific)
    pub priority: i32,
    /// Policy status
    pub status: PolicyStatus,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Last modified timestamp
    pub updated_at: DateTime<Utc>,
}

/// [ZTNA RESOURCE FILTERS] Granular Resource-Level Access Control
/// @MISSION Define exactly what data can be accessed.
/// @THREAT Over-broad data access.
/// @COUNTERMEASURE Row-level, column-level, and table-level filtering.
/// @COMPLIANCE Data minimization and privacy regulations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZTNAResourceFilters {
    /// Allowed schemas (empty = all allowed)
    pub schemas: Vec<String>,
    /// Allowed tables (empty = all allowed)
    pub tables: Vec<String>,
    /// Column-level restrictions (table -> allowed columns)
    pub columns: std::collections::HashMap<String, Vec<String>>,
    /// Row-level security filters (SQL WHERE clauses)
    pub row_filters: Vec<String>,
    /// Maximum rows that can be returned
    pub max_rows: Option<u32>,
    /// Maximum query execution time
    pub max_execution_time: Option<u32>,
}

/// [ZTNA CONDITIONS] Context-Based Access Conditions
/// @MISSION Verify access context before allowing operations.
/// @THREAT Access from unauthorized contexts.
/// @COUNTERMEASURE Multi-factor context validation.
/// @COMPLIANCE Zero Trust security model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZTNAConditions {
    /// Required IP ranges or locations
    pub ip_ranges: Vec<String>,
    /// Required device types or characteristics
    pub device_types: Vec<String>,
    /// Required authentication methods
    pub auth_methods: Vec<String>,
    /// Time-based restrictions
    pub time_restrictions: Option<TimeRestrictions>,
    /// Risk-based conditions
    pub risk_threshold: Option<RiskLevel>,
    /// Geographic restrictions
    pub geo_restrictions: Vec<String>,
}

/// [TIME RESTRICTIONS] Temporal Access Control
/// @MISSION Limit access to specific time windows.
/// @THREAT Access outside business hours.
/// @COUNTERMEASURE Time-based policy enforcement.
/// @COMPLIANCE Compliance with time-based access requirements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRestrictions {
    /// Days of week (0 = Sunday, 6 = Saturday)
    pub days_of_week: Vec<u8>,
    /// Hours of day (0-23)
    pub hours_of_day: Vec<u8>,
    /// Time zone for restrictions
    pub timezone: String,
}

/// [RISK LEVEL ENUM] Risk-Based Access Control
/// @MISSION Adjust access based on calculated risk.
/// @THREAT High-risk access attempts.
/// @COUNTERMEASURE Risk-adaptive security controls.
/// @COMPLIANCE Risk-based authentication standards.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// [POLICY STATUS ENUM] Policy Lifecycle Management
/// @MISSION Control policy activation and deactivation.
/// @THREAT Stale or unauthorized policies.
/// @COUNTERMEASURE Policy lifecycle management.
/// @AUDIT Policy status changes are logged.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PolicyStatus {
    Active,
    Inactive,
    Draft,
    Expired,
}

/// [ZTNA ACCESS REQUEST] Real-time Access Evaluation
/// @MISSION Evaluate access requests against policies.
/// @THREAT Unauthorized access attempts.
/// @COUNTERMEASURE Real-time policy evaluation.
/// @AUDIT All access requests are logged.
/// @FLOW Collect Context -> Evaluate Policies -> Make Decision -> Audit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZTNAAccessRequest {
    /// Requesting principal
    pub principal: String,
    /// Target database connection
    pub connection_id: Uuid,
    /// Requested operation
    pub operation: DatabaseOperation,
    /// Target resources
    pub resources: Vec<String>,
    /// Client context
    pub context: ZTNAContext,
    /// Request timestamp
    pub timestamp: DateTime<Utc>,
}

/// [ZTNA CONTEXT] Client and Session Context Information
/// @MISSION Collect comprehensive context for access decisions.
/// @THREAT Insufficient context for security decisions.
/// @COUNTERMEASURE Rich context collection and validation.
/// @COMPLIANCE Zero Trust context requirements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZTNAContext {
    /// Client IP address
    pub ip_address: String,
    /// User agent string
    pub user_agent: String,
    /// Device fingerprint
    pub device_fingerprint: Option<String>,
    /// Geographic location
    pub location: Option<GeoLocation>,
    /// Authentication method used
    pub auth_method: String,
    /// Session identifier
    pub session_id: String,
    /// Risk score (0-100)
    pub risk_score: Option<u32>,
}

/// [GEO LOCATION] Geographic Context Information
/// @MISSION Provide location-based access control.
/// @THREAT Access from unauthorized locations.
/// @COUNTERMEASURE Geographic policy enforcement.
/// @COMPLIANCE Location-based security requirements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    /// Country code (ISO 3166-1 alpha-2)
    pub country: String,
    /// Region/state
    pub region: String,
    /// City
    pub city: String,
    /// Latitude
    pub latitude: f64,
    /// Longitude
    pub longitude: f64,
}

/// [ZTNA ACCESS DECISION] Policy Evaluation Result
/// @MISSION Communicate access control decisions.
/// @THREAT Ambiguous or incorrect access decisions.
/// @COUNTERMEASURE Clear, auditable decisions.
/// @AUDIT All decisions are logged with reasoning.
/// @FLOW Evaluate -> Decide -> Log -> Enforce
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZTNAAccessDecision {
    /// Access granted or denied
    pub allowed: bool,
    /// Applied policy ID (if allowed)
    pub policy_id: Option<Uuid>,
    /// Decision reasoning
    pub reason: String,
    /// Additional context or restrictions
    pub restrictions: Option<ZTNAQueryRestrictions>,
    /// Decision timestamp
    pub timestamp: DateTime<Utc>,
}

/// [ZTNA QUERY RESTRICTIONS] Runtime Query Modifications
/// @MISSION Apply additional restrictions to allowed queries.
/// @THREAT Queries that bypass policy restrictions.
/// @COUNTERMEASURE Runtime query modification and validation.
/// @COMPLIANCE Query-level security enforcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZTNAQueryRestrictions {
    /// Additional WHERE clauses to inject
    pub additional_filters: Vec<String>,
    /// Columns to exclude from results
    pub excluded_columns: Vec<String>,
    /// Maximum result set size
    pub max_results: Option<u32>,
    /// Required query timeout
    pub timeout_seconds: Option<u32>,
}

/// [DATABASE PERMISSION MODEL] Legacy Access Control (for backward compatibility)
/// @MISSION Maintain backward compatibility with existing permissions.
/// @THREAT Breaking changes to existing systems.
/// @COUNTERMEASURE Gradual migration to ZTNA policies.
/// @DEPRECATED Use ZTNADatabasePolicy for new implementations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabasePermission {
    /// User or role identifier
    pub principal: String,
    /// Database connection ID
    pub connection_id: Uuid,
    /// Allowed operations
    pub operations: Vec<DatabaseOperation>,
    /// Resource restrictions (tables, schemas, etc.)
    pub resource_filters: Vec<String>,
    /// Permission expiration
    pub expires_at: Option<DateTime<Utc>>,
}

/// [DATABASE OPERATION ENUM] Supported Database Operations
/// @MISSION Define granular database operations.
/// @THREAT Over-permissive access.
/// @COUNTERMEASURE Minimal required permissions.
/// @COMPLIANCE Principle of least privilege.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DatabaseOperation {
    Select,
    Insert,
    Update,
    Delete,
    Create,
    Drop,
    Alter,
    Execute,
    Admin,
}

impl DatabaseConnection {
    /// [CONNECTION BUILDER] Create New Database Connection
    /// @MISSION Initialize database connection with validation.
    /// @THREAT Invalid connection parameters.
    /// @COUNTERMEASURE Validate all parameters before creation.
    /// @AUDIT Connection creation is logged.
    pub fn new(
        name: String,
        db_type: DatabaseType,
        host: String,
        port: u16,
        database_name: String,
        username: String,
        password_ref: String,
        tenant: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name,
            db_type,
            host,
            port,
            database_name,
            username,
            password_ref,
            connection_params: std::collections::HashMap::new(),
            status: DatabaseStatus::Inactive,
            tenant,
            max_connections: 10,
            connection_timeout: 30,
            query_timeout: 300,
            created_at: now,
            updated_at: now,
            last_health_check: None,
        }
    }

    /// [CONNECTION VALIDATOR] Validate Connection Parameters
    /// @MISSION Ensure connection parameters are valid.
    /// @THREAT Malformed connection strings.
    /// @COUNTERMEASURE Comprehensive parameter validation.
    /// @AUDIT Validation failures are logged.
    pub fn validate(&self) -> Result<(), String> {
        if self.name.is_empty() {
            return Err("Database name cannot be empty".to_string());
        }
        if self.host.is_empty() {
            return Err("Host cannot be empty".to_string());
        }
        if self.port == 0 {
            return Err("Port must be greater than 0".to_string());
        }
        if self.database_name.is_empty() {
            return Err("Database name cannot be empty".to_string());
        }
        if self.username.is_empty() {
            return Err("Username cannot be empty".to_string());
        }
        if self.tenant.is_empty() {
            return Err("Tenant cannot be empty".to_string());
        }
        Ok(())
    }
}

impl DatabaseQuery {
    /// [QUERY VALIDATOR] Validate Query Parameters
    /// @MISSION Prevent malicious or invalid queries.
    /// @THREAT SQL injection or malformed queries.
    /// @COUNTERMEASURE Query validation and sanitization.
    /// @AUDIT Invalid queries are logged.
    pub fn validate(&self) -> Result<(), String> {
        if self.query.trim().is_empty() {
            return Err("Query cannot be empty".to_string());
        }
        // Basic SQL injection prevention
        let forbidden_patterns = ["--", "/*", "*/", "xp_", "sp_"];
        for pattern in &forbidden_patterns {
            if self.query.to_lowercase().contains(pattern) {
                return Err(format!("Query contains forbidden pattern: {}", pattern));
            }
        }
        Ok(())
    }
}

impl ZTNADatabasePolicy {
    /// [POLICY BUILDER] Create New ZTNA Policy
    /// @MISSION Initialize policy with secure defaults.
    /// @THREAT Weak policy configurations.
    /// @COUNTERMEASURE Secure defaults and validation.
    /// @AUDIT Policy creation is logged.
    pub fn new(name: String, tenant: String, connection_id: Uuid) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name,
            tenant,
            connection_id,
            principals: vec![],
            operations: vec![],
            resource_filters: ZTNAResourceFilters {
                schemas: vec![],
                tables: vec![],
                columns: std::collections::HashMap::new(),
                row_filters: vec![],
                max_rows: Some(1000),
                max_execution_time: Some(30),
            },
            conditions: ZTNAConditions {
                ip_ranges: vec![],
                device_types: vec![],
                auth_methods: vec![],
                time_restrictions: None,
                risk_threshold: Some(RiskLevel::High),
                geo_restrictions: vec![],
            },
            priority: 1,
            status: PolicyStatus::Draft,
            created_at: now,
            updated_at: now,
        }
    }

    /// [POLICY VALIDATOR] Validate Policy Configuration
    /// @MISSION Ensure policy integrity and security.
    /// @THREAT Malformed or insecure policies.
    /// @COUNTERMEASURE Comprehensive validation.
    /// @AUDIT Validation failures are logged.
    pub fn validate(&self) -> Result<(), String> {
        if self.name.is_empty() {
            return Err("Policy name cannot be empty".to_string());
        }
        if self.tenant.is_empty() {
            return Err("Tenant cannot be empty".to_string());
        }
        if self.principals.is_empty() {
            return Err("Policy must have at least one principal".to_string());
        }
        if self.operations.is_empty() {
            return Err("Policy must allow at least one operation".to_string());
        }
        if self.priority < 1 || self.priority > 100 {
            return Err("Priority must be between 1 and 100".to_string());
        }

        // Validate time restrictions if present
        if let Some(time_restrictions) = &self.conditions.time_restrictions {
            for &day in &time_restrictions.days_of_week {
                if day > 6 {
                    return Err("Invalid day of week in time restrictions".to_string());
                }
            }
            for &hour in &time_restrictions.hours_of_day {
                if hour > 23 {
                    return Err("Invalid hour of day in time restrictions".to_string());
                }
            }
        }

        Ok(())
    }
}

/// [DEVICE STATUS ENUM] Operational Status of Managed Devices
/// @MISSION Track device availability and health.
/// @THREAT Unmonitored or failed devices.
/// @COUNTERMEASURE Regular health checks and status monitoring.
/// @AUDIT Status changes are logged.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DeviceStatus {
    Online,
    Offline,
    Maintenance,
    Error,
    Unknown,
}

/// [DEVICE TYPE ENUM] Types of Devices that can be Managed
/// @MISSION Categorize devices for appropriate management.
/// @THREAT Incorrect device handling.
/// @COUNTERMEASURE Type-specific management logic.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DeviceType {
    Router,
    Switch,
    Server,
    Firewall,
    LoadBalancer,
    AccessPoint,
    IoTDevice,
    Other,
}

/// [DEVICE CONNECTION TYPE] How the Device Connects to Management
/// @MISSION Define connection methods for device management.
/// @THREAT Insecure or unreliable connections.
/// @COUNTERMEASURE Secure, authenticated connections.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DeviceConnectionType {
    SNMP,
    SSH,
    REST,
    WebSocket,
    MQTT,
}

/// [DEVICE MODEL] Remote Device Management Structure
/// @MISSION Enable secure remote management of network devices.
/// @THREAT Unauthorized device access or configuration changes.
/// @COUNTERMEASURE Authentication, authorization, and audit logging.
/// @AUDIT All device operations are logged with user context.
/// @FLOW Register -> Authenticate -> Connect -> Manage -> Audit
/// @DEPENDENCY Organization, user permissions, and secure connections.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    /// Unique identifier for the device
    pub id: Uuid,
    /// Human-readable name for the device
    pub name: String,
    /// Device hostname or IP address
    pub hostname: String,
    /// Device IP address (if different from hostname)
    pub ip_address: Option<String>,
    /// Type of device
    pub device_type: DeviceType,
    /// Connection method for management
    pub connection_type: DeviceConnectionType,
    /// Device vendor/manufacturer
    pub vendor: Option<String>,
    /// Device model
    pub model: Option<String>,
    /// Operating system or firmware version
    pub os_version: Option<String>,
    /// Current operational status
    pub status: DeviceStatus,
    /// Associated organization
    pub organization_id: Uuid,
    /// Device location (datacenter, rack, etc.)
    pub location: Option<String>,
    /// Device tags for categorization
    pub tags: Vec<String>,
    /// Management port (SNMP: 161, SSH: 22, etc.)
    pub management_port: Option<u16>,
    /// SNMP community string or SSH credentials reference
    pub credentials_ref: Option<String>,
    /// Last successful contact timestamp
    pub last_seen: Option<DateTime<Utc>>,
    /// Device uptime in seconds
    pub uptime: Option<i64>,
    /// CPU usage percentage
    pub cpu_usage: Option<f32>,
    /// Memory usage percentage
    pub memory_usage: Option<f32>,
    /// Additional device-specific metadata
    pub metadata: std::collections::HashMap<String, String>,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Last modified timestamp
    pub updated_at: DateTime<Utc>,
}

/// [DEVICE COMMAND MODEL] Remote Command Execution on Devices
/// @MISSION Execute commands on managed devices securely.
/// @THREAT Unauthorized command execution.
/// @COUNTERMEASURE Command validation and audit logging.
/// @AUDIT All commands are logged with execution results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCommand {
    /// Unique identifier for the command execution
    pub id: Uuid,
    /// Target device ID
    pub device_id: Uuid,
    /// User who initiated the command
    pub user_id: Uuid,
    /// Command to execute
    pub command: String,
    /// Command parameters
    pub parameters: Option<std::collections::HashMap<String, String>>,
    /// Command execution status
    pub status: CommandStatus,
    /// Command output/result
    pub output: Option<String>,
    /// Exit code (for shell commands)
    pub exit_code: Option<i32>,
    /// Execution start time
    pub started_at: Option<DateTime<Utc>>,
    /// Execution completion time
    pub completed_at: Option<DateTime<Utc>>,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
}

/// [COMMAND STATUS ENUM] Status of Device Command Execution
/// @MISSION Track command execution lifecycle.
/// @THREAT Unmonitored command execution.
/// @COUNTERMEASURE Status tracking and timeout handling.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CommandStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Timeout,
    Cancelled,
}

/// [DEVICE METRICS MODEL] Performance and Health Metrics
/// @MISSION Collect and store device performance data.
/// @THREAT Missing performance visibility.
/// @COUNTERMEASURE Regular metric collection and alerting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceMetrics {
    /// Unique identifier for the metrics entry
    pub id: Uuid,
    /// Target device ID
    pub device_id: Uuid,
    /// Timestamp when metrics were collected
    pub timestamp: DateTime<Utc>,
    /// CPU usage percentage
    pub cpu_usage: Option<f32>,
    /// Memory usage percentage
    pub memory_usage: Option<f32>,
    /// Disk usage percentage
    pub disk_usage: Option<f32>,
    /// Network interface statistics
    pub network_stats: Option<NetworkStats>,
    /// Temperature readings
    pub temperature: Option<f32>,
    /// Power consumption
    pub power_usage: Option<f32>,
    /// Custom metrics
    pub custom_metrics: std::collections::HashMap<String, f32>,
}

/// [NETWORK STATS] Network Interface Statistics
/// @MISSION Track network performance metrics.
/// @THREAT Network performance issues.
/// @COUNTERMEASURE Interface monitoring and alerting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStats {
    /// Interface name
    pub interface: String,
    /// Bytes received
    pub rx_bytes: u64,
    /// Bytes transmitted
    pub tx_bytes: u64,
    /// Packets received
    pub rx_packets: u64,
    /// Packets transmitted
    pub tx_packets: u64,
    /// Receive errors
    pub rx_errors: u64,
    /// Transmit errors
    pub tx_errors: u64,
}

/// [MAC STATUS ENUM] Status of MAC Identity
/// @MISSION Track MAC identity lifecycle.
/// @THREAT Unauthorized or compromised MAC identities.
/// @COUNTERMEASURE Status tracking and revocation.
/// @AUDIT Status changes are logged.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MacStatus {
    Active,
    Inactive,
    Revoked,
}

/// [MAC CERTIFICATE INFO MODEL] Cryptographic Certificate Information for MAC
/// @MISSION Store certificate details for MAC identity verification.
/// @THREAT Certificate compromise or expiration.
/// @COUNTERMEASURE Certificate lifecycle management and validation.
/// @AUDIT Certificate operations are logged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacCertificateInfo {
    /// Certificate serial number
    pub serial_number: String,
    /// Certificate fingerprint (SHA256)
    pub fingerprint: String,
    /// Certificate issuer
    pub issuer: String,
    /// Certificate subject
    pub subject: String,
    /// Certificate validity start
    pub not_before: DateTime<Utc>,
    /// Certificate validity end
    pub not_after: DateTime<Utc>,
    /// Certificate status
    pub status: CertificateStatus,
    /// Certificate revocation reason (if revoked)
    pub revocation_reason: Option<String>,
    /// Certificate revocation date (if revoked)
    pub revoked_at: Option<DateTime<Utc>>,
    /// OCSP responder URL
    pub ocsp_url: Option<String>,
    /// CRL distribution point
    pub crl_url: Option<String>,
}

/// [CERTIFICATE STATUS ENUM] Status of MAC Certificate
/// @MISSION Track certificate lifecycle.
/// @THREAT Expired or revoked certificates.
/// @COUNTERMEASURE Status tracking and renewal.
/// @AUDIT Status changes are logged.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CertificateStatus {
    Active,
    Expired,
    Revoked,
    Suspended,
}

/// [MAC SIGNATURE INFO MODEL] Cryptographic Signature for MAC Integrity
/// @MISSION Store signature details for MAC address integrity.
/// @THREAT MAC tampering or spoofing.
/// @COUNTERMEASURE Cryptographic signatures and verification.
/// @AUDIT Signature operations are logged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacSignatureInfo {
    /// Signature algorithm used
    pub algorithm: String,
    /// Signature value (base64 encoded)
    pub signature: String,
    /// Signing key identifier
    pub key_id: String,
    /// Signature timestamp
    pub signed_at: DateTime<Utc>,
    /// Signature validity period
    pub valid_until: Option<DateTime<Utc>>,
}

/// [MAC IDENTITY MODEL] Sovereign MAC Address Identity Management
/// @MISSION Manage physical device identities with SGE-MAC format.
/// @THREAT MAC spoofing or identity theft.
/// @COUNTERMEASURE Cryptographic MAC generation and validation.
/// @AUDIT All MAC operations are logged with full context.
/// @FLOW Generate -> Register -> Validate -> Audit
/// @DEPENDENCY Vault for secure MAC generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacIdentity {
    /// Unique identifier for the MAC identity
    pub id: Uuid,
    /// SGE-MAC address (internal sovereign format)
    pub sge_mac: String,
    /// Standard IEEE 802 MAC address (optional mapping)
    pub standard_mac: Option<String>,
    /// Associated IP address
    pub ip_address: Option<String>,
    /// Owner identifier (user or device UUID)
    pub owner: String,
    /// Hardware fingerprint UUID
    pub fingerprint: String,
    /// Current status
    pub status: MacStatus,
    /// Associated organization
    pub organization_id: Uuid,
    /// Certificate information for this MAC
    pub certificate: Option<MacCertificateInfo>,
    /// Signature information for MAC integrity
    pub signature: Option<MacSignatureInfo>,
    /// Additional metadata
    pub metadata: std::collections::HashMap<String, String>,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Last modified timestamp
    pub updated_at: DateTime<Utc>,
}