# Grafana API Implementation Documentation

## Overview

This document provides comprehensive documentation for the Grafana API implementation within the Sky Genesis Enterprise API Service. The implementation provides programmatic access to Grafana's HTTP API for automated dashboard management, datasource configuration, and alerting setup.

## Architecture

The Grafana integration follows a modular architecture with the following components:

### Core Components

#### 1. Grafana Service (`api/src/services/grafana_service.rs`)
The main service layer that handles HTTP communication with Grafana's API.

**Key Features:**
- Secure API key management via Vault
- RESTful operations for dashboards, datasources, and alerts
- Error handling and retry logic
- Connection pooling and timeout management

**Configuration:**
```rust
// Environment variables
GRAFANA_URL=https://grafana.skygenesisenterprise.com  // Default URL
GRAFANA_API_KEY_PATH=grafana/api_key                  // Vault path for API key
```

#### 2. Grafana Core (`api/src/core/grafana_core.rs`)
Business logic layer providing high-level operations and template management.

**Key Features:**
- Predefined dashboard and alert templates
- Template parameterization and validation
- Datasource configuration management
- Template lifecycle management

**Available Templates:**
- **System Health Dashboard**: Comprehensive system monitoring
- **Security Monitoring Dashboard**: Threat detection and alerts
- **High Error Rate Alert**: API error monitoring
- **High Response Time Alert**: Performance monitoring

#### 3. Grafana Middleware (`api/src/middlewares/grafana_middleware.rs`)
Security and access control layer for Grafana operations.

**Key Features:**
- JWT-based authentication
- Role-based authorization (Read, Write, Admin, Template)
- Rate limiting and request validation
- Comprehensive audit logging

**Permission Levels:**
- `Read`: View dashboards and configurations
- `Write`: Create/modify dashboards and datasources
- `Admin`: Full administrative access
- `Template`: Access to template operations

#### 4. Grafana Models (`api/src/models/grafana_models.rs`)
Data structures and validation for Grafana entities.

**Key Models:**
- `GrafanaDashboard`: Complete dashboard representation
- `GrafanaDatasource`: Datasource connection configuration
- `GrafanaAlertRule`: Alert rule definitions
- `GrafanaPanel`: Individual dashboard panels
- `GrafanaTarget`: Data query targets

**Validation:**
- JSON schema validation
- Required field checking
- Type safety enforcement
- Security sanitization

#### 5. Grafana Queries (`api/src/queries/grafana_queries.rs`)
Database operations for persistent Grafana data storage.

**Database Tables:**
- `grafana_dashboards`: Dashboard metadata and configurations
- `grafana_datasources`: Datasource connection details
- `grafana_alert_rules`: Alert rule definitions
- `grafana_audit_logs`: Operation audit trail
- `grafana_templates`: Reusable templates

**Operations:**
- CRUD operations for all entities
- Audit logging for compliance
- Multi-tenant data isolation
- Secure credential storage

#### 6. Grafana Utils (`api/src/utils/grafana_utils.rs`)
Utility functions for common Grafana operations.

**Key Utilities:**
- UID generation (Grafana-compatible)
- Data transformation (Prometheus → Grafana)
- Query validation and formatting
- Security sanitization
- Performance monitoring

## API Endpoints

### Health Check
```http
GET /api/v1/grafana/health
```

**Response:**
```json
{
  "healthy": true,
  "message": "Grafana service is healthy",
  "timestamp": "2024-01-01T12:00:00Z"
}
```

### Dashboard Management

#### Create Dashboard
```http
POST /api/v1/grafana/dashboards
Content-Type: application/json

{
  "dashboard": {
    "title": "My Dashboard",
    "tags": ["monitoring"],
    "panels": [...]
  },
  "folder_id": 0,
  "overwrite": false
}
```

#### List Dashboards
```http
GET /api/v1/grafana/dashboards
```

#### Get Dashboard
```http
GET /api/v1/grafana/dashboards/{uid}
```

#### Update Dashboard
```http
PUT /api/v1/grafana/dashboards/{uid}
```

#### Delete Dashboard
```http
DELETE /api/v1/grafana/dashboards/{uid}
```

### Datasource Management

#### Create Datasource
```http
POST /api/v1/grafana/datasources
Content-Type: application/json

{
  "name": "Prometheus",
  "type": "prometheus",
  "url": "http://prometheus:9090",
  "access": "proxy"
}
```

### Alert Management

#### Create Alert Rule
```http
POST /api/v1/grafana/alerts
Content-Type: application/json

{
  "title": "High Error Rate",
  "condition": "C",
  "data": [...],
  "no_data_state": "NoData",
  "exec_err_state": "Error",
  "for_duration": "5m"
}
```

## Template System

### Dashboard Templates

#### System Health Template
```json
{
  "title": "Sky Genesis System Health",
  "panels": [
    {
      "title": "Active Connections",
      "targets": [{
        "expr": "sky_genesis_active_connections{service=\"api\"}"
      }]
    },
    {
      "title": "Response Time",
      "targets": [{
        "expr": "sky_genesis_average_response_time_ms{service=\"api\"}"
      }]
    }
  ]
}
```

#### Security Monitoring Template
```json
{
  "title": "Sky Genesis Security Monitoring",
  "panels": [
    {
      "title": "Failed Authentication Attempts",
      "targets": [{
        "expr": "sky_genesis_failed_auth_attempts_total"
      }]
    }
  ]
}
```

### Alert Templates

#### High Error Rate Alert
```json
{
  "title": "High Error Rate on {{service}}",
  "condition": "C",
  "data": [
    {
      "expr": "rate(sky_genesis_http_requests_total{status=~\"5..\"}[5m]) / rate(sky_genesis_http_requests_total[5m]) * 100 > 5"
    }
  ]
}
```

## Security Implementation

### Authentication
- JWT token validation via existing auth service
- API key retrieval from Vault
- Secure credential storage

### Authorization
- Role-based access control
- Permission validation per operation
- Organization-based isolation

### Audit Logging
- Complete operation tracking
- User and organization context
- Success/failure status
- Timestamp and metadata

### Input Validation
- JSON schema validation
- SQL injection prevention
- XSS protection
- Data sanitization

## Database Schema

### Grafana Dashboards Table
```sql
CREATE TABLE grafana_dashboards (
    id BIGSERIAL PRIMARY KEY,
    uid VARCHAR(40) UNIQUE NOT NULL,
    title VARCHAR(255) NOT NULL,
    folder_uid VARCHAR(40),
    tags TEXT[] DEFAULT '{}',
    created_by VARCHAR(255) NOT NULL,
    updated_by VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    is_template BOOLEAN DEFAULT FALSE,
    template_name VARCHAR(255),
    metadata JSONB DEFAULT '{}'
);
```

### Grafana Datasources Table
```sql
CREATE TABLE grafana_datasources (
    id BIGSERIAL PRIMARY KEY,
    uid VARCHAR(40) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    datasource_type VARCHAR(100) NOT NULL,
    url VARCHAR(500) NOT NULL,
    access VARCHAR(20) DEFAULT 'proxy',
    basic_auth BOOLEAN DEFAULT FALSE,
    basic_auth_user VARCHAR(255),
    credentials_path VARCHAR(500) NOT NULL,
    json_data JSONB DEFAULT '{}',
    created_by VARCHAR(255) NOT NULL,
    updated_by VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    is_default BOOLEAN DEFAULT FALSE,
    organization_id VARCHAR(255) NOT NULL
);
```

### Grafana Alert Rules Table
```sql
CREATE TABLE grafana_alert_rules (
    id BIGSERIAL PRIMARY KEY,
    uid VARCHAR(40) UNIQUE NOT NULL,
    title VARCHAR(255) NOT NULL,
    condition TEXT NOT NULL,
    no_data_state VARCHAR(20) DEFAULT 'NoData',
    exec_err_state VARCHAR(20) DEFAULT 'Error',
    for_duration VARCHAR(20) DEFAULT '5m',
    annotations JSONB DEFAULT '{}',
    labels JSONB DEFAULT '{}',
    is_paused BOOLEAN DEFAULT FALSE,
    created_by VARCHAR(255) NOT NULL,
    updated_by VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    dashboard_uid VARCHAR(40),
    panel_id BIGINT
);
```

### Grafana Audit Logs Table
```sql
CREATE TABLE grafana_audit_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    organization_id VARCHAR(255) NOT NULL,
    operation VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_uid VARCHAR(40) NOT NULL,
    action VARCHAR(50) NOT NULL,
    details JSONB DEFAULT '{}',
    ip_address INET,
    user_agent TEXT,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT
);
```

### Grafana Templates Table
```sql
CREATE TABLE grafana_templates (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    template_type VARCHAR(50) NOT NULL,
    description TEXT,
    version VARCHAR(20) DEFAULT '1.0',
    content JSONB NOT NULL,
    parameters JSONB DEFAULT '{}',
    tags TEXT[] DEFAULT '{}',
    created_by VARCHAR(255) NOT NULL,
    updated_by VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE
);
```

## Configuration

### Environment Variables
```bash
# Grafana Connection
GRAFANA_URL=https://grafana.skygenesisenterprise.com
GRAFANA_API_KEY_PATH=grafana/api_key

# Database (inherited from main application)
DATABASE_URL=postgresql://user:password@localhost/sky_genesis

# Vault Configuration (inherited)
VAULT_ADDR=https://vault.skygenesisenterprise.com
VAULT_TOKEN=your-vault-token
```

### Vault Setup
```bash
# Store Grafana API key in Vault
vault kv put secret/grafana/api_key key="your-grafana-api-key"

# Store datasource credentials
vault kv put secret/grafana/datasources/prometheus \
  username="prometheus-user" \
  password="prometheus-password"
```

## Usage Examples

### Creating a Dashboard from Template
```rust
use crate::core::grafana_core::GrafanaCore;

// Initialize core
let vault_client = Arc::new(VaultClient::new()?);
let core = GrafanaCore::new(vault_client);

// Get system health template
let template = core.get_dashboard_template("system-health").unwrap();

// Apply parameters
let parameters = HashMap::from([
    ("service".to_string(), "api".to_string()),
    ("environment".to_string(), "production".to_string()),
]);

let dashboard_json = core.apply_template_parameters(&template.template, &parameters)?;

// Create dashboard via service
let service = GrafanaService::new(vault_client)?;
let grafana_dashboard = GrafanaDashboard {
    dashboard: dashboard_json,
    folder_id: Some(1),
    overwrite: false,
};

service.create_dashboard(grafana_dashboard).await?;
```

### Setting up Prometheus Datasource
```rust
use crate::services::grafana_service::GrafanaService;

let service = GrafanaService::new(vault_client)?;

let datasource = GrafanaDatasource {
    name: "Sky Genesis Enterprise Prometheus".to_string(),
    r#type: "prometheus".to_string(),
    url: "http://prometheus.skygenesisenterprise.com:9090".to_string(),
    access: "proxy".to_string(),
    basic_auth: Some(true),
    basic_auth_user: Some("prometheus".to_string()),
    secure_json_data: Some(HashMap::from([
        ("password".to_string(), "secure-password".to_string())
    ])),
    json_data: Some(json!({"timeInterval": "15s"})),
};

service.create_datasource(datasource).await?;
```

## Testing

### Unit Tests
```bash
cargo test grafana_models::tests
cargo test grafana_utils::tests
cargo test grafana_core::tests
```

### Integration Tests
```bash
cargo test grafana_service::tests --features integration
cargo test grafana_middleware::tests --features integration
```

### Performance Tests
```bash
cargo test grafana_tests::test_bulk_template_processing
cargo test grafana_tests::test_concurrent_template_access
```

## Monitoring and Metrics

### Application Metrics
- `grafana_operations_total`: Total Grafana API operations
- `grafana_operation_duration_seconds`: Operation response times
- `grafana_errors_total`: Operation error counts
- `grafana_template_usage_total`: Template usage statistics

### Health Checks
- Grafana API connectivity
- Database connectivity
- Vault connectivity
- Template validation

## Troubleshooting

### Common Issues

#### Authentication Failures
```
Error: Invalid API key
Solution: Verify GRAFANA_API_KEY_PATH in Vault
```

#### Permission Denied
```
Error: Insufficient permissions
Solution: Check user roles and Grafana permissions
```

#### Template Not Found
```
Error: Template 'xyz' not found
Solution: Verify template name and active status
```

#### Database Connection Issues
```
Error: Connection timeout
Solution: Check database connectivity and credentials
```

### Debug Commands
```bash
# Test Grafana connectivity
curl -H "Authorization: Bearer $GRAFANA_API_KEY" \
     https://grafana.skygenesisenterprise.com/api/health

# Check API health
curl http://localhost:8080/api/v1/grafana/health

# List available templates
curl http://localhost:8080/api/v1/grafana/dashboards
```

## Performance Considerations

### Optimization Strategies
- Template caching in memory
- Connection pooling for Grafana API
- Database query optimization
- Async operation handling

### Scalability
- Horizontal scaling support
- Rate limiting per user/organization
- Background job processing for bulk operations
- CDN integration for static assets

## Security Considerations

### Data Protection
- Encrypted storage of sensitive data
- Secure API key management via Vault
- Input validation and sanitization
- SQL injection prevention

### Access Control
- Multi-tenant data isolation
- Role-based permissions
- Audit logging for compliance
- Rate limiting and abuse prevention

### Network Security
- HTTPS-only communication
- Certificate validation
- Firewall configuration
- VPN integration for internal access

## Compliance

### GDPR Compliance
- Data minimization principles
- Right to erasure implementation
- Audit logging for data access
- Consent management integration

### SOX Compliance
- Complete audit trails
- Change management tracking
- Access control enforcement
- Financial data protection

### Enterprise Security
- Zero-trust architecture
- Defense in depth
- Regular security assessments
- Incident response procedures

## Future Enhancements

### Planned Features
- **Advanced Templating**: Dynamic template generation
- **Multi-Grafana Support**: Multiple Grafana instances
- **Dashboard Versioning**: Historical dashboard tracking
- **Real-time Collaboration**: Concurrent dashboard editing
- **AI-Powered Insights**: Automated dashboard recommendations

### API Extensions
- **Bulk Operations**: Batch dashboard/datasource management
- **Import/Export**: Dashboard migration between environments
- **Backup/Restore**: Automated configuration backups
- **Integration APIs**: Third-party tool integrations

## Support and Maintenance

### Monitoring
- Application performance monitoring
- Error rate tracking
- User adoption metrics
- System resource usage

### Maintenance Tasks
- Template updates and validation
- Database cleanup and optimization
- Security patch management
- Performance tuning

### Documentation Updates
- API endpoint documentation
- Template catalog maintenance
- Troubleshooting guide updates
- Security best practices

---

This implementation provides a comprehensive, enterprise-grade Grafana API integration that enables automated monitoring infrastructure management while maintaining security, compliance, and performance standards.