# Monitoring & Grafana Integration

## Overview

The Sky Genesis Enterprise API provides comprehensive monitoring endpoints designed for integration with Grafana and other monitoring dashboards. These endpoints expose system health, performance metrics, and operational data in formats compatible with enterprise monitoring solutions.

## Available Endpoints

### 1. System Health Check (`/api/v1/health`)
- **Purpose**: Lightweight health check for load balancers and basic monitoring
- **Format**: JSON
- **Use Case**: Kubernetes readiness/liveness probes, load balancer health checks
- **Frequency**: Every 30 seconds

### 2. Detailed System Status (`/api/v1/status`)
- **Purpose**: Comprehensive system overview with component health
- **Format**: JSON
- **Use Case**: Detailed monitoring dashboards, incident response
- **Frequency**: Every 5 minutes

### 3. Prometheus Metrics Export (`/api/v1/metrics/prometheus`)
- **Purpose**: Standard Prometheus metrics for Grafana integration
- **Format**: Prometheus exposition format
- **Use Case**: Grafana dashboards, alerting rules
- **Frequency**: Every 30 seconds

### 4. Component Health (`/api/v1/health/{component}`)
- **Purpose**: Individual component health monitoring
- **Format**: JSON
- **Use Case**: Component-specific alerting and monitoring
- **Components**: vault, database, authentication, websocket

## Grafana Integration

### Sky Genesis Grafana API

The Sky Genesis API provides direct integration with Grafana through dedicated endpoints that allow programmatic management of dashboards, datasources, and alert rules. This enables automated monitoring setup and configuration.

#### Available Grafana API Endpoints

##### Health Check
- **Endpoint**: `GET /api/v1/grafana/health`
- **Purpose**: Verify Grafana service connectivity
- **Response**: JSON with health status and timestamp

##### Dashboard Management
- **Create Dashboard**: `POST /api/v1/grafana/dashboards`
- **List Dashboards**: `GET /api/v1/grafana/dashboards`
- **Get Dashboard**: `GET /api/v1/grafana/dashboards/{uid}`
- **Update Dashboard**: `PUT /api/v1/grafana/dashboards/{uid}`
- **Delete Dashboard**: `DELETE /api/v1/grafana/dashboards/{uid}`

##### Datasource Management
- **Create Datasource**: `POST /api/v1/grafana/datasources`

##### Alert Management
- **Create Alert Rule**: `POST /api/v1/grafana/alerts`

##### Template Management
- **List Templates**: `GET /api/v1/grafana/templates`
- **Get Template**: `GET /api/v1/grafana/templates/{name}`
- **Apply Template**: `POST /api/v1/grafana/templates/{name}/apply`

#### Example: Create Prometheus Datasource

```bash
curl -X POST http://your-api-server:8080/api/v1/grafana/datasources \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Sky Genesis Prometheus",
    "type": "prometheus",
    "url": "http://prometheus:9090",
    "access": "proxy"
  }'
```

#### Example: Create System Health Dashboard

```bash
curl -X POST http://your-api-server:8080/api/v1/grafana/dashboards \
  -H "Content-Type: application/json" \
  -d '{
    "dashboard": {
      "title": "Sky Genesis System Health",
      "tags": ["sky-genesis", "health"],
      "timezone": "browser",
      "panels": [
        {
          "title": "Active Connections",
          "type": "graph",
          "targets": [{
            "expr": "sky_genesis_active_connections{service=\"api\"}",
            "legendFormat": "Active Connections"
          }]
        }
      ],
      "time": {
        "from": "now-1h",
        "to": "now"
      },
      "refresh": "30s"
    },
    "overwrite": false
  }'
```

#### Example: Create Alert Rule

```bash
curl -X POST http://your-api-server:8080/api/v1/grafana/alerts \
  -H "Content-Type: application/json" \
  -d '{
    "title": "High Error Rate",
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
          "expr": "sky_genesis_error_rate_percent{service=\"api\"}",
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
   }'
```

#### Example: Apply Dashboard Template

```bash
curl -X POST http://your-api-server:8080/api/v1/grafana/templates/system-health/apply \
  -H "Content-Type: application/json" \
  -d '{
    "parameters": {
      "service": "api",
      "environment": "production",
      "title": "Production API Health"
    },
    "folder_id": 1,
    "overwrite": false
  }'
```

### Grafana Templates

The Sky Genesis API provides pre-built Grafana dashboard and alert templates for common monitoring scenarios. Templates can be applied with custom parameters to quickly set up monitoring infrastructure.

#### Available Templates

##### Dashboard Templates
- **system-health**: Comprehensive system monitoring dashboard with panels for active connections, response times, error rates, and resource usage
- **security-monitoring**: Threat detection and security alerts dashboard with authentication failures and access patterns
- **performance-overview**: Application performance metrics dashboard with throughput and latency monitoring
- **infrastructure-monitoring**: Server and infrastructure health dashboard with CPU, memory, and disk monitoring

##### Alert Templates
- **high-error-rate**: Alert for elevated error rates (>5% threshold)
- **high-response-time**: Alert for slow response times (>1000ms threshold)
- **service-down**: Alert for service unavailability (up == 0)
- **resource-exhaustion**: Alert for high resource usage (CPU >90%, Memory >90%)

#### Template Parameters

Templates accept parameters for customization:

```json
{
  "service": "api",
  "environment": "production",
  "title": "Custom Dashboard Title",
  "time_range": "1h",
  "refresh_interval": "30s",
  "prometheus_url": "http://prometheus.skygenesisenterprise.com:9090",
  "loki_url": "http://loki.skygenesisenterprise.com:3100"
}
```

#### Template API Usage

##### List Available Templates
```bash
curl http://your-api-server:8080/api/v1/grafana/templates
```

##### Get Template Details
```bash
curl http://your-api-server:8080/api/v1/grafana/templates/system-health
```

##### Apply Dashboard Template
```bash
curl -X POST http://your-api-server:8080/api/v1/grafana/templates/system-health/apply \
  -H "Content-Type: application/json" \
  -d '{
    "parameters": {
      "service": "api",
      "environment": "production",
      "title": "Production API Health Dashboard"
    },
    "folder_id": 1,
    "overwrite": false
  }'
```

##### Apply Alert Template
```bash
curl -X POST http://your-api-server:8080/api/v1/grafana/templates/high-error-rate/apply \
  -H "Content-Type: application/json" \
  -d '{
    "parameters": {
      "service": "api",
      "threshold": "5",
      "duration": "5m"
    }
  }'
```

### Configuration Requirements

#### Environment Variables
- `GRAFANA_URL`: Base URL of your Grafana instance (default: `https://grafana.skygenesisenterprise.com`)
- `GRAFANA_API_KEY_PATH`: Vault path to store Grafana API key (default: `grafana/api_key`)

#### Grafana API Key Setup
1. **Create API Key in Grafana**:
   - Go to Grafana Settings > API Keys
   - Create a new API key with Editor or Admin permissions
   - Copy the generated key

2. **Store API Key in Vault**:
   ```bash
   vault kv put secret/grafana/api_key key="your-grafana-api-key"
   ```

#### Permissions Required
The Grafana API key must have permissions for:
- Creating/reading/updating/deleting dashboards
- Creating/reading datasources
- Creating/reading alert rules

### Prometheus Data Source Setup

1. **Add Prometheus Data Source in Grafana**:
   ```
   URL: http://your-api-server:8080/api/v1/metrics/prometheus
   Scrape Interval: 30s
   ```

2. **Create Dashboard**:
   - Import the Sky Genesis dashboard template
   - Or create custom panels using the metrics below

### Key Metrics Available

#### System Metrics
```
sky_genesis_active_connections{service="api"} - Number of active connections
sky_genesis_total_requests_total{service="api"} - Total requests processed
sky_genesis_error_rate_percent{service="api"} - Error rate percentage
sky_genesis_average_response_time_ms{service="api"} - Average response time
sky_genesis_memory_usage_mb{service="api"} - Memory usage in MB
sky_genesis_cpu_usage_percent{service="api"} - CPU usage percentage
sky_genesis_database_connections{service="api"} - Active database connections
sky_genesis_cache_hit_rate_percent{service="api"} - Cache hit rate percentage
```

#### Health Status
- **Endpoint**: `/api/v1/health`
- **Data**: Overall system health status
- **Grafana Query**: Use JSON API data source or custom plugin

### Sample Grafana Dashboard Panels

#### 1. System Health Status
```json
{
  "title": "System Health",
  "type": "stat",
  "targets": [{
    "expr": "up{job=\"sky-genesis-api\"}",
    "legendFormat": "API Status"
  }]
}
```

#### 2. Active Connections
```json
{
  "title": "Active Connections",
  "type": "graph",
  "targets": [{
    "expr": "sky_genesis_active_connections{service=\"api\"}",
    "legendFormat": "Active Connections"
  }]
}
```

#### 3. Response Time
```json
{
  "title": "Average Response Time",
  "type": "graph",
  "targets": [{
    "expr": "sky_genesis_average_response_time_ms{service=\"api\"}",
    "legendFormat": "Response Time (ms)"
  }]
}
```

#### 4. Error Rate
```json
{
  "title": "Error Rate",
  "type": "graph",
  "targets": [{
    "expr": "sky_genesis_error_rate_percent{service=\"api\"}",
    "legendFormat": "Error Rate (%)"
  }]
}
```

## Alerting Rules

### Prometheus Alerting Examples

```yaml
groups:
  - name: sky-genesis-api
    rules:
      - alert: HighErrorRate
        expr: sky_genesis_error_rate_percent{service="api"} > 5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High error rate on Sky Genesis API"
          description: "Error rate is {{ $value }}%"

      - alert: HighResponseTime
        expr: sky_genesis_average_response_time_ms{service="api"} > 1000
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Slow response time on Sky Genesis API"
          description: "Average response time is {{ $value }}ms"

      - alert: APIDown
        expr: up{job="sky-genesis-api"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Sky Genesis API is down"
          description: "API service is not responding"
```

## Kubernetes Integration

### Readiness and Liveness Probes

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: sky-genesis-api
spec:
  containers:
  - name: api
    image: sky-genesis/api:latest
    ports:
    - containerPort: 8080
    readinessProbe:
      httpGet:
        path: /api/v1/ready
        port: 8080
      initialDelaySeconds: 30
      periodSeconds: 10
    livenessProbe:
      httpGet:
        path: /api/v1/alive
        port: 8080
      initialDelaySeconds: 60
      periodSeconds: 30
```

### ServiceMonitor for Prometheus Operator

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: sky-genesis-api
  namespace: monitoring
spec:
  selector:
    matchLabels:
      app: sky-genesis-api
  endpoints:
  - port: http
    path: /api/v1/metrics/prometheus
    interval: 30s
```

## Monitoring Best Practices

### 1. Endpoint Selection
- Use `/api/v1/health` for basic health checks
- Use `/api/v1/metrics/prometheus` for detailed metrics
- Use `/api/v1/status` for operational dashboards

### 2. Scraping Frequency
- Health checks: Every 30 seconds
- Detailed metrics: Every 30 seconds
- Status reports: Every 5 minutes

### 3. Alerting Strategy
- Critical: API down, high error rates (>10%)
- Warning: Slow response times (>1s), degraded components
- Info: Component status changes, version updates

### 4. Dashboard Organization
- **System Overview**: Overall health, uptime, version
- **Performance**: Response times, throughput, error rates
- **Resources**: CPU, memory, connections
- **Components**: Individual service health status

## Troubleshooting

### Common Issues

1. **Metrics not appearing in Grafana**
   - Check Prometheus data source configuration
   - Verify endpoint accessibility: `curl http://api:8080/api/v1/metrics/prometheus`
   - Check Prometheus scrape target status

2. **Health checks failing**
   - Verify component dependencies (Vault, database, etc.)
   - Check network connectivity between components
   - Review application logs for error details

3. **High latency in metrics collection**
   - Reduce scraping frequency if needed
   - Check system resource usage
   - Optimize database queries in health checks

### Debug Commands

```bash
# Test health endpoint
curl -s http://localhost:8080/api/v1/health | jq

# Test Prometheus metrics
curl -s http://localhost:8080/api/v1/metrics/prometheus | head -20

# Test detailed status
curl -s http://localhost:8080/api/v1/status | jq .health

# Test component health
curl -s http://localhost:8080/api/v1/health/vault | jq
```

## Grafana API Best Practices

### Authentication and Security
- Store Grafana API keys securely in Vault
- Use HTTPS for all Grafana API communications
- Implement proper access controls and audit logging
- Rotate API keys regularly for security

### Dashboard Management
- Use templates for consistent dashboard creation
- Organize dashboards in folders for better management
- Implement versioning for critical dashboards
- Document dashboard purposes and data sources

### Alert Configuration
- Set appropriate alert thresholds based on your environment
- Use descriptive alert names and descriptions
- Configure alert routing to appropriate teams
- Regularly review and tune alert rules

### Performance Optimization
- Cache template results when possible
- Use batch operations for bulk dashboard creation
- Monitor API rate limits and implement backoff strategies
- Optimize dashboard refresh intervals based on data freshness needs

## Security Considerations

- All monitoring endpoints are publicly accessible (by design for monitoring)
- Consider network-level restrictions for production environments
- Use HTTPS for all monitoring traffic
- Implement authentication for sensitive monitoring data if required
- Grafana API keys should be stored securely and rotated regularly

## Performance Impact

- Health checks are designed to be lightweight (< 100ms)
- Metrics collection is optimized for frequent polling
- Component health checks run in parallel where possible
- Consider caching for high-traffic monitoring scenarios
- Grafana API operations may have rate limits depending on your Grafana configuration</content>
</xai:function_call<parameter name="filePath">docs/monitoring-grafana-integration.md