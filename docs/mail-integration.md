# Mail Integration with Stalwart

## Overview

The Mail module integrates with Stalwart Mail Server as a secure proxy, providing a unified API while maintaining strict security boundaries. Stalwart acts as the core mail engine, handling SMTP, IMAP, and JMAP protocols internally.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Sky Genesis Enterprise                   │
│  ┌─────────────────┐    ┌─────────────────┐                 │
│  │   Mail Module   │    │   Stalwart      │                 │
│  │   (SGE-Core)    │    │   Client        │                 │
│  │                 │    │                 │                 │
│  │ • Auth & Authz  │◄──►│ • JMAP/HTTP     │                 │
│  │ • Proxy         │    │ • mTLS          │                 │
│  │ • Policies      │    │ • Headers       │                 │
│  └─────────────────┘    └─────────────────┘                 │
└─────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────┐
│            Official Stalwart Mail Server                    │
│            https://stalwart.skygenesisenterprise.com        │
│  ┌─────────────────┐    ┌─────────────────┐                 │
│  │   JMAP API      │    │   SMTP/IMAP     │                 │
│  │   (mTLS Only)   │    │   (Internal)    │                 │
│  │                 │    │                 │                 │
│  │ • Message Ops   │    │ • Send/Receive  │                 │
│  │ • Mailbox Mgmt  │    │ • Storage       │                 │
│  │ • Search        │    │ • Protocols     │                 │
│  └─────────────────┘    └─────────────────┘                 │
└─────────────────────────────────────────────────────────────┘
```

## Dynamic Server Routing

### Server Resolution Architecture
The Mail module supports dynamic routing to multiple Stalwart servers based on user context, tenant, or geographic location. This enables:

- **Multi-tenant deployments**: Different tenants can use different Stalwart instances
- **Geographic distribution**: Users routed to nearest regional server
- **Load balancing**: Distribution of load across multiple servers
- **Disaster recovery**: Automatic failover to backup servers

### Server Resolver Interface
```rust
#[async_trait]
pub trait StalwartServerResolver: Send + Sync {
    async fn resolve_server(&self, user: &User, operation: &str) -> Result<String, StalwartError>;
}
```

### Available Resolvers

#### Official Resolver (Default)
Routes all requests to the official SGE Stalwart server:
```rust
pub async fn new_official(vault_client: Arc<VaultClient>) -> Result<Self, StalwartError>
```
- **URL**: `https://stalwart.skygenesisenterprise.com`
- **Use Case**: Single centralized deployment

#### Tenant-Based Resolver
Routes requests based on user tenant:
```rust
pub async fn new_tenant_based(vault_client: Arc<VaultClient>) -> Result<Self, StalwartError>
```
- **Logic**: Extracts tenant from user roles (`tenant:{name}`)
- **Configuration**: `secret/stalwart/tenants/{tenant}/server_url`
- **Use Case**: Multi-tenant with dedicated servers

#### Region-Based Resolver
Routes requests based on geographic region:
```rust
pub async fn new_region_based(vault_client: Arc<VaultClient>, default_region: String) -> Result<Self, StalwartError>
```
- **Logic**: Determines region from user metadata or tenant mapping
- **Configuration**: `secret/stalwart/regions/{region}/server_url`
- **Use Case**: Global deployment with regional servers

### Client Initialization
```rust
pub async fn new(
    vault_client: Arc<VaultClient>,
    server_resolver: Arc<dyn StalwartServerResolver>
) -> Result<Self, StalwartError>
```
**Process:**
1. Accept server resolver for dynamic routing
2. Load mTLS certificates from Vault
3. Configure HTTP client with mTLS
4. Return configured client with routing capability

### Routing Decision Flow
```
User Request → Extract Context (Tenant/Region/Operation)
                   ↓
            Server Resolver → Determine Target Server
                   ↓
            Route to Appropriate Stalwart Instance
                   ↓
            Apply mTLS + SGE Headers
                   ↓
            Execute Operation
```

## Configuration Examples

### Single Server (Official)
```rust
// Use official SGE Stalwart server
let stalwart_client = StalwartClient::new_official(vault_client).await?;
```

**Vault Configuration:**
```
secret/stalwart/client_cert: <certificate>
secret/stalwart/client_key: <private_key>
secret/stalwart/ca_cert: <ca_certificate>
```

### Multi-Tenant Deployment
```rust
// Route based on tenant
let stalwart_client = StalwartClient::new_tenant_based(vault_client).await?;
```

**Vault Configuration:**
```
secret/stalwart/client_cert: <certificate>
secret/stalwart/client_key: <private_key>
secret/stalwart/ca_cert: <ca_certificate>
secret/stalwart/tenants/acme/server_url: "https://stalwart-acme.sge.internal"
secret/stalwart/tenants/globex/server_url: "https://stalwart-globex.sge.internal"
```

**User Role Configuration:**
- User roles: `["employee", "tenant:acme"]` → Routes to `stalwart-acme.sge.internal`
- User roles: `["employee", "tenant:globex"]` → Routes to `stalwart-globex.sge.internal`

### Geographic Distribution
```rust
// Route based on region
let stalwart_client = StalwartClient::new_region_based(vault_client, "us-east-1".to_string()).await?;
```

**Vault Configuration:**
```
secret/stalwart/client_cert: <certificate>
secret/stalwart/client_key: <private_key>
secret/stalwart/ca_cert: <ca_certificate>
secret/stalwart/regions/us-east-1/server_url: "https://stalwart-us-east.sge.internal"
secret/stalwart/regions/eu-west-1/server_url: "https://stalwart-eu-west.sge.internal"
secret/stalwart/regions/ap-southeast-1/server_url: "https://stalwart-ap-southeast.sge.internal"
```

### Custom Resolver
```rust
// Implement custom routing logic
#[derive(Clone)]
struct CustomResolver {
    vault_client: Arc<VaultClient>,
    routing_rules: HashMap<String, String>,
}

#[async_trait]
impl StalwartServerResolver for CustomResolver {
    async fn resolve_server(&self, user: &User, operation: &str) -> Result<String, StalwartError> {
        // Custom routing logic based on user attributes, operation type, etc.
        // Example: Route based on user department, time of day, load balancing, etc.
        todo!("Implement custom routing logic")
    }
}
```

## Communication Protocol

### Primary Protocol: JMAP over HTTP
- **Standard**: JMAP (RFC 8620) for mail operations
- **Transport**: HTTP/1.1 with mTLS
- **Authentication**: Internal headers + client certificates

### Fallback Protocol: HTTP REST
- **Custom REST API** for operations not covered by JMAP
- **Same security model** as JMAP
- **Consistent request/response format**

## Security Model

### Mutual TLS (mTLS)
- **Client Certificate**: SGE-Core presents Vault-signed certificate
- **Server Verification**: Stalwart validates certificate chain
- **Certificate Rotation**: Automated via Vault

### Internal Headers
Every request to Stalwart includes SGE-specific headers:

```
X-SGE-User-ID: uuid-of-authenticated-user
X-SGE-Tenant: tenant-identifier
X-SGE-Session-ID: unique-session-identifier
X-SGE-Request-ID: unique-request-identifier
X-SGE-Timestamp: unix-timestamp
X-SGE-Signature: hmac-signature-of-request
```

### Authentication Flow
```
1. Client → SGE (JWT/API Key)
2. SGE validates → Extracts user context
3. SGE → Stalwart (mTLS + Headers)
4. Stalwart trusts SGE → Processes request
5. Stalwart → SGE (Response)
6. SGE → Client (Filtered response)
```

## Request Mapping

### JMAP Method Mapping

#### Mailbox Operations
```
SGE: GET /api/v1/mail/mailboxes
JMAP: {
  "methodCalls": [
    ["Mailbox/get", {
      "accountId": "user@domain",
      "ids": null
    }, "0"]
  ]
}
```

#### Message Operations
```
SGE: GET /api/v1/mail/messages?mailbox=INBOX
JMAP: {
  "methodCalls": [
    ["Email/query", {
      "accountId": "user@domain",
      "filter": {"inMailbox": "INBOX"}
    }, "0"],
    ["Email/get", {
      "accountId": "user@domain",
      "#ids": {
        "resultOf": "0",
        "name": "Email/query",
        "path": "/ids"
      }
    }, "1"]
  ]
}
```

#### Send Operations
```
SGE: POST /api/v1/mail/messages
JMAP: {
  "methodCalls": [
    ["Email/set", {
      "accountId": "user@domain",
      "create": {
        "draft": {
          "mailboxIds": {"Draft": true},
          "subject": "Test",
          "body": "..."
        }
      }
    }, "0"],
    ["EmailSubmission/set", {
      "accountId": "user@domain",
      "create": {
        "submission": {
          "emailId": "#0",
          "envelope": {...}
        }
      }
    }, "1"]
  ]
}
```

## Stalwart Client Implementation

### Client Structure
```rust
pub struct StalwartClient {
    client: Client,                    // HTTP client with mTLS
    base_url: String,                  // Stalwart JMAP endpoint
    cert_path: String,                 // Client certificate path
    key_path: String,                  // Private key path
    vault_client: Arc<VaultClient>,    // For certificate rotation
}
```

### Key Methods

#### `execute_jmap_request(request: JmapRequest) -> Result<JmapResponse>`
- Serializes JMAP request to JSON
- Adds SGE headers and mTLS
- Sends to Stalwart JMAP endpoint
- Parses and returns response

#### `proxy_request(path: &str, method: Method, body: Option<Value>) -> Result<Value>`
- Generic HTTP proxy method
- Handles non-JMAP operations
- Maintains security context

#### `health_check() -> Result<bool>`
- Verifies Stalwart connectivity
- Validates mTLS configuration
- Checks service availability

### Certificate Management
- **Automatic Rotation**: Certificates rotated before expiration
- **Vault Integration**: Certificates stored and managed in Vault
- **Hot Reloading**: Certificate updates without service restart

## Error Handling

### Stalwart Error Mapping
Stalwart errors are mapped to SGE error codes:

```
Stalwart "notFound" → SGE 404 Not Found
Stalwart "forbidden" → SGE 403 Forbidden
Stalwart "overQuota" → SGE 429 Too Many Requests
Stalwart "serverError" → SGE 500 Internal Server Error
```

### Network Error Handling
- **Timeout**: Configurable timeouts with retry logic
- **Connection Failure**: Circuit breaker pattern
- **Certificate Issues**: Automatic certificate refresh

## Performance Optimization

### Connection Pooling
- HTTP client maintains connection pool
- mTLS handshake optimization
- Keep-alive connections

### Caching
- **Mailbox Metadata**: Cached for 5 minutes
- **User Quotas**: Cached for 1 hour
- **Certificate Validation**: Cached until expiration

### Async Processing
- Non-blocking I/O for all Stalwart operations
- Concurrent request handling
- Streaming for large attachments

## Monitoring & Observability

### Metrics Collection
- Request/response latency
- Error rates by operation type
- Stalwart connectivity status
- Certificate expiration warnings

### Logging
- Request/response logging with correlation IDs
- Security event logging
- Performance monitoring
- Audit trails for sensitive operations

### Health Checks
- Stalwart service availability
- mTLS certificate validity
- Queue depth monitoring
- Storage capacity checks

## Configuration

### Environment Variables
```bash
# Stalwart Connection
STALWART_JMAP_PATH=/jmap
STALWART_TIMEOUT_SECONDS=30

# Routing Configuration
STALWART_ROUTING_MODE=official  # official|tenant|region
STALWART_DEFAULT_REGION=us-east-1  # For region-based routing

# mTLS Configuration
STALWART_CLIENT_CERT=/etc/sge/certs/stalwart.crt
STALWART_CLIENT_KEY=/etc/sge/certs/stalwart.key
STALWART_CA_CERT=/etc/sge/certs/ca.crt

# Performance Tuning
STALWART_MAX_CONNECTIONS=100
STALWART_CONNECT_TIMEOUT=5
STALWART_REQUEST_TIMEOUT=30
```

### Vault Secrets

#### Core Authentication Secrets
- **`secret/stalwart/client_cert`**: PEM-encoded client certificate for mTLS
- **`secret/stalwart/client_key`**: PEM-encoded private key for mTLS
- **`secret/stalwart/ca_cert`**: PEM-encoded CA certificate for server verification

#### Routing Configuration Secrets

**For Tenant-Based Routing:**
- **`secret/stalwart/tenants/{tenant}/server_url`**: Server URL for specific tenant
- Example: `secret/stalwart/tenants/acme/server_url` → `"https://stalwart-tenant-acme.sge.internal"`

**For Region-Based Routing:**
- **`secret/stalwart/regions/{region}/server_url`**: Server URL for specific region
- Example: `secret/stalwart/regions/us-east-1/server_url` → `"https://stalwart-us-east.sge.internal"`

**Certificate Requirements:**
- Issued by SGE Certificate Authority
- Extended Key Usage: Client Authentication
- Subject Alternative Name: SGE service identifier
- Valid for at least 90 days
- Must be valid for all target Stalwart servers

## Deployment Considerations

### Network Security
- **Official Endpoint**: All traffic routed through `https://stalwart.skygenesisenterprise.com`
- **mTLS Required**: Mutual TLS authentication mandatory
- **IP Whitelisting**: SGE-Core IPs whitelisted at network level
- **TLS 1.3**: Minimum TLS version enforced

### High Availability
- **Load Balancing**: Multiple Stalwart instances
- **Failover**: Automatic failover between instances
- **Data Replication**: Mailbox data synchronization

### Backup & Recovery
- **Mail Data**: Regular backups of mailbox data
- **Configuration**: Stalwart configuration backup
- **Disaster Recovery**: Cross-region replication

## Future Enhancements

### Advanced Features
- **Push Notifications**: Real-time mail delivery notifications
- **Advanced Search**: Full-text search with indexing
- **Mail Rules**: Server-side filtering and organization
- **Calendar Integration**: Meeting requests and calendar sync

### Protocol Extensions
- **IMAP Proxy**: Direct IMAP access through SGE
- **SMTP Submission**: Secure SMTP submission proxy
- **WebSocket Support**: Real-time updates via WebSocket

### Compliance & Security
- **Dynamic Routing**: Secure routing to appropriate servers based on context
- **End-to-End Encryption**: PGP/SMIME support
- **Audit Logging**: Comprehensive audit trails with server routing information
- **Data Residency**: Geographic data placement compliance
- **GDPR Compliance**: Data portability and deletion with proper routing