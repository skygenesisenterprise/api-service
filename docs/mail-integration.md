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
│                   Stalwart Mail Server                       │
│  ┌─────────────────┐    ┌─────────────────┐                 │
│  │   JMAP API      │    │   SMTP/IMAP     │                 │
│  │   (Internal)    │    │   (Internal)    │                 │
│  │                 │    │                 │                 │
│  │ • Message Ops   │    │ • Send/Receive  │                 │
│  │ • Mailbox Mgmt  │    │ • Storage       │                 │
│  │ • Search        │    │ • Protocols     │                 │
│  └─────────────────┘    └─────────────────┘                 │
└─────────────────────────────────────────────────────────────┘
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
STALWART_BASE_URL=https://stalwart-mail.internal
STALWART_JMAP_PATH=/jmap
STALWART_TIMEOUT_SECONDS=30

# mTLS Configuration
STALWART_CLIENT_CERT=/etc/sge/certs/stalwart.crt
STALWART_CLIENT_KEY=/etc/sge/certs/stalwart.key
STALWART_CA_CERT=/etc/sge/certs/ca.crt

# Performance Tuning
STALWART_MAX_CONNECTIONS=100
STALWART_CONNECT_TIMEOUT=5
STALWART_REQUEST_TIMEOUT=30
```

### Vault Paths
- `secret/stalwart/client_cert`: Client certificate
- `secret/stalwart/client_key`: Private key
- `secret/stalwart/ca_cert`: CA certificate

## Deployment Considerations

### Network Security
- **Internal Network**: Stalwart only accessible from SGE
- **Firewall Rules**: Restrict Stalwart to SGE IP ranges
- **TLS Everywhere**: All communication encrypted

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
- **End-to-End Encryption**: PGP/SMIME support
- **Audit Logging**: Comprehensive audit trails
- **Data Retention**: Configurable retention policies
- **GDPR Compliance**: Data portability and deletion