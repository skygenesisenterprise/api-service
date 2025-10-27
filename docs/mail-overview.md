# Mail Module Overview

## Introduction

The Mail module is a secure proxy gateway that provides unified access to Stalwart Mail Server within the Sky Genesis Enterprise ecosystem. It handles all mail-related operations through the `/api/v1/mail/` endpoints, ensuring proper authentication, authorization, and secure communication with the internal mail server.

## Architecture

The Mail module follows the same layered architecture as other SGE modules:

```
┌─────────────────────────────────────────────────────────────┐
│                    Client Layer                             │
│  GET /api/v1/mail/messages?folder=inbox                     │
└─────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────┐
│                    HTTP Layer (Warp)                        │
│  ┌─────────────────┐    ┌─────────────────┐                 │
│  │   Mail Routes   │    │   JWT/Auth      │                 │
│  │ • /api/v1/mail/*│    │ • Middleware    │                 │
│  └─────────────────┘    └─────────────────┘                 │
└─────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────┐
│                   Business Layer                            │
│  ┌─────────────────┐    ┌─────────────────┐                 │
│  │ Mail Controller │    │   Mail Service  │                 │
│  │ • Request       │    │ • Auth Check    │                 │
│  │ • Response      │    │ • Policy Enf.   │                 │
│  └─────────────────┘    └─────────────────┘                 │
└─────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────┐
│                   Integration Layer                         │
│  ┌─────────────────┐    ┌─────────────────┐                 │
│  │ Stalwart Client │    │   Vault Client  │                 │
│  │ • JMAP/HTTP     │    │ • mTLS Certs    │                 │
│  │ • Proxy         │    │ • Internal Auth │                 │
│  └─────────────────┘    └─────────────────┘                 │
└─────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────┐
│                   Stalwart Mail Server                       │
│  • SMTP/IMAP/JMAP    • Internal API    • mTLS Only          │
└─────────────────────────────────────────────────────────────┘
```

## Core Principles

### Secure Proxy Gateway
- All mail operations go through SGE Mail module
- Stalwart only trusts SGE-Core (mTLS or Vault tokens)
- No direct client access to Stalwart

### Authentication & Authorization
- JWT token validation (Keycloak)
- API key validation (Vault)
- User context injection
- Tenant isolation

### Request Transformation
- Client requests → SGE validation → Stalwart proxy
- Header injection (X-SGE-User-ID, X-SGE-Tenant)
- Request normalization
- Response filtering

### Centralized Control
- Unified logging and metrics
- Policy enforcement
- Rate limiting
- Audit trails

## Module Components

### Mail Routes (`mail_routes.rs`)
- Route definitions for `/api/v1/mail/*`
- Middleware application (auth, validation)
- Request routing to controllers

### Mail Controller (`mail_controller.rs`)
- HTTP request/response handling
- Input validation and sanitization
- Error handling and formatting
- Response transformation

### Mail Service (`mail_service.rs`)
- Business logic for mail operations
- Authentication and authorization checks
- Policy enforcement
- Stalwart client orchestration

### Stalwart Client (`stalwart_client.rs`)
- HTTP/JMAP client for Stalwart communication
- mTLS certificate handling
- Request proxying
- Response processing

## Security Model

### Authentication Flow
```
Client Request (JWT) → SGE Auth Middleware → User Validation
                                                           ↓
                                                    Policy Check → Tenant Context
                                                           ↓
                                                Stalwart Request (mTLS)
```

### Authorization Policies
- **User Access**: Users can only access their own mailboxes
- **Tenant Isolation**: Multi-tenant separation enforced
- **Operation Limits**: Rate limiting and quota management
- **Content Filtering**: Malware scanning and content policies

### Internal Authentication
- **mTLS**: Mutual TLS with Vault-signed certificates
- **Internal Tokens**: Vault-generated tokens for Stalwart trust
- **Header Injection**: SGE-specific headers for context

## Data Flow

### Mail Message Retrieval
```
1. Client: GET /api/v1/mail/messages?folder=inbox
2. SGE: Validate JWT, extract user context
3. SGE: Check access policies
4. SGE: Transform to Stalwart request
5. Stalwart: Process via JMAP/HTTP
6. SGE: Filter and log response
7. Client: Receive mail data
```

### Mail Sending
```
1. Client: POST /api/v1/mail/send
2. SGE: Validate JWT and content
3. SGE: Apply sending policies
4. SGE: Route to Stalwart SMTP proxy
5. Stalwart: Send via SMTP
6. SGE: Log and confirm delivery
```

## Integration Points

### External Dependencies
- **Stalwart Mail Server**: Core mail engine
- **Keycloak**: User authentication
- **Vault**: Secrets and certificates
- **PostgreSQL**: Audit logs and metadata

### Internal Dependencies
- **Auth Service**: JWT validation
- **Key Service**: API key validation
- **Vault Client**: Certificate management
- **Logging**: Centralized audit trails

## Configuration

### Environment Variables
```bash
# Stalwart Configuration
STALWART_URL=https://stalwart-mail.internal
STALWART_JMAP_PORT=8080
STALWART_SMTP_PORT=587

# mTLS Configuration
STALWART_CERT_PATH=/etc/sge/certs/stalwart.crt
STALWART_KEY_PATH=/etc/sge/certs/stalwart.key

# Mail Policies
MAIL_RATE_LIMIT=100/minute
MAIL_ATTACHMENT_MAX_SIZE=10MB
MAIL_RETENTION_DAYS=365
```

### Policy Configuration
- User quotas and limits
- Content filtering rules
- Spam detection settings
- Backup and retention policies

## Monitoring & Observability

### Metrics
- Request/response counts
- Latency measurements
- Error rates by endpoint
- Mail volume statistics

### Logging
- Audit logs for all operations
- Security events
- Performance monitoring
- Error tracking

### Health Checks
- Stalwart connectivity
- Certificate validity
- Queue status
- Storage capacity

## Future Extensions

### Advanced Features
- **Mail Filtering**: Server-side rules and filters
- **Search**: Full-text search across mailboxes
- **Contacts**: Address book management
- **Calendar**: Calendar integration
- **Push Notifications**: Real-time mail notifications

### Scalability
- **Load Balancing**: Multiple Stalwart instances
- **Caching**: Redis for session and metadata
- **Queue Management**: Async processing for large operations

### Compliance
- **Encryption**: End-to-end encryption
- **Retention**: Configurable data retention
- **Audit**: Comprehensive audit trails
- **GDPR**: Data portability and deletion