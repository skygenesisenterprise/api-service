# Sky Genesis Enterprise API - Protocol Integrations

This document provides an overview of the native protocol integrations implemented in the SGE Enterprise API Service.

## Architecture Overview

The SGE Enterprise API Service implements a modular architecture with native support for multiple protocols, enabling seamless federation between Sky Genesis Enterprise services (Aether Mail, Aether Office, Aether Search, etc.).

## Implemented Protocols

### v1 - Security & Infrastructure (Completed)

#### 🔐 OAuth2 / OIDC + FIDO2 - Identity and Security
- **OIDC Provider**: Keycloak integration with full OIDC discovery and token validation
- **FIDO2/WebAuthn**: Hardware-based authentication with U2F support
- **Endpoints**:
  - `POST /api/v1/auth/oidc/login` - Initiate OIDC authorization
  - `GET /api/v1/auth/oidc/callback` - OIDC callback handler
  - `POST /api/v1/auth/fido2/register/start` - Start FIDO2 registration
  - `POST /api/v1/auth/fido2/auth/start` - Start FIDO2 authentication

#### 🕸️ IPSec / Tailscale / WireGuard - Internal Private Network
- **WireGuard**: VPN configuration management and peer handling
- **Tailscale**: Authentication and status monitoring
- **Endpoints**:
  - `GET /vpn/peers` - List VPN peers
  - `POST /vpn/peers` - Add VPN peer
  - `GET /tailscale/status` - Tailscale status
  - `GET /tailscale/ip` - Get Tailscale IP

#### 🔑 Vault Integration - Certificate & Key Management
- **Auto-rotation**: Automatic certificate renewal before expiration
- **PKI Operations**: Certificate issuance and revocation
- **Transit Engine**: Military-grade encryption operations

### v2 - Communication & Interoperability (Completed)

#### 🗨️ XMPP / WebSocket - Real-time Presence and Chat
- **Presence Management**: Online, away, busy, offline status
- **Real-time Chat**: Direct messages and group chats
- **WebSocket Support**: Bidirectional communication
- **Endpoints**:
  - `WS /ws/connect` - WebSocket connection
  - `GET /xmpp/presence` - Get all presence status
  - `POST /xmpp/presence` - Update presence

#### ⚡ gRPC / QUIC - Inter-service Performance
- **Protocol Buffers**: Efficient binary serialization
- **QUIC Transport**: HTTP/3 support for reduced latency
- **Service Proxies**:
  - Mail Service: `POST /api/v1/mail/send`
  - Search Service: `GET /api/v1/search`
- **Endpoints**:
  - `POST /api/v1/mail/send` - Send email via gRPC
  - `GET /api/v1/search` - Search via gRPC proxy

#### 📁 WebDAV / CalDAV / CardDAV - File & Data Management
- **WebDAV**: File management operations (PROPFIND, PROPPATCH, MKCOL, etc.)
- **CalDAV**: Calendar event management
- **CardDAV**: Contact management
- **Aether Office Integration**: Seamless file sync
- **Endpoints**:
  - `PROPFIND /api/v1/dav/files/*` - WebDAV operations
  - `POST /api/v1/dav/calendar` - Create calendar
  - `POST /api/v1/dav/contacts` - Create address book

#### 📊 OpenTelemetry - Sovereign Observability
- **Traces**: Distributed tracing with OTLP export
- **Metrics**: Prometheus-compatible metrics
- **Logs**: Structured logging with trace correlation
- **Self-hosted**: No external dependencies
- **Endpoints**:
  - `GET /api/v1/metrics` - Metrics export
  - `GET /api/v1/telemetry/traces` - Trace data
  - `GET /api/v1/telemetry/health` - Observability health

## Security Features

### End-to-End Encryption
- **TLS 1.3**: All communications encrypted
- **mTLS**: Mutual TLS for service-to-service communication
- **Perfect Forward Secrecy**: Ephemeral key exchange

### Authentication Methods
- **OIDC Tokens**: JWT validation with JWKS
- **API Keys**: Header-based authentication
- **FIDO2**: Hardware security keys
- **Client Certificates**: mTLS authentication

### Authorization
- **RBAC**: Role-based access control
- **ACL**: Attribute-based permissions
- **Vault Policies**: Fine-grained secret access

## Network Architecture

### Internal Network (VPN)
- **Subnet**: 10.128.x.x
- **WireGuard**: Kernel-level VPN
- **Tailscale**: Zero-config VPN
- **Isolated**: Complete traffic isolation

### Service Mesh
- **gRPC**: Efficient inter-service communication
- **QUIC**: Reduced latency transport
- **Load Balancing**: Automatic service discovery

## Deployment Considerations

### Infrastructure Requirements
- **Rust Runtime**: Tokio async runtime
- **Keycloak**: OIDC provider
- **Vault**: Secret management
- **PostgreSQL**: Primary database
- **Redis**: Session and cache storage

### Monitoring & Observability
- **OpenTelemetry Collector**: Centralized telemetry
- **Prometheus**: Metrics collection
- **Grafana**: Visualization dashboards
- **Self-hosted**: No external SaaS dependencies

## Roadmap v3 (Future)

### Federation Protocols
- **ActivityPub**: Social network federation
- **LDAP**: Enterprise directory integration
- **SAML**: Government and institutional SSO
- **GraphQL**: Unified API gateway

### Advanced Security
- **SCAP**: Automated security compliance
- **NetFlow**: Network traffic analysis
- **Redfish**: Hardware management

## API Examples

### OIDC Authentication
```bash
# Initiate login
curl -X POST http://localhost:8080/api/v1/auth/oidc/login \
  -H "Content-Type: application/json" \
  -d '{"redirect_uri": "http://localhost:3000/callback"}'

# Handle callback
curl "http://localhost:8080/api/v1/auth/oidc/callback?code=...&state=..."
```

### WebSocket Presence
```javascript
const ws = new WebSocket('ws://localhost:8080/ws/connect');

// Send presence update
ws.send(JSON.stringify({
  type: 'PresenceUpdate',
  user_id: 'user123',
  status: 'online',
  status_message: 'Available'
}));

// Subscribe to presence updates
ws.send(JSON.stringify({
  type: 'Subscribe',
  channel: 'presence:user123'
}));
```

### gRPC Email Sending
```bash
curl -X POST http://localhost:8080/api/v1/mail/send \
  -H "Content-Type: application/json" \
  -d '{
    "to": ["recipient@example.com"],
    "subject": "Test Email",
    "body": "Hello from SGE API!"
  }'
```

### WebDAV File Operations
```bash
# List files
curl -X PROPFIND http://localhost:8080/api/v1/dav/files/ \
  -H "Depth: 1"

# Create collection
curl -X MKCOL http://localhost:8080/api/v1/dav/files/new-folder/
```

## Configuration

### Environment Variables
```bash
# OIDC/Keycloak
KEYCLOAK_URL=https://keycloak.skygenesisenterprise.com
KEYCLOAK_REALM=skygenesisenterprise

# FIDO2
FIDO2_RP_ID=localhost
FIDO2_RP_ORIGIN=http://localhost:8080

# Vault
VAULT_ADDR=https://vault.skygenesisenterprise.com
VAULT_ROLE_ID=...
VAULT_SECRET_ID=...

# VPN
VPN_INTERFACE=wg0
TAILSCALE_AUTH_KEY=...

# OpenTelemetry
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
```

This implementation provides a solid foundation for a sovereign, secure, and interoperable enterprise API service with native protocol support.