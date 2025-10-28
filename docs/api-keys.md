# API Keys

## Overview

API keys are used to authenticate requests to the Sky Genesis Enterprise API service. All API keys are prefixed with `sk_` for easy identification and security. Each API key has a specific status that determines its environment access level.

## API Key Status

API keys can have one of two statuses:

- **`sandbox`**: For development, testing, and staging environments
- **`production`**: For live production environments

### Status Behavior

- **Sandbox keys** can only access sandbox/test resources
- **Production keys** can access both sandbox and production resources
- All API keys are tenant-scoped for isolation

### Access Matrix

| Key Status    | Sandbox Access | Production Access |
|---------------|----------------|-------------------|
| sandbox      | ✅            | ❌                |
| production   | ✅            | ✅                |

## Key Format

All API keys follow the format:
```
sk_<random_string>
```

Example:
```
sk_a1b2c3d4e5f678901234567890123456789
```

## Creating API Keys

### Basic Key Creation

```http
POST /api/keys?sandbox&type=client&tenant=my-tenant&ttl=3600
```

Or with explicit status:

```http
POST /api/keys?status=sandbox&type=client&tenant=my-tenant&ttl=3600
```

Response:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "key": "sk_sandbox_a1b2c3d4e5f678901234567890123456789",
  "key_type": "client",
  "tenant": "my-tenant",
  "status": "sandbox",
  "ttl": 3600,
  "created_at": "2024-01-15T10:30:00Z",
  "permissions": ["read"],
  "vault_path": "secret/client",
  "certificate": null
}
```

### Convenience Endpoints

```http
# Create sandbox key
POST /api/keys/sandbox?type=client&tenant=my-tenant&ttl=3600

# Create production key
POST /api/keys/production?type=client&tenant=my-tenant&ttl=3600
```

Response:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "key": "sk_a1b2c3d4e5f678901234567890123456789",
  "key_type": "Client",
  "tenant": "my-tenant",
  "ttl": 3600,
  "created_at": "2024-01-15T10:30:00Z",
  "permissions": ["read"],
  "vault_path": "secret/client",
  "certificate": null
}
```

### Key with Certificate

```http
POST /api/keys/with-certificate?sandbox&type=server&tenant=my-tenant&ttl=7200&cert_type=rsa
```

Or using convenience endpoints:

```http
# Sandbox key with certificate
POST /api/keys/sandbox/with-certificate?type=server&tenant=my-tenant&ttl=7200&cert_type=rsa

# Production key with certificate
POST /api/keys/production/with-certificate?type=server&tenant=my-tenant&ttl=7200&cert_type=ecdsa
```

## Authentication

Use the API key in the request headers:

```http
Authorization: Bearer sk_a1b2c3d4e5f678901234567890123456789
```

or

```http
X-API-Key: sk_a1b2c3d4e5f678901234567890123456789
X-Key-Type: client
```

## Key Types

- **Client**: For client applications
- **Server**: For server-to-server communication
- **Database**: For database access

## Key Management

### List Keys

```http
GET /api/keys?tenant=my-tenant
```

### Get Specific Key

```http
GET /api/keys/550e8400-e29b-41d4-a716-446655440000
```

### Revoke Key

```http
DELETE /api/keys/550e8400-e29b-41d4-a716-446655440000
```

## Rate Limiting

Rate limits vary by key status and operation type:

- **Sandbox keys**: Standard limits for testing (1000 reads/min, 100 writes/min)
- **Production keys**: Higher limits for production workloads (2000 reads/min, 200 writes/min)

## Security Considerations

1. **Environment Separation**: Sandbox keys cannot access production data
2. **Tenant Isolation**: Keys are scoped to specific tenants
3. **Certificate Validation**: Optional certificate-based authentication
4. **Audit Logging**: All key operations are logged
5. **TTL Enforcement**: Keys expire automatically based on TTL

## Best Practices

1. Use sandbox keys for development and testing
2. Rotate keys regularly, especially production keys
3. Use certificates for enhanced security in production
4. Monitor key usage and revoke unused keys
5. Set appropriate TTL values based on use case
6. Store keys securely and never expose them in logs or version control

## Error Responses

```json
{
  "error": {
    "code": "ENVIRONMENT_ACCESS_DENIED",
    "message": "API key with status 'sandbox' cannot access 'production' environment"
  }
}
```

```json
{
  "error": {
    "code": "INSUFFICIENT_PERMISSIONS",
    "message": "Missing required permissions: [\"write\", \"admin\"]"
  }
}
```