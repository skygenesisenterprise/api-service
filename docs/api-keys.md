# API Keys

## Overview

API keys are used to authenticate requests to the Sky Genesis Enterprise API service. All API keys are prefixed with `sk_` for easy identification and security.

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

API keys can be created through the REST API with different types and optional certificate authentication.

### Basic Key Creation

```http
POST /api/v1/keys
Content-Type: application/json

{
  "key_type": "client",
  "tenant": "my-tenant",
  "ttl": 3600
}
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
POST /api/v1/keys/with-certificate
Content-Type: application/json

{
  "key_type": "server",
  "tenant": "my-tenant",
  "ttl": 7200,
  "certificate_type": "rsa"
}
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

## Security Notes

- API keys are only returned once during creation
- Store keys securely and never expose them in logs or version control
- Rotate keys regularly for enhanced security
- Use appropriate key types for different access patterns