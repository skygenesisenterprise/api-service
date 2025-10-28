# API Endpoints Documentation

## Base URL
All API endpoints are served under `http://localhost:3000` in development.

## Authentication
Most endpoints require authentication via JWT tokens in the `Authorization` header:
```
Authorization: Bearer <jwt_token>
```

### Certificate-Based Authentication
Some endpoints support certificate-based authentication using public/private key pairs. Clients must include:
- `X-API-Key`: API key ID
- `X-Timestamp`: Current Unix timestamp
- `X-Signature`: Base64-encoded signature of "API_KEY_ID+TIMESTAMP" using the private key

Example:
```
X-API-Key: 123e4567-e89b-12d3-a456-426614174000
X-Timestamp: 1640995200
X-Signature: MEUCIQDO...base64_signature
```

## Endpoints

### Hello World
- **GET** `/hello`
- **Description**: Simple health check endpoint
- **Response**: `"Hello, World!"`

### Authentication Endpoints

#### Login
- **POST** `/auth/login`
- **Headers**:
  - `x-app-token`: Application token for validation
- **Body**:
  ```json
  {
    "email": "user@example.com",
    "password": "password"
  }
  ```
- **Response**:
  ```json
  {
    "access_token": "jwt_token",
    "refresh_token": "refresh_token",
    "expires_in": 3600,
    "user": {
      "id": "user_id",
      "email": "user@example.com",
      "first_name": "John",
      "last_name": "Doe",
      "roles": ["employee"],
      "created_at": "2023-01-01T00:00:00Z",
      "enabled": true
    }
  }
  ```

#### Register
- **POST** `/auth/register`
- **Body**:
  ```json
  [
    {
      "id": "user_id",
      "email": "user@example.com",
      "first_name": "John",
      "last_name": "Doe",
      "roles": ["employee"],
      "created_at": "2023-01-01T00:00:00Z",
      "enabled": true
    },
    "password"
  ]
  ```
- **Response**: `200 OK`

#### Password Recovery
- **POST** `/auth/recover`
- **Body**:
  ```json
  {
    "email": "user@example.com"
  }
  ```
- **Response**: `200 OK`

#### Get Current User
- **GET** `/auth/me`
- **Headers**: `Authorization: Bearer <token>`
- **Response**:
  ```json
  {
    "id": "user_id",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "roles": ["employee"],
    "created_at": "2023-01-01T00:00:00Z",
    "enabled": true
  }
  ```

### Key Management Endpoints

#### Create API Key
- **POST** `/api/keys`
- **Headers**: `Authorization: Bearer <token>`
- **Query Parameters**:
  - `type`: Key type (`client`, `server`, `database`)
  - `tenant`: Tenant identifier
  - `ttl`: Time to live in seconds (default: 3600)
- **Response**:
  ```json
  {
    "id": "key_id",
    "key_type": "Client",
    "tenant": "tenant_id",
    "ttl": 3600,
    "created_at": "2023-01-01T00:00:00Z",
    "permissions": ["read"],
    "vault_path": "secret/client"
  }
  ```

#### List API Keys
- **GET** `/api/keys`
- **Headers**: `Authorization: Bearer <token>`
- **Query Parameters**:
  - `tenant`: Tenant identifier
- **Response**:
  ```json
  [
    {
      "id": "key_id",
      "key_type": "Client",
      "tenant": "tenant_id",
      "ttl": 3600,
      "created_at": "2023-01-01T00:00:00Z",
      "permissions": ["read"],
      "vault_path": "secret/client"
    }
  ]
  ```

#### Get API Key
- **GET** `/api/keys/{id}`
- **Headers**: `Authorization: Bearer <token>`
- **Response**: Same as create key response

#### Revoke API Key
- **DELETE** `/api/keys/{id}`
- **Headers**: `Authorization: Bearer <token>`
- **Response**:
  ```json
  {
    "message": "Key revoked"
  }
  ```

#### Create API Key with Certificate
- **POST** `/api/keys/with-certificate`
- **Headers**: `Authorization: Bearer <token>`
- **Query Parameters**:
  - `type`: Key type (`client`, `server`, `database`)
  - `tenant`: Tenant identifier
  - `ttl`: Time to live in seconds (default: 3600)
  - `cert_type`: Certificate type (`rsa` or `ecdsa`, default: `rsa`)
- **Response**:
  ```json
  {
    "id": "key_id",
    "key_type": "Client",
    "tenant": "tenant_id",
    "ttl": 3600,
    "created_at": "2023-01-01T00:00:00Z",
    "permissions": ["read"],
    "vault_path": "secret/client",
    "certificate": {
      "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
      "private_key_path": "secret/certificates/key_id/private",
      "certificate_type": "RSA",
      "fingerprint": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
    }
  }
  ```

#### Get Public Key
- **GET** `/api/keys/{id}/public-key`
- **Headers**: `Authorization: Bearer <token>`
- **Response**:
  ```json
  {
    "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
    "certificate_type": "RSA",
    "fingerprint": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
  }
  ```

#### Revoke Certificate
- **DELETE** `/api/keys/{id}/certificate`
- **Headers**: `Authorization: Bearer <token>`
- **Response**:
  ```json
  {
    "message": "Certificate revoked"
  }
  ```

#### Certificate-Authenticated Endpoint (Example)
- **GET** `/api/secure/cert`
- **Headers**:
  - `X-API-Key`: API key ID
  - `X-Timestamp`: Current Unix timestamp
  - `X-Signature`: Base64-encoded signature
- **Response**:
  ```json
  {
    "message": "Authenticated with certificate",
    "api_key_id": "123e4567-e89b-12d3-a456-426614174000"
  }
  ```

## Error Responses

All endpoints may return the following error responses:

- **400 Bad Request**: Invalid request data
- **401 Unauthorized**: Missing or invalid authentication
- **403 Forbidden**: Insufficient permissions
- **404 Not Found**: Resource not found
- **500 Internal Server Error**: Server error

Error response format:
```json
{
  "error": "Error message"
}
```

## Rate Limiting

API endpoints implement rate limiting to prevent abuse. Rate limits vary by endpoint and user role.

## Data Types

### User
```json
{
  "id": "string",
  "email": "string",
  "first_name": "string?",
  "last_name": "string?",
  "roles": ["string"],
  "created_at": "datetime",
  "enabled": "boolean"
}
```

### ApiKey
```json
{
  "id": "string",
  "key_type": "Client|Server|Database",
  "tenant": "string",
  "ttl": "number",
  "created_at": "datetime",
  "permissions": ["string"],
  "vault_path": "string",
  "certificate": "CertificateInfo?" // Optional certificate information
}
```

### CertificateInfo
```json
{
  "public_key": "string", // PEM-encoded public key
  "private_key_path": "string", // Path to private key in vault
  "certificate_type": "RSA|ECDSA",
  "fingerprint": "string" // SHA256 fingerprint for verification
}
```