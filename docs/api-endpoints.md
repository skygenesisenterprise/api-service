# API Endpoints Documentation

## Base URL
All API endpoints are served under `http://localhost:8080` in development.

## Authentication

### Primary Authentication: JWT Tokens
Most endpoints require authentication via JWT tokens in the `Authorization` header:
```
Authorization: Bearer <jwt_token>
```

### Enhanced Security: Certificate-Coupled API Keys
For enhanced security, API keys can be coupled with digital certificates. This creates a two-factor authentication system where requests must provide both:

1. **JWT Token** (proves user identity)
2. **Certificate Signature** (proves API key ownership)

#### Certificate-Coupled Authentication Headers
When using certificate-coupled API keys, clients must include additional headers:
- `X-API-Key`: API key ID (must have an associated certificate)
- `X-Timestamp`: Current Unix timestamp
- `X-Signature`: Base64-encoded signature of "API_KEY_ID+TIMESTAMP" using the private key

Example request with both JWT and certificate:
```
Authorization: Bearer <jwt_token>
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

### SSO Endpoints

#### SSO Login Page
- **GET** `/sso/login`
- **Query Parameters**:
  - `redirect_uri`: Application callback URL
  - `state`: CSRF protection parameter
  - `client_id`: Application identifier
- **Description**: Serves the SSO login page under the API domain
- **Response**: HTML login page

#### SSO Authentication
- **POST** `/sso/auth`
- **Content-Type**: `application/x-www-form-urlencoded`
- **Form Fields**:
  - `username`: User email
  - `password`: User password
  - `redirect_uri`: Application callback URL
  - `state`: State parameter
  - `client_id`: Application identifier
- **Description**: Handles authentication and redirects to application
- **Response**: Redirect to application's redirect_uri with tokens

#### SSO Resources
- **GET** `/sso/resources/css/login.css`
- **Description**: Serves CSS resources for the login page
- **Response**: CSS stylesheet

#### SSO Callback
- **GET** `/sso/callback`
- **Query Parameters**:
  - `access_token`: JWT access token
  - `refresh_token`: JWT refresh token
  - `expires_in`: Token expiration time
  - `state`: State parameter
  - `client_id`: Application identifier
- **Description**: Application endpoint to receive authentication tokens
- **Response**:
  ```json
  {
    "access_token": "jwt_token",
    "refresh_token": "refresh_token",
    "expires_in": 3600,
    "state": "state_value",
    "client_id": "app_id",
    "message": "SSO authentication successful"
  }
  ```

### Key Management Endpoints

#### Create Standard API Key
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

#### Create Certificate-Coupled API Key
- **POST** `/api/keys/with-certificate`
- **Headers**: `Authorization: Bearer <token>`
- **Query Parameters**:
  - `type`: Key type (`client`, `server`, `database`)
  - `tenant`: Tenant identifier
  - `ttl`: Time to live in seconds (default: 3600)
  - `cert_type`: Certificate type (`rsa` or `ecdsa`, default: `rsa`)
- **Description**: Creates an API key with an associated digital certificate for enhanced security
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
  - `Authorization`: Bearer JWT token
  - `X-API-Key`: API key ID with certificate
  - `X-Timestamp`: Current Unix timestamp
  - `X-Signature`: Base64-encoded signature
- **Description**: Example endpoint requiring both JWT and certificate authentication
- **Response**:
  ```json
  {
    "message": "Authenticated with JWT + certificate",
    "user_id": "user_id",
    "api_key_id": "123e4567-e89b-12d3-a456-426614174000"
  }
  ```

## Certificate-Coupled API Key Usage

### Overview
Certificate-coupled API keys provide enhanced security by requiring cryptographic proof of key ownership for each request. This prevents unauthorized use even if the JWT token is compromised.

### Workflow

1. **Create Certificate-Coupled Key**
   ```bash
   POST /api/keys/with-certificate?type=client&tenant=myorg&cert_type=rsa
   Authorization: Bearer <jwt_token>
   ```

2. **Store Certificate Information**
   - The server stores the public key
   - The client must securely store the private key
   - Use the key ID for subsequent requests

3. **Make Authenticated Requests**
   - Include JWT token (user authentication)
   - Include certificate signature (key ownership proof)
   - Server verifies both authentications

### Security Benefits

- **Two-Factor Authentication**: JWT (what you know) + Certificate (what you have)
- **Non-Repudiation**: Cryptographic proof of request origin
- **Key Theft Protection**: Stolen JWT alone cannot be used without the private key
- **Replay Attack Prevention**: Timestamp validation prevents replay attacks

### Certificate Types

- **RSA**: Traditional asymmetric cryptography, widely supported
- **ECDSA**: Elliptic curve cryptography, more efficient for constrained environments

### Best Practices

1. **Private Key Security**: Never expose private keys, store them securely
2. **Key Rotation**: Regularly rotate certificate-coupled keys
3. **Timestamp Accuracy**: Ensure client and server time synchronization
4. **Signature Verification**: Always validate signatures server-side
5. **Certificate Revocation**: Revoke certificates immediately upon compromise

### Certificate Authentication Flow

1. **Create API key with certificate**:
   ```bash
   POST /api/keys/with-certificate?type=client&tenant=myorg&ttl=3600&cert_type=rsa
   Authorization: Bearer <jwt_token>
   ```

2. **Retrieve certificate information** (including public key):
   ```bash
   GET /api/keys/{api_key_id}/public-key
   Authorization: Bearer <jwt_token>
   ```

3. **Client signs requests**: For each API request, the client:
   - Creates a timestamp: `timestamp = current_unix_timestamp()`
   - Creates message: `message = api_key_id + timestamp`
   - Signs the message with private key: `signature = sign(message, private_key)`
   - Encodes signature in base64: `signature_b64 = base64_encode(signature)`
   - Sends request with headers:
     ```
     X-API-Key: {api_key_id}
     X-Timestamp: {timestamp}
     X-Signature: {signature_b64}
     ```

4. **Server verifies**: Server retrieves the public key from stored certificate and verifies the signature

### Complete Example

**1. Create certificate-enabled API key:**
```bash
curl -X POST "http://localhost:8080/api/keys/with-certificate?type=client&tenant=myorg&ttl=3600&cert_type=rsa" \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
```

**Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "key_type": "Client",
  "tenant": "myorg",
  "ttl": 3600,
  "created_at": "2023-01-01T00:00:00Z",
  "permissions": ["read"],
  "vault_path": "secret/client",
  "certificate": {
    "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----",
    "private_key_path": "secret/certificates/550e8400-e29b-41d4-a716-446655440000/private",
    "certificate_type": "RSA",
    "fingerprint": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
  }
}
```

**2. Make authenticated request with certificate:**
```bash
# Calculate timestamp and signature (this would be done in client code)
timestamp=$(date +%s)
message="${api_key_id}${timestamp}"
signature=$(echo -n "$message" | openssl dgst -sha256 -sign private_key.pem | base64)

curl -X GET "http://localhost:8080/api/secure/cert" \
  -H "X-API-Key: 550e8400-e29b-41d4-a716-446655440000" \
  -H "X-Timestamp: $timestamp" \
  -H "X-Signature: $signature"
```

### Example Client Implementation (JavaScript/Node.js)

```javascript
const crypto = require('crypto');
const axios = require('axios');

// Assuming you have the private key in PEM format
const privateKey = `-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----`;

const apiKeyId = 'your-api-key-id';

function signRequest(apiKeyId, timestamp) {
  const message = apiKeyId + timestamp;
  const sign = crypto.createSign('SHA256');
  sign.update(message);
  const signature = sign.sign(privateKey);
  return signature.toString('base64');
}

async function makeAuthenticatedRequest() {
  const timestamp = Math.floor(Date.now() / 1000);
  const signature = signRequest(apiKeyId, timestamp.toString());

  const response = await axios.get('/api/secure/cert', {
    headers: {
      'X-API-Key': apiKeyId,
      'X-Timestamp': timestamp,
      'X-Signature': signature
    }
  });

  return response.data;
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

### WebSocket Endpoints

#### Public WebSocket Connection
- **GET** `/ws`
- **Description**: Establish a public WebSocket connection for real-time communication
- **Authentication**: None required
- **Protocol**: WebSocket with JSON messages

#### Authenticated WebSocket Connection
- **GET** `/ws/auth`
- **Headers**: `Authorization: Bearer <jwt_token>`
- **Description**: Establish an authenticated WebSocket connection
- **Authentication**: JWT token required

#### WebSocket Status
- **GET** `/ws/status`
- **Description**: Get WebSocket server status and statistics
- **Response**:
  ```json
  {
    "status": "active",
    "clients_connected": 5,
    "channels_active": 3,
    "timestamp": 1640995200
  }
  ```

#### Broadcast Message
- **POST** `/ws/broadcast/{channel}`
- **Headers**: `Authorization: Bearer <jwt_token>`
- **Body**: JSON message to broadcast
- **Description**: Send a message to all clients subscribed to a channel

#### Send Notification
- **POST** `/ws/notify/{user_id}`
- **Headers**: `Authorization: Bearer <jwt_token>`
- **Body**:
  ```json
  {
    "title": "Notification Title",
    "message": "Notification message",
    "level": "info|success|warning|error"
  }
  ```

### Security & Cryptography Endpoints

#### Security Status
- **GET** `/api/v1/security/status`
- **Description**: Get comprehensive security system status
- **Response**:
  ```json
  {
    "status": "active",
    "encryption_keys_active": 5,
    "signing_keys_active": 3,
    "algorithms": {
      "symmetric_encryption": ["AES-256-GCM", "ChaCha20-Poly1305"],
      "key_exchange": ["X25519"],
      "signatures": ["Ed25519", "ECDSA-P384"],
      "hash_functions": ["SHA-512", "SHA-3-512"],
      "key_derivation": ["HKDF-SHA-512"],
      "password_hashing": ["Argon2id"]
    },
    "security_level": "high",
    "post_quantum_ready": false,
    "timestamp": 1640995200
  }
  ```

#### Generate Encryption Key
- **POST** `/api/v1/security/keys/encryption/generate`
- **Headers**: `Authorization: Bearer <jwt_token>`
- **Body**:
  ```json
  {
    "key_id": "my-encryption-key"
  }
  ```
- **Description**: Generate and store a new encryption key

#### Generate Signing Key
- **POST** `/api/v1/security/keys/signing/generate`
- **Headers**: `Authorization: Bearer <jwt_token>`
- **Body**:
  ```json
  {
    "key_id": "my-signing-key",
    "key_type": "ed25519"  // or "ecdsa-p384"
  }
  ```
- **Description**: Generate a new signing keypair (Ed25519 or ECDSA P-384)

#### Encrypt Data
- **POST** `/api/v1/security/encrypt`
- **Headers**: `Authorization: Bearer <jwt_token>`
- **Body**:
  ```json
  {
    "key_id": "my-encryption-key",
    "data": "SGVsbG8gV29ybGQ="  // base64 encoded plaintext
  }
  ```
- **Response**:
  ```json
  {
    "status": "success",
    "ciphertext": "encrypted_data_base64"
  }
  ```

#### Decrypt Data
- **POST** `/api/v1/security/decrypt`
- **Headers**: `Authorization: Bearer <jwt_token>`
- **Body**:
  ```json
  {
    "key_id": "my-encryption-key",
    "data": "encrypted_data_base64"
  }
  ```
- **Response**:
  ```json
  {
    "status": "success",
    "plaintext": "decrypted_data_base64"
  }
  ```

#### Sign Data
- **POST** `/api/v1/security/sign`
- **Headers**: `Authorization: Bearer <jwt_token>`
- **Body**:
  ```json
  {
    "key_id": "my-signing-key",
    "data": "data_to_sign_base64"
  }
  ```
- **Response**:
  ```json
  {
    "status": "success",
    "signature": "signature_base64"
  }
  ```

#### Verify Signature
- **POST** `/api/v1/security/verify`
- **Headers**: `Authorization: Bearer <jwt_token>`
- **Body**:
  ```json
  {
    "key_id": "my-signing-key",
    "data": "original_data_base64",
    "signature": "signature_base64"
  }
  ```
- **Response**:
  ```json
  {
    "status": "success",
    "valid": true
  }
  ```

#### Hash Password
- **POST** `/api/v1/security/password/hash`
- **Headers**: `Authorization: Bearer <jwt_token>`
- **Body**:
  ```json
  {
    "password": "my_secure_password"
  }
  ```
- **Response**:
  ```json
  {
    "status": "success",
    "salt": "salt_base64",
    "hash": "argon2id_hash"
  }
  ```

#### Verify Password
- **POST** `/api/v1/security/password/verify`
- **Headers**: `Authorization: Bearer <jwt_token>`
- **Body**:
  ```json
  {
    "password": "my_secure_password",
    "salt": "salt_base64",
    "hash": "argon2id_hash"
  }
  ```
- **Response**:
  ```json
  {
    "status": "success",
    "valid": true
  }
  ```

#### Perform Key Exchange
- **POST** `/api/v1/security/key-exchange`
- **Headers**: `Authorization: Bearer <jwt_token>`
- **Description**: Perform X25519 key exchange simulation
- **Response**:
  ```json
  {
    "status": "success",
    "shared_key": "derived_shared_key_base64",
    "note": "In production, keys would be exchanged securely between parties"
  }
  ```

#### Hash Data
- **POST** `/api/v1/security/hash`
- **Headers**: `Authorization: Bearer <jwt_token>`
- **Body**:
  ```json
  {
    "data": "data_to_hash_base64"
  }
  ```
- **Response**:
  ```json
  {
    "status": "success",
    "algorithm": "SHA-512",
    "hash": "hash_base64"
  }
  ```

#### Generate Random Data
- **POST** `/api/v1/security/random`
- **Headers**: `Authorization: Bearer <jwt_token>`
- **Body**:
  ```json
  {
    "length": 32
  }
  ```
- **Response**:
  ```json
  {
    "status": "success",
    "data": "random_bytes_base64"
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