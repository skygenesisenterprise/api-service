# Middlewares

## Overview

Middlewares provide cross-cutting concerns like authentication, logging, and request validation. They are implemented as Warp filters and defined in the `api/src/middlewares/` directory.

## Authentication Middleware (`auth_middleware.rs`)

### JWT Authentication Filter

```rust
pub fn jwt_auth() -> impl Filter<Extract = (Claims,), Error = Rejection> + Clone
```

**Purpose:** Validates JWT tokens in the Authorization header.

**Process:**
1. Extracts `Authorization` header
2. Checks for "Bearer " prefix
3. Decodes and validates JWT token using `jsonwebtoken` crate
4. Returns claims if valid, rejects if invalid

**Headers Expected:**
```
Authorization: Bearer <jwt_token>
```

**Claims Structure:**
```rust
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,      // Subject (user ID)
    exp: usize,       // Expiration timestamp
    scopes: Vec<String>, // Permissions/scopes
}
```

**Error Handling:**
- `AuthError::InvalidToken`: Returned for malformed or invalid tokens
- Warp rejection with custom error type

### Auth Guard (`auth_guard.rs`)

**Purpose:** Alternative authentication mechanism (currently placeholder).

**Note:** Implementation details may vary; currently forwards to JWT auth.

### Certificate Authentication Middleware (`cert_auth_middleware.rs`)

```rust
pub fn certificate_auth(key_service: Arc<KeyService>) -> impl Filter<Extract = (CertAuthClaims,), Error = Rejection> + Clone
```

**Purpose:** Validates requests signed with private keys corresponding to API key certificates.

**Process:**
1. Extracts `X-API-Key`, `X-Timestamp`, and `X-Signature` headers
2. Validates timestamp is within acceptable window (5 minutes)
3. Retrieves API key and associated certificate
4. Verifies signature using the public key (RSA or ECDSA)
5. Returns certificate claims if valid

**Headers Expected:**
```
X-API-Key: <api_key_id>
X-Timestamp: <unix_timestamp>
X-Signature: <base64_encoded_signature>
```

**Certificate Claims Structure:**
```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct CertAuthClaims {
    pub api_key_id: String,
    pub timestamp: u64,
    pub signature: String,
}
```

**Supported Algorithms:**
- RSA with PKCS#1 v1.5 padding (for RSA certificates)
- ECDSA with P-256 curve (for ECDSA certificates)

**Error Handling:**
- `CertAuthError::InvalidSignature`: Invalid or malformed signature
- `CertAuthError::KeyNotFound`: API key doesn't exist
- `CertAuthError::CertificateNotFound`: API key has no certificate
- `CertAuthError::ExpiredTimestamp`: Timestamp outside acceptable window

## Logging Middleware (`logging.rs`)

**Purpose:** Logs incoming requests and responses.

**Features:**
- Request logging with method, path, and headers
- Response logging with status codes
- Timing information
- Error logging

## Auth Module (`auth.rs`)

Contains shared authentication utilities and error types.

### AuthError Enum
```rust
#[derive(Debug)]
pub enum AuthError {
    InvalidToken,
    VaultError,
    InvalidKeyType,
}
```

**Implements:** `warp::reject::Reject` for Warp integration.

## Middleware Integration

### Route-Level Application
Middlewares are applied at the route level using Warp's filter composition:

```rust
let protected_route = warp::path!("api" / "protected")
    .and(jwt_auth())
    .and_then(handler);
```

### Global Middleware
Some middlewares (like logging) can be applied globally to all routes:

```rust
let routes = routes.with(logging_middleware);
```

## Security Features

### Token Validation
- HS256 algorithm for JWT signing
- Expiration time validation
- Issuer and audience validation (configurable)

### Request Validation
- Header presence and format validation
- Content-type validation for JSON endpoints
- Input sanitization

## Error Responses

Authentication failures return appropriate HTTP status codes:
- `401 Unauthorized`: Missing or invalid token
- `403 Forbidden`: Insufficient permissions
- `400 Bad Request`: Malformed requests

## Configuration

Middleware behavior can be configured via environment variables:
- `JWT_SECRET`: Secret key for JWT validation
- `TOKEN_EXPIRATION`: Token lifetime in seconds

## Performance Considerations

- JWT validation is computationally lightweight
- Token caching can be implemented for better performance
- Logging is configurable to avoid performance impact in production

## Testing

Middlewares include unit tests for:
- Valid token acceptance
- Invalid token rejection
- Error handling
- Header parsing

## Future Enhancements

- OAuth2 integration
- API key authentication
- Rate limiting
- Request/response compression
- CORS handling
- Request tracing and correlation IDs