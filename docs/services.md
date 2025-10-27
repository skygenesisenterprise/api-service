# Services Layer

## Overview

The services layer contains the business logic of the API, abstracting complex operations and integrating with external systems like Vault and Keycloak. Services are defined in the `api/src/services/` directory.

## KeyService

Handles API key management operations, including creation, retrieval, and revocation.

### Structure
```rust
pub struct KeyService {
    vault: Arc<VaultClient>,
}
```

### Methods

#### `create_key(key_type, tenant, ttl)`
Creates a new API key with the specified parameters.

**Parameters:**
- `key_type`: `KeyType` enum (Client, Server, Database)
- `tenant`: String identifier for tenant isolation
- `ttl`: Time-to-live in seconds

**Process:**
1. Generate unique key ID
2. Rotate key in Vault
3. Create ApiKey struct with metadata
4. Log key creation to database
5. Return the created key

**Returns:** `Result<ApiKey, Box<dyn std::error::Error>>`

#### `revoke_key(id)`
Revokes an API key by marking it as inactive.

**Parameters:**
- `id`: String key identifier

**Process:**
1. Update database to mark key as revoked
2. Potentially revoke in Vault (if supported)

**Returns:** `Result<(), Box<dyn std::error::Error>>`

#### `get_key(id)`
Retrieves a specific API key by ID.

**Parameters:**
- `id`: String key identifier

**Returns:** `Result<ApiKey, Box<dyn std::error::Error>>`

#### `list_keys(tenant)`
Lists all API keys for a specific tenant.

**Parameters:**
- `tenant`: String tenant identifier

**Returns:** `Result<Vec<ApiKey>, Box<dyn std::error::Error>>`

## AuthService

Manages user authentication and integration with Keycloak.

### Structure
```rust
pub struct AuthService {
    keycloak: Arc<KeycloakClient>,
    vault: Arc<VaultClient>,
}
```

### Methods

#### `login(req, app_token)`
Authenticates a user via Keycloak and returns JWT tokens.

**Parameters:**
- `req`: `LoginRequest` with email and password
- `app_token`: Application token for validation

**Process:**
1. Validate app_token against Vault
2. Authenticate user with Keycloak
3. Retrieve user info from Keycloak
4. Generate internal JWT token
5. Return login response with tokens and user data

**Returns:** `Result<LoginResponse, Box<dyn std::error::Error>>`

#### `register(user, password)`
Registers a new user in Keycloak.

**Parameters:**
- `user`: `User` struct with user details
- `password`: Plain text password

**Process:**
1. Create user in Keycloak with provided details
2. Set up credentials

**Returns:** `Result<(), Box<dyn std::error::Error>>`

#### `recover_password(email)`
Initiates password recovery process.

**Parameters:**
- `email`: User's email address

**Returns:** `Result<(), Box<dyn std::error::Error>>`

#### `get_me(token)`
Retrieves current user information from JWT token.

**Parameters:**
- `token`: JWT access token

**Process:**
1. Validate JWT token
2. Extract user claims
3. Return user information

**Returns:** `Result<User, Box<dyn std::error::Error>>`

## VaultManager

Placeholder service for Vault operations (currently minimal implementation).

### Structure
```rust
pub struct VaultManager {
    // Fields for Vault management
}
```

## Service Dependencies

### Shared Dependencies
- All services use `Arc<T>` for thread-safe sharing
- Services depend on core clients (VaultClient, KeycloakClient)
- Error handling uses `Box<dyn std::error::Error>`

### External Integrations
- **Vault**: Used for secret storage and key rotation
- **Keycloak**: Used for user authentication and management
- **Database**: Planned for persistent storage (currently placeholder)

## Error Handling

Services use Rust's `Result<T, E>` pattern with boxed errors for flexibility. Common error types include:
- Authentication failures
- Vault communication errors
- Keycloak integration errors
- Database operation errors

## Async Operations

All service methods are `async` and use Tokio for async runtime. This allows for non-blocking I/O operations with external services.

## Security Considerations

- Sensitive operations require proper authentication
- Secrets are never logged or exposed in responses
- All external communications use HTTPS
- Tokens have appropriate expiration times

## Testing

Services include unit tests in the `tests/` directory, focusing on:
- Happy path scenarios
- Error conditions
- Mock external dependencies
- Business logic validation

## Future Enhancements

- Database integration for persistent storage
- Caching layer for frequently accessed data
- Audit logging for all operations
- Rate limiting at service level
- Metrics and monitoring integration