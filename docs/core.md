# Core Integrations

## Overview

The core module handles integrations with external services: HashiCorp Vault for secret management and Keycloak for identity management. These integrations are critical for the API's security and authentication features.

## Vault Integration (`vault.rs`)

### VaultClient

Manages secure communication with HashiCorp Vault for secret storage and key management.

#### Structure
```rust
pub struct VaultClient {
    client: Client,                    // HTTP client
    base_url: String,                  // Vault server URL
    token: Arc<Mutex<String>>,         // Auth token
    token_expires: Arc<Mutex<Instant>>, // Token expiration
}
```

#### Initialization
```rust
pub async fn new(base_url: String, role_id: String, secret_id: String) -> Result<Self, Box<dyn std::error::Error>>
```

**Process:**
1. Creates HTTP client
2. Authenticates using AppRole method
3. Stores token and expiration time
4. Returns configured client

#### Authentication Methods

##### AppRole Authentication
Uses Vault's AppRole authentication method for machine-to-machine authentication.

**Parameters:**
- `role_id`: AppRole role identifier
- `secret_id`: AppRole secret identifier

**Environment Variables:**
- `VAULT_ADDR`: Vault server URL
- `VAULT_ROLE_ID`: AppRole role ID
- `VAULT_SECRET_ID`: AppRole secret ID

#### Core Methods

##### `get_secret(path: &str) -> Result<Value, Box<dyn std::error::Error>>`
Retrieves a secret from Vault.

**Parameters:**
- `path`: Secret path (e.g., "secret/myapp/database")

**Returns:** JSON value containing secret data

##### `set_secret(path: &str, data: Value) -> Result<(), Box<dyn std::error::Error>>`
Stores a secret in Vault.

**Parameters:**
- `path`: Secret path
- `data`: JSON data to store

##### `rotate_key(key_type: &str) -> Result<String, Box<dyn std::error::Error>>`
Rotates a key and stores the new value in Vault.

**Parameters:**
- `key_type`: Type of key ("client", "server", "database")

**Process:**
1. Generates new key
2. Stores in Vault at "secret/{key_type}"
3. Returns the new key value

#### Token Management
- Automatic token refresh before expiration
- Thread-safe token storage using Arc<Mutex<>>
- Configurable lease duration handling

## Keycloak Integration (`keycloak.rs`)

### KeycloakClient

Handles user authentication and management through Keycloak.

#### Structure
```rust
pub struct KeycloakClient {
    client: Client,           // HTTP client
    base_url: String,         // Keycloak server URL
    realm: String,            // Keycloak realm
    client_id: String,        // OAuth2 client ID
    client_secret: String,    // OAuth2 client secret
}
```

#### Initialization
```rust
pub async fn new(vault: Arc<VaultClient>) -> Result<Self, Box<dyn std::error::Error>>
```

**Process:**
1. Retrieves client secret from Vault
2. Configures HTTP client
3. Returns authenticated client

**Environment Variables:**
- `KEYCLOAK_URL`: Keycloak server URL
- `KEYCLOAK_REALM`: Realm name
- `KEYCLOAK_CLIENT_ID`: OAuth2 client ID

#### Authentication Methods

##### `login(email: &str, password: &str) -> Result<TokenResponse, Box<dyn std::error::Error>>`
Authenticates a user and returns OAuth2 tokens.

**Parameters:**
- `email`: User email
- `password`: User password

**Returns:** TokenResponse with access_token, refresh_token, expires_in

##### `register(user: &User, password: &str) -> Result<(), Box<dyn std::error::Error>>`
Creates a new user in Keycloak.

**Parameters:**
- `user`: User details
- `password`: User password

**Process:**
1. Obtains admin token
2. Creates user via Keycloak Admin API
3. Sets user credentials

##### `get_user_info(access_token: &str) -> Result<Value, Box<dyn std::error::Error>>`
Retrieves user information using access token.

**Parameters:**
- `access_token`: Valid OAuth2 access token

**Returns:** User info JSON from Keycloak

##### `recover_password(email: &str) -> Result<(), Box<dyn std::error::Error>>`
Initiates password recovery (placeholder implementation).

## Integration Patterns

### Service Layer Integration
Core clients are injected into services:

```rust
let vault_client = Arc::new(VaultClient::new(vault_addr, role_id, secret_id).await?);
let keycloak_client = Arc::new(KeycloakClient::new(vault_client.clone()).await?);

let auth_service = Arc::new(AuthService::new(keycloak_client, vault_client.clone()));
let key_service = Arc::new(KeyService::new(vault_client));
```

### Error Handling
- Network errors are propagated as boxed errors
- Authentication failures return specific error types
- Timeouts and connection issues are handled gracefully

### Async Operations
- All methods are async for non-blocking I/O
- Uses reqwest for HTTP client operations
- Integrates with Tokio async runtime

## Security Features

### Vault Security
- AppRole authentication (no long-lived tokens)
- Automatic token rotation
- Encrypted secret storage
- Path-based access control

### Keycloak Security
- OAuth2/OpenID Connect compliance
- Secure token handling
- Admin API protection
- User credential encryption

## Configuration

### Required Environment Variables
```bash
# Vault
VAULT_ADDR=https://vault.example.com
VAULT_ROLE_ID=role_id
VAULT_SECRET_ID=secret_id

# Keycloak
KEYCLOAK_URL=https://keycloak.example.com
KEYCLOAK_REALM=myrealm
KEYCLOAK_CLIENT_ID=api-client
```

### Vault Paths
- `keycloak/client_secret`: OAuth2 client secret
- `secret/client`: Client API keys
- `secret/server`: Server API keys
- `secret/database`: Database API keys

## Monitoring and Logging

- HTTP requests are logged with reqwest
- Authentication attempts are tracked
- Token expiration is monitored
- Errors are propagated with context

## Testing

Core modules include integration tests:
- Mock HTTP servers for Vault/Keycloak
- Authentication flow testing
- Error condition handling
- Token validation testing

## Future Enhancements

- Connection pooling for better performance
- Circuit breaker pattern for resilience
- Metrics collection for monitoring
- Support for multiple Vault/Keycloak instances
- Advanced authentication methods (LDAP, SAML)
- Token caching and refresh optimization