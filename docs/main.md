# Application Entry Point

## Overview

The `main.rs` file serves as the application entry point, responsible for initializing all components, setting up external integrations, and starting the HTTP server.

## Application Flow

### 1. Environment Setup
```rust
dotenv().ok();
```
Loads environment variables from `.env` file if present.

### 2. Vault Client Initialization
```rust
let vault_addr = std::env::var("VAULT_ADDR").unwrap_or("https://vault.skygenesisenterprise.com".to_string());
let role_id = std::env::var("VAULT_ROLE_ID").expect("VAULT_ROLE_ID must be set");
let secret_id = std::env::var("VAULT_SECRET_ID").expect("VAULT_SECRET_ID must be set");
let vault_client = Arc::new(crate::core::vault::VaultClient::new(vault_addr, role_id, secret_id).await.unwrap());
```

**Purpose:** Establishes secure connection to HashiCorp Vault.

**Requirements:**
- `VAULT_ADDR`: Vault server URL
- `VAULT_ROLE_ID`: AppRole role identifier
- `VAULT_SECRET_ID`: AppRole secret identifier

**Error Handling:** Panics if authentication fails.

### 3. Keycloak Client Initialization
```rust
let keycloak_client = Arc::new(crate::core::keycloak::KeycloakClient::new(vault_client.clone()).await.unwrap());
```

**Purpose:** Sets up Keycloak integration for user authentication.

**Dependencies:** Requires Vault client for retrieving client secrets.

### 4. Service Initialization
```rust
let auth_service = Arc::new(crate::services::auth_service::AuthService::new(keycloak_client, vault_client.clone()));
let key_service = Arc::new(crate::services::key_service::KeyService::new(vault_client));
```

**Purpose:** Creates service layer instances with injected dependencies.

**Thread Safety:** Uses `Arc<T>` for shared ownership across async tasks.

### 5. Vault Manager Setup
```rust
let vault_token = std::env::var("VAULT_TOKEN").unwrap_or_default();
let vault_manager = Arc::new(crate::services::vault_manager::VaultManager::new("dummy".to_string(), vault_token));
```

**Note:** Currently a placeholder implementation.

### 6. Route Configuration
```rust
let routes = routes::routes(vault_manager, key_service, auth_service);
```

**Purpose:** Combines all API routes into the final router.

### 7. Server Startup
```rust
println!("Server started at http://localhost:{}", port);
warp::serve(routes)
    .run(([127, 0, 0, 1], port))
    .await;
```

**Configuration:**
- Host: 127.0.0.1 (localhost)
- Port: 8080 (configurable via PORT environment variable)
- Server: Warp HTTP server

## Module Imports

The main function relies on several modules:

```rust
mod models;
mod services;
mod middlewares;
mod routes;
mod controllers;
mod core;
mod queries;
mod utils;
mod tests;
```

## Error Handling Strategy

### Environment Variables
- Uses `expect()` for required variables (panics on missing)
- Uses `unwrap_or()` for optional variables with defaults
- Uses `unwrap()` for operations that should not fail in normal conditions

### Service Initialization
- Uses `unwrap()` assuming proper configuration
- In production, should use proper error handling and graceful shutdown

## Configuration Management

### Environment Variables Required
- `VAULT_ADDR`: Vault server endpoint
- `VAULT_ROLE_ID`: Vault authentication role
- `VAULT_SECRET_ID`: Vault authentication secret
- `VAULT_TOKEN`: Alternative Vault token (optional)

### Keycloak Configuration
Retrieved from Vault:
- `keycloak/client_secret`: OAuth2 client secret

Environment variables:
- `KEYCLOAK_URL`: Keycloak server URL
- `KEYCLOAK_REALM`: Keycloak realm
- `KEYCLOAK_CLIENT_ID`: OAuth2 client ID

### JWT Configuration
- `JWT_SECRET`: Secret key for token signing

## Dependency Injection

The application uses constructor injection to provide dependencies:

1. **Vault Client** → Keycloak Client, Key Service, Auth Service
2. **Keycloak Client** → Auth Service
3. **Services** → Routes → Controllers

This pattern enables:
- Testability through mocking
- Loose coupling between components
- Configuration flexibility

## Async Runtime

Uses Tokio async runtime (`#[tokio::main]`) for:
- Non-blocking I/O operations
- Concurrent request handling
- External service integrations

## Logging

Basic console logging for server startup. In production, should be enhanced with:
- Structured logging
- Log levels
- External log aggregation

## Security Considerations

### Secret Management
- All secrets retrieved from Vault at startup
- No secrets in configuration files
- Secure authentication flows

### Network Security
- Localhost binding for development
- Should use proper TLS in production
- Firewall configuration required

## Startup Sequence Diagram

```
Environment Setup
        ↓
Vault Authentication
        ↓
Keycloak Client Init
        ↓
Service Layer Init
        ↓
Route Configuration
        ↓
Server Startup
```

## Error Scenarios

### Vault Connection Failure
- Application fails to start
- Requires Vault service availability
- Check network connectivity and credentials

### Keycloak Connection Failure
- Application fails to start
- Requires Keycloak service availability
- Check Vault secrets and Keycloak configuration

### Port Binding Failure
- Port 8080 may be in use
- Check for other running services
- Configure alternative port if needed

## Future Enhancements

- Graceful shutdown handling
- Health check endpoints
- Configuration validation
- Service discovery integration
- Docker containerization
- Kubernetes deployment support
- Monitoring and metrics
- Configuration hot-reloading