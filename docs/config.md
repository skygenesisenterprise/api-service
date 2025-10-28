# Configuration Module

## Overview

The configuration module (`api/src/config/`) is currently a placeholder for centralized configuration management. As the application grows, this module will handle all configuration-related concerns including environment variables, application settings, and external service configurations.

## Current State

The module is currently empty with only a module declaration:

```rust
// Config Rust mod
```

## Planned Features

### Environment Configuration
Centralized loading and validation of environment variables:

```rust
#[derive(Debug)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub vault: VaultConfig,
    pub keycloak: KeycloakConfig,
    pub jwt: JwtConfig,
}

#[derive(Debug)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: usize,
}

#[derive(Debug)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
}

#[derive(Debug)]
pub struct VaultConfig {
    pub address: String,
    pub role_id: String,
    pub secret_id: String,
    pub token: Option<String>,
}

#[derive(Debug)]
pub struct KeycloakConfig {
    pub url: String,
    pub realm: String,
    pub client_id: String,
}

#[derive(Debug)]
pub struct JwtConfig {
    pub secret: String,
    pub expiration_hours: i64,
}
```

### Configuration Loading
```rust
impl AppConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        // Load and validate all configuration
    }
}
```

### Validation
- Required field validation
- URL format validation
- Secret presence validation
- Type conversion and parsing

## Benefits of Centralized Configuration

### Type Safety
- Compile-time validation of configuration structure
- Type-safe access to configuration values
- Prevention of configuration-related runtime errors

### Validation
- Early validation at startup
- Clear error messages for missing or invalid configuration
- Environment-specific validation rules

### Testability
- Easy mocking of configuration in tests
- Configuration fixtures for integration tests
- Environment isolation for testing

### Maintainability
- Single source of truth for configuration
- Clear documentation of required settings
- Easy to add new configuration options

## Configuration Sources

### Environment Variables
Primary source for configuration in containerized environments.

### Configuration Files
Optional YAML/TOML files for development environments.

### Vault Integration
Sensitive configuration retrieved from Vault at runtime.

## Environment Variables

### Server Configuration
- `SERVER_HOST`: Server bind address (default: 127.0.0.1)
- `PORT`: Server port (default: 8080)
- `SERVER_WORKERS`: Number of worker threads (default: number of CPUs)

### Database Configuration
- `DATABASE_URL`: PostgreSQL connection string
- `DATABASE_MAX_CONNECTIONS`: Maximum pool connections (default: 10)
- `DATABASE_MIN_CONNECTIONS`: Minimum pool connections (default: 1)

### Vault Configuration
- `VAULT_ADDR`: Vault server URL
- `VAULT_ROLE_ID`: AppRole role ID
- `VAULT_SECRET_ID`: AppRole secret ID
- `VAULT_TOKEN`: Direct Vault token (alternative to AppRole)

### Keycloak Configuration
- `KEYCLOAK_URL`: Keycloak server URL
- `KEYCLOAK_REALM`: Keycloak realm name
- `KEYCLOAK_CLIENT_ID`: OAuth2 client ID

### JWT Configuration
- `JWT_SECRET`: Secret key for JWT signing
- `JWT_EXPIRATION_HOURS`: Token expiration time (default: 1)

## Configuration Validation

### Startup Validation
- Validate all required environment variables are present
- Validate URL formats
- Validate secret key lengths
- Test external service connectivity (optional)

### Runtime Validation
- Re-validate configuration on reload
- Validate configuration changes
- Log configuration warnings

## Security Considerations

### Secret Handling
- Never log sensitive configuration values
- Use secure random generation for secrets
- Rotate secrets regularly

### Environment Separation
- Different configurations for dev/staging/prod
- Secret isolation between environments
- Configuration encryption at rest

## Future Implementation

### Configuration Hot Reload
- Watch for configuration changes
- Graceful configuration updates
- Signal handling for reload

### Configuration UI
- Admin interface for configuration management
- Configuration validation UI
- Configuration history and rollback

### Advanced Features
- Configuration templates
- Environment-specific overrides
- Configuration inheritance
- Remote configuration sources