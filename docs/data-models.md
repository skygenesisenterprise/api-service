# Data Models

## Overview

The API uses strongly-typed data structures defined in Rust using Serde for serialization/deserialization. All models are defined in the `api/src/models/` directory.

## User Model

Represents a user in the system, integrated with Keycloak.

```rust
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    pub id: String,
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub roles: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub enabled: bool,
}
```

### Fields
- `id`: Unique user identifier (UUID from Keycloak)
- `email`: User's email address (used as username)
- `first_name`: Optional first name
- `last_name`: Optional last name
- `roles`: List of user roles (e.g., ["employee", "admin"])
- `created_at`: Account creation timestamp
- `enabled`: Whether the account is active

## API Key Model

Represents an API key with associated metadata and permissions.

```rust
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum KeyType {
    Client,
    Server,
    Database,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApiKey {
    pub id: String,
    pub key_type: KeyType,
    pub tenant: String,
    pub ttl: u64,
    pub created_at: DateTime<Utc>,
    pub permissions: Vec<String>,
    pub vault_path: String,
}
```

### Fields
- `id`: Unique key identifier (UUID)
- `key_type`: Type of key (Client, Server, or Database)
- `tenant`: Tenant identifier for multi-tenancy
- `ttl`: Time-to-live in seconds
- `created_at`: Key creation timestamp
- `permissions`: List of permissions (currently ["read"])
- `vault_path`: Path in Vault where the key is stored

## Authentication Models

### Login Request
```rust
#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}
```

### Login Response
```rust
#[derive(Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
    pub user: User,
}
```

## JWT Claims

Used internally for JWT token validation.

```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,      // Subject (user ID)
    pub email: String,    // User email
    pub roles: Vec<String>, // User roles
    pub exp: usize,       // Expiration timestamp
    pub iat: usize,       // Issued at timestamp
}
```

## Keycloak Integration Models

### Token Response (from Keycloak)
```rust
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: String,
    expires_in: u64,
}
```

### Register Request (to Keycloak)
```rust
#[derive(Serialize)]
struct RegisterRequest {
    username: String,
    email: String,
    first_name: Option<String>,
    last_name: Option<String>,
    enabled: bool,
    credentials: Vec<Credential>,
}
```

## Validation Rules

### User Validation
- `email`: Must be valid email format
- `roles`: Non-empty array
- `enabled`: Boolean flag

### API Key Validation
- `key_type`: Must be one of the enum values
- `tenant`: Non-empty string
- `ttl`: Positive integer (seconds)
- `permissions`: Array of valid permission strings

## Serialization

All models use JSON serialization with the following conventions:
- Snake_case field names in JSON
- Optional fields use `Option<T>`
- Timestamps use ISO 8601 format
- Enums serialize as strings

## Database Mapping

Models are designed to map to PostgreSQL tables with the following schema:

### users table
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    roles TEXT[], -- Array of roles
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    enabled BOOLEAN DEFAULT TRUE
);
```

### api_keys table
```sql
CREATE TABLE api_keys (
    id UUID PRIMARY KEY,
    key_type VARCHAR(50) NOT NULL,
    tenant VARCHAR(255) NOT NULL,
    ttl BIGINT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    permissions TEXT[], -- Array of permissions
    vault_path VARCHAR(255) NOT NULL,
    revoked BOOLEAN DEFAULT FALSE
);
```

## Future Extensions

The model structure is designed to be extensible:
- Additional user fields can be added to the User struct
- New key types can be added to the KeyType enum
- Permissions can be expanded beyond "read"
- Custom claims can be added to JWT tokens