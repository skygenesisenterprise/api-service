# Sky Genesis Enterprise API Service - Overview

## Introduction

The Sky Genesis Enterprise API Service is a Rust-based web API built with the Warp framework, providing secure key management and authentication services. It integrates with HashiCorp Vault for secret management and Keycloak for identity and access management.

## Architecture

The API follows a modular architecture with the following key components:

### Core Components
- **Warp Framework**: HTTP server and routing
- **Vault Integration**: Secret storage and key rotation
- **Keycloak Integration**: User authentication and authorization
- **PostgreSQL**: Data persistence (planned)

### Module Structure
```
api/src/
├── main.rs              # Application entry point
├── config/              # Configuration management
├── controllers/         # Request handlers
├── core/                # External service integrations (Vault, Keycloak)
├── middlewares/         # Authentication and validation middleware
├── models/              # Data structures and types
├── queries/             # Database query abstractions
├── routes/              # API route definitions
├── services/            # Business logic layer
├── tests/               # Unit and integration tests
└── utils/               # Utility functions
```

## Key Features

### Authentication & Authorization
- JWT-based authentication
- Integration with Keycloak for user management
- Role-based access control
- App token validation via Vault

### Key Management
- API key creation and rotation
- Multi-tenant key isolation
- Time-to-live (TTL) support
- Secure storage in Vault

### Security
- All sensitive data stored in Vault
- Encrypted communication
- Input validation and sanitization
- Audit logging

## Technology Stack

- **Language**: Rust
- **Web Framework**: Warp
- **Authentication**: Keycloak
- **Secrets Management**: HashiCorp Vault
- **Database**: PostgreSQL (planned)
- **Serialization**: Serde (JSON)
- **Async Runtime**: Tokio

## Environment Variables

Required environment variables for operation:

- `VAULT_ADDR`: Vault server URL
- `VAULT_ROLE_ID`: Vault AppRole role ID
- `VAULT_SECRET_ID`: Vault AppRole secret ID
- `VAULT_TOKEN`: Vault token (alternative auth)
- `KEYCLOAK_URL`: Keycloak server URL
- `KEYCLOAK_REALM`: Keycloak realm
- `KEYCLOAK_CLIENT_ID`: Keycloak client ID
- `JWT_SECRET`: JWT signing secret

## API Endpoints

The API exposes endpoints under two main categories:

### Authentication Endpoints (`/auth/*`)
- `POST /auth/login` - User login
- `POST /auth/register` - User registration
- `POST /auth/recover` - Password recovery
- `GET /auth/me` - Get current user info

### Key Management Endpoints (`/api/keys/*`)
- `POST /api/keys` - Create new API key
- `GET /api/keys` - List API keys
- `GET /api/keys/{id}` - Get specific API key
- `DELETE /api/keys/{id}` - Revoke API key

## Development

### Building
```bash
cargo build
```

### Running
```bash
cargo run
```

### Testing
```bash
cargo test
```

## Deployment

The service is designed to run in containerized environments with proper secret management through Vault and external authentication via Keycloak.