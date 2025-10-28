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
- API key creation and rotation with `sk_` prefix
- Multi-tenant key isolation
- Time-to-live (TTL) support
- Secure storage in Vault
- Cryptographic key operations (encryption, signing, key exchange)

### Cryptographic Operations
- **Symmetric Encryption**: AES-256-GCM and ChaCha20-Poly1305
- **Digital Signatures**: Ed25519 (API tokens) and ECDSA P-384 (high security)
- **Key Exchange**: X25519 (Curve25519) for secure key establishment
- **Password Hashing**: Argon2id with optimized parameters
- **Hash Functions**: SHA-512 and SHA-3-512
- **Key Derivation**: HKDF-SHA-512 with proper salt handling

### Security
- **Modern Cryptography**: AES-256-GCM, ChaCha20-Poly1305, Ed25519, X25519, Argon2id
- **Post-Quantum Ready**: Architecture prepared for Kyber/Dilithium integration
- **Zero-Knowledge Security**: Sensitive data never exposed in logs or responses
- **Authenticated Encryption**: AEAD (Authenticated Encryption with Associated Data) only
- **Secure Key Management**: Hardware-backed key storage with automatic rotation
- **All sensitive data stored in Vault**
- **Encrypted communication**
- **Input validation and sanitization**
- **Comprehensive audit logging**

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
- `POST /api/keys` - Create new API key (with `sk_` prefix)
- `GET /api/keys` - List API keys
- `GET /api/keys/{id}` - Get specific API key
- `DELETE /api/keys/{id}` - Revoke API key

### Security & Cryptography Endpoints (`/api/v1/security/*`)
- `GET /security/status` - Security system status and active algorithms
- `POST /security/keys/encryption/generate` - Generate encryption keys
- `POST /security/keys/signing/generate` - Generate signing keys (Ed25519/ECDSA)
- `POST /security/encrypt` - Encrypt data with AES-256-GCM or ChaCha20-Poly1305
- `POST /security/decrypt` - Decrypt data
- `POST /security/sign` - Sign data with Ed25519 or ECDSA
- `POST /security/verify` - Verify digital signatures
- `POST /security/password/hash` - Hash passwords with Argon2id
- `POST /security/password/verify` - Verify password hashes
- `POST /security/key-exchange` - Perform X25519 key exchange
- `POST /security/hash` - Hash data with SHA-512
- `POST /security/random` - Generate cryptographically secure random data

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