# Sky Genesis Enterprise API Documentation

[![Rust](https://img.shields.io/badge/Rust-1.70+-000000?style=for-the-badge&logo=rust)](https://www.rust-lang.org/)
[![Warp](https://img.shields.io/badge/Warp-0.3-000000?style=for-the-badge)](https://crates.io/crates/warp)
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)

The Sky Genesis Enterprise API is a high-performance, secure Rust-based web service designed for enterprise-grade key management, authentication, and communication services. This documentation provides comprehensive guidance for developers, architects, and system administrators working with the platform.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Documentation Structure](#documentation-structure)
- [Quick Start](#quick-start)
- [Security Features](#security-features)
- [Technology Stack](#technology-stack)
- [Implementation Status](#implementation-status)
- [Contributing](#contributing)

## Overview

The Sky Genesis Enterprise API implements a modular, layered architecture that ensures scalability, security, and maintainability. Built with Rust and the Warp web framework, it provides enterprise-grade services including:

- **Secure Key Management**: API key generation, rotation, and certificate-coupled authentication
- **Identity Management**: JWT-based authentication with Keycloak integration
- **Communication Services**: VoIP, WebSocket, and XMPP-based real-time messaging
- **Mail Services**: Dynamic routing and secure email processing
- **Monitoring & Observability**: Comprehensive metrics and audit logging

## Architecture

The API follows a clean, layered architecture with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────────┐
│                    Presentation Layer                       │
│  ┌─────────────────┐    ┌─────────────────┐                 │
│  │   HTTP Routes   │    │   Middlewares   │                 │
│  │ • REST Endpoints│    │ • JWT Auth      │                 │
│  │ • WebSocket     │    │ • Validation    │                 │
│  └─────────────────┘    └─────────────────┘                 │
└─────────────────────────────────────────────────────────────┘
                                 │
┌─────────────────────────────────────────────────────────────┐
│                   Business Logic Layer                      │
│  ┌─────────────────┐    ┌─────────────────┐                 │
│  │  Controllers    │    │   Services      │                 │
│  │ • Request/Resp  │    │ • Auth Service  │                 │
│  │ • Error Handling│    │ • Key Service   │                 │
│  └─────────────────┘    └─────────────────┘                 │
└─────────────────────────────────────────────────────────────┘
                                 │
┌─────────────────────────────────────────────────────────────┐
│                   Integration Layer                         │
│  ┌─────────────────┐    ┌─────────────────┐                 │
│  │  Core Clients   │    │   Data Access   │                 │
│  │ • Vault Client  │    │ • Database      │                 │
│  │ • Keycloak      │    │ • Cache         │                 │
│  └─────────────────┘    └─────────────────┘                 │
└─────────────────────────────────────────────────────────────┘
                                 │
┌─────────────────────────────────────────────────────────────┐
│                   External Dependencies                     │
│  • HashiCorp Vault    • Keycloak    • PostgreSQL            │
│  • Redis             • Stalwart Mail • Monitoring Stack     │
└─────────────────────────────────────────────────────────────┘
```

### Key Architectural Principles

- **Modularity**: Clear separation between HTTP handling, business logic, and data access
- **Security-First**: Multi-layered authentication and encryption
- **Scalability**: Asynchronous processing with connection pooling
- **Observability**: Comprehensive logging, metrics, and tracing
- **Testability**: Dependency injection and isolated unit testing

## Documentation Structure

### 📋 Core Documentation
- **[API Overview](api-overview.md)** - High-level architecture and key features
- **[API Endpoints](api-endpoints.md)** - Complete REST API reference
- **[Data Models](data-models.md)** - Request/response structures and validation

### 🏗️ Technical Implementation
- **[Main Entry Point](main.md)** - Application bootstrap and configuration
- **[Routes](routes.md)** - HTTP route definitions and middleware integration
- **[Controllers](controllers.md)** - Request handling and response formatting
- **[Services](services.md)** - Business logic and external service integration
- **[Core Integrations](core.md)** - Vault and Keycloak client implementations
- **[Middlewares](middlewares.md)** - Authentication and request processing
- **[Utilities](utils.md)** - Helper functions for cryptography and validation

### 🔐 Security & Authentication
- **[Certificate Authentication](certificate-auth-example.md)** - Certificate-coupled API keys guide
- **[Two-Factor Authentication](two-factor-auth.md)** - 2FA implementation details
- **[OIDC Integration](oidc-fido2.md)** - OpenID Connect and FIDO2 support

### 📧 Communication Services
- **[Mail Overview](mail-overview.md)** - Email processing architecture
- **[Mail Endpoints](mail-endpoints.md)** - Email API reference
- **[Mail Integration](mail-integration.md)** - Stalwart server integration
- **[VoIP Integration](voip-integration.md)** - Voice over IP and PBX integration
- **[WebSocket/XMPP](xmpp-websocket.md)** - Real-time messaging protocols

### 🔧 Infrastructure & Operations
- **[Docker Deployment](docker.md)** - Containerization and orchestration
- **[Monitoring](monitoring-grafana-integration.md)** - Metrics and alerting setup
- **[Security Guidelines](security.md)** - Security best practices
- **[Configuration](config.md)** - Environment and application configuration

## Quick Start

### Prerequisites
- Rust 1.70+ with 2021 edition
- PostgreSQL 13+
- Redis 6+
- HashiCorp Vault
- Keycloak 20+

### Installation
```bash
# Clone the repository
git clone https://github.com/skygenesisenterprise/api-service.git
cd api-service

# Install dependencies
cargo build

# Configure environment
cp .env.example .env
# Edit .env with your configuration

# Run the service
cargo run
```

### Basic Usage
```bash
# Health check
curl http://localhost:8080/hello

# Authenticate
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password"}'

# Create API key
curl -X POST http://localhost:8080/api/keys \
  -H "Authorization: Bearer <jwt_token>" \
  -H "Content-Type: application/json" \
  -d '{"type":"client","tenant":"default"}'
```

## Security Features

### Multi-Layer Authentication
The API implements a comprehensive security model:

- **JWT Authentication**: Bearer token-based user authentication
- **Certificate-Coupled API Keys**: Two-factor authentication with digital signatures
- **App Tokens**: Service-level authentication for external integrations
- **FIDO2/WebAuthn**: Hardware-based authentication support

### Certificate-Coupled Authentication
Certificate-coupled API keys provide enhanced security through cryptographic proof:

1. **JWT Token**: Establishes user identity and permissions
2. **Digital Signature**: Proves API key ownership via RSA/ECDSA signatures
3. **Timestamp Validation**: Prevents replay attacks
4. **Certificate Verification**: Validates certificate authenticity

**Supported Algorithms:**
- RSA with SHA-256 (PKCS#1 v1.5)
- ECDSA with P-256 curve and SHA-256

### Data Protection
- **End-to-End Encryption**: TLS 1.3 for all communications
- **Secret Management**: HashiCorp Vault for key storage and rotation
- **Audit Logging**: Comprehensive logging of all security events
- **Input Validation**: Strict validation of all user inputs
- **Rate Limiting**: Protection against abuse and DoS attacks

## Data Flow Architecture

### Authentication Flow
```
┌─────────────┐    ┌──────────────┐    ┌──────────────┐    ┌─────────────┐
│   Client    │───▶│ JWT Middleware│───▶│Auth Controller│───▶│Keycloak/OIDC│
└─────────────┘    └──────────────┘    └──────────────┘    └─────────────┘
                                                        │
                                                        ▼
                                               ┌──────────────┐
                                               │ JWT Response │
                                               └──────────────┘
```

### API Key Management Flow
```
┌─────────────┐    ┌──────────────┐    ┌──────────────┐    ┌─────────────┐
│   Client    │───▶│ JWT Middleware│───▶│Key Controller│───▶│ Key Service │
└─────────────┘    └──────────────┘    └──────────────┘    └─────────────┘
                                                        │
                                                        ▼
                                               ┌──────────────┐
                                               │ Vault Client │
                                               └──────────────┘
```

### External Integrations
- **HashiCorp Vault**: Secure secret storage and automatic key rotation
- **Keycloak**: Identity and access management with OIDC support
- **PostgreSQL**: Persistent data storage for audit logs and metadata
- **Redis**: Session management and caching
- **Stalwart Mail**: Dynamic email routing and processing

## Technology Stack

### Core Technologies
| Component | Technology | Version | Purpose |
|-----------|------------|---------|---------|
| **Language** | Rust | 1.70+ (2021 edition) | High-performance, memory-safe development |
| **Web Framework** | Warp | 0.3.x | Asynchronous, type-safe HTTP server |
| **Async Runtime** | Tokio | 1.x | Asynchronous I/O and task management |
| **Serialization** | Serde | 1.x | JSON and data structure serialization |
| **Authentication** | JWT + Keycloak | 8.x + 20.x | Identity and access management |
| **Secret Management** | HashiCorp Vault | Latest | Secure key storage and rotation |
| **Database** | PostgreSQL | 13+ | Persistent data storage |
| **Cache** | Redis | 6+ | Session and data caching |
| **Mail Server** | Stalwart | Latest | Dynamic email routing |

### Key Dependencies
```toml
[dependencies]
# Web Framework & Async
warp = "0.3"                    # High-performance web framework
tokio = { version = "1", features = ["full"] }
futures = "0.3"                  # Future utilities

# Serialization & Data
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"              # JSON handling
uuid = { version = "1.0", features = ["v4"] }
chrono = { version = "0.4", features = ["serde"] }

# Authentication & Security
jsonwebtoken = "8.0"            # JWT token handling
reqwest = { version = "0.11", features = ["json"] }
rsa = { version = "0.9", features = ["sha2", "pem", "pkcs1v15"] }
p256 = { version = "0.13", features = ["ecdsa", "pem"] }
sha2 = "0.10"                   # Cryptographic hashing
base64 = "0.21"                 # Base64 encoding

# External Services
vault = "0.1"                   # Vault client
keycloak = "0.1"                # Keycloak integration
redis = "0.23"                  # Redis client
postgres = "0.19"               # PostgreSQL driver

# Utilities
dotenv = "0.15"                 # Environment configuration
env_logger = "0.10"             # Logging
clap = { version = "4.0", features = ["derive"] }  # CLI parsing
```

## Implementation Status

### ✅ Production Ready
- **Core Architecture**: Complete modular design with clean separation of concerns
- **Authentication System**: JWT + Keycloak integration with OIDC support
- **API Key Management**: Full lifecycle management with Vault integration
- **Certificate-Coupled Keys**: RSA/ECDSA two-factor authentication
- **REST API**: Complete endpoint implementation with OpenAPI documentation
- **Error Handling**: Structured error responses and logging
- **Security**: Cryptographic signature verification and audit logging

### 🚧 In Active Development
- **Database Integration**: PostgreSQL schema and migration system
- **Monitoring Stack**: Prometheus metrics and Grafana dashboards
- **Performance Optimization**: Caching strategies and connection pooling
- **WebSocket Services**: Real-time communication protocols

### 📋 Planned Features
- **Multi-Tenant Support**: Advanced tenant isolation and management
- **API Versioning**: Semantic versioning and backward compatibility
- **Administration Interface**: Web-based management console
- **Migration Tools**: Database migration and data transformation utilities
- **Advanced Analytics**: Usage metrics and performance insights

## Project Structure

```
api/
├── src/
│   ├── main.rs                 # Application entry point
│   ├── config/                 # Configuration management
│   ├── controllers/            # HTTP request handlers
│   │   ├── auth_controller.rs
│   │   ├── key_controller.rs
│   │   ├── voip_controller.rs
│   │   └── mod.rs
│   ├── core/                   # External service clients
│   │   ├── vault_client.rs
│   │   ├── keycloak_client.rs
│   │   └── mod.rs
│   ├── middlewares/            # Authentication middleware
│   ├── models/                 # Data structures and DTOs
│   ├── routes/                 # Route definitions
│   ├── services/               # Business logic layer
│   │   ├── auth_service.rs
│   │   ├── key_service.rs
│   │   └── mod.rs
│   ├── utils/                  # Utility functions
│   └── websocket.rs            # WebSocket server
├── tests/                      # Integration tests
├── Cargo.toml                  # Rust dependencies
└── Cargo.lock

docs/                           # Documentation
├── README.md                   # This file
├── api-overview.md
├── api-endpoints.md
└── ...

infrastructure/                 # Deployment configurations
├── docker/
├── kubernetes/
└── terraform/

runbooks/                       # Operational guides
├── ci-cd/
├── containers/
└── monitoring/
```

## Design Principles

### 🏗️ Architectural Patterns
- **Clean Architecture**: Strict separation between business logic and infrastructure
- **Dependency Injection**: Constructor-based injection for testability
- **Functional Programming**: Pure functions and immutable data structures
- **Error Handling**: Explicit error types with proper propagation

### 🔒 Security Principles
- **Defense in Depth**: Multiple security layers and controls
- **Zero Trust**: Every request requires explicit authentication
- **Least Privilege**: Minimal permissions for all operations
- **Audit Everything**: Comprehensive logging of security events

### 📈 Performance Principles
- **Asynchronous Processing**: Non-blocking I/O operations
- **Connection Pooling**: Efficient resource management
- **Caching Strategy**: Intelligent caching for improved performance
- **Horizontal Scaling**: Stateless design for easy scaling

## Contributing

We welcome contributions to the Sky Genesis Enterprise API project. Please see our [Contributing Guidelines](CONTRIBUTING.md) for details on:

- Development setup and workflow
- Code style and standards
- Testing requirements
- Pull request process

### Development Workflow
1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Ensure all tests pass
5. Submit a pull request

### Testing
```bash
# Run unit tests
cargo test

# Run integration tests
cargo test --test integration

# Run with coverage
cargo tarpaulin
```

---

## 📚 Additional Resources

- **[API Endpoints Reference](api-endpoints.md)** - Complete API documentation
- **[Deployment Guide](docker.md)** - Containerization and orchestration
- **[Security Guidelines](security.md)** - Security best practices
- **[Monitoring Setup](monitoring-grafana-integration.md)** - Observability configuration

For questions or support, please refer to our [Support Documentation](SUPPORT.md) or create an issue in our [GitHub Repository](https://github.com/sky-genesis/enterprise-api/issues).