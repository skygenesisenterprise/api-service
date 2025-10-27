# Sky Genesis Enterprise API Documentation

This documentation covers the complete architecture of the Sky Genesis Enterprise API, a Rust web service for secure key management and authentication.

## General Architecture

The API follows a modular layered architecture with clear separation of responsibilities:

```
┌─────────────────────────────────────────────────────────────┐
│                    HTTP Layer (Warp)                        │
│  ┌─────────────────┐    ┌─────────────────┐                 │
│  │   Routes        │    │   Middlewares   │                 │
│  │ • /auth/*       │    │ • JWT Auth      │                 │
│  │ • /api/keys/*   │    │ • Validation    │                 │
│  └─────────────────┘    └─────────────────┘                 │
└─────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────┐
│                   Business Layer                            │
│  ┌─────────────────┐    ┌─────────────────┐                 │
│  │  Controllers    │    │   Services      │                 │
│  │ • Auth Ctrl     │    │ • AuthService   │                 │
│  │ • Key Ctrl      │    │ • KeyService    │                 │
│  └─────────────────┘    └─────────────────┘                 │
└─────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────┐
│                   Integration Layer                         │
│  ┌─────────────────┐    ┌─────────────────┐                 │
│  │  Core Clients   │    │   Data Access   │                 │
│  │ • VaultClient   │    │ • Queries       │                 │
│  │ • KeycloakClient│    │ • Models        │                 │
│  └─────────────────┘    └─────────────────┘                 │
└─────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────┐
│                   External Services                          │
│  • HashiCorp Vault    • Keycloak    • PostgreSQL (planned)  │
└─────────────────────────────────────────────────────────────┘
```

## Documentation Structure

### 📋 Overview
- **[API Overview](api-overview.md)** - Global architecture, technologies and key features
- **[API Endpoints](api-endpoints.md)** - Complete endpoint reference with examples
- **[Data Models](data-models.md)** - Data structures and validation rules

### 🏗️ Technical Architecture
- **[Main Entry Point](main.md)** - Application startup and initialization
- **[Routes](routes.md)** - API route definitions with Warp filters
- **[Controllers](controllers.md)** - HTTP request handlers and response formatting
- **[Services](services.md)** - Business logic and external integrations
- **[Core Integrations](core.md)** - Vault and Keycloak clients with connection management
- **[Middlewares](middlewares.md)** - JWT authentication and request processing
- **[Utilities](utils.md)** - Helper functions (tokens, keys, hashing)

### 📧 Mail Module
- **[Mail Overview](mail-overview.md)** - Mail module architecture and security model
- **[Mail Endpoints](mail-endpoints.md)** - Complete mail API reference
- **[Mail Integration](mail-integration.md)** - Stalwart server integration details

### 🔧 Planned Components
- **[Configuration](config.md)** - Centralized configuration management (to implement)
- **[Database Queries](queries.md)** - Database abstraction layer (currently placeholder)

## Data Flow

### User Authentication
```
Client Request → JWT Middleware → Auth Controller → Auth Service → Keycloak Client
                                                                      ↓
                                                            Token Generation → JWT Response
```

### API Key Management
```
Client Request → JWT Middleware → Key Controller → Key Service → Vault Client
                                                                    ↓
                                                          Key Rotation → Database Log
```

### External Integration Points
- **Vault**: Secure secret storage and automatic key rotation
- **Keycloak**: User management and OAuth2 authentication
- **PostgreSQL** (planned): Persistence of audit data and metadata

## Architectural Patterns

### Dependency Injection
- Use of `Arc<T>` for thread-safe service sharing
- Constructor injection to facilitate testing
- Clear separation between business logic and infrastructure

### Error Handling
- Layer-specific error types
- Propagation via `Result<T, Box<dyn std::error::Error>>`
- Centralized HTTP rejection handling

### Asynchronous Programming
- Tokio runtime for I/O operations
- `async/await` for code readability
- Timeout and reconnection management

### Security
- Multi-level authentication (JWT + App Token)
- Strict input validation
- Audit logging of sensitive operations
- Secret encryption via Vault

## Technologies and Dependencies

### Technical Stack
- **Language**: Rust 1.70+ with 2021 edition
- **Web Framework**: Warp (async, type-safe)
- **Authentication**: JWT (jsonwebtoken) + Keycloak OAuth2
- **Secrets**: HashiCorp Vault with AppRole
- **Database**: PostgreSQL (planned)
- **Async Runtime**: Tokio
- **Serialization**: Serde (JSON)
- **Logging**: env_logger (future configuration)

### Key Dependencies
```toml
[dependencies]
warp = "0.3"           # Web framework
tokio = { version = "1", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
jsonwebtoken = "8.0"   # JWT handling
reqwest = "0.11"       # HTTP client
uuid = "1.0"           # ID generation
chrono = "0.4"         # Date/time handling
dotenv = "0.15"        # Environment variables
```

## Implementation Status

### ✅ Implemented
- Complete modular architecture
- JWT authentication + Keycloak integration
- API key management with Vault
- Complete REST routes
- Structured error handling
- Basic unit tests

### 🚧 In Development
- Complete PostgreSQL integration
- Centralized configuration
- Metrics and monitoring
- Caching and performance optimization

### 📋 Planned
- Migration system
- Administration interface
- Advanced multi-tenant support
- API versioning
- OpenAPI documentation

## Module Structure

```
api/src/
├── main.rs              # 🚀 Entry point and orchestration
├── config/              # ⚙️ Configuration (placeholder)
├── controllers/         # 🎯 HTTP request handling
├── core/                # 🔗 External clients (Vault/Keycloak)
├── middlewares/         # 🛡️ Authentication and validation
├── models/              # 📊 Data structures
├── queries/             # 💾 Database access (placeholder)
├── routes/              # 🛣️ Endpoint definitions
├── services/            # 🏢 Business logic
├── tests/               # ✅ Unit tests
└── utils/               # 🔧 Utilities (tokens, keys)
```

## Design Principles

### Separation of Concerns
- **Routes**: Endpoint definitions only
- **Controllers**: Request parsing/validation
- **Services**: Pure business logic
- **Core**: Communication with external services

### Functional Programming
- Pure functions where possible
- Data immutability
- Explicit error handling
- Composition over inheritance

### Security First
- Systematic input validation
- Mandatory authentication
- Complete audit logging
- Secrets never hardcoded

---

*For practical usage examples, see [API Endpoints](api-endpoints.md). For local development, see [API Overview](api-overview.md).*