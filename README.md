# 🔐 Sky Genesis Enterprise API Service

[![Rust](https://img.shields.io/badge/Rust-1.70+-000000?style=for-the-badge&logo=rust)](https://www.rust-lang.org/)
[![Warp](https://img.shields.io/badge/Warp-0.3-000000?style=for-the-badge)](https://crates.io/crates/warp)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-12+-4169E1?style=for-the-badge&logo=postgresql)](https://www.postgresql.org/)
[![Next.js](https://img.shields.io/badge/Next.js-15-000000?style=for-the-badge&logo=next.js)](https://nextjs.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker)](https://www.docker.com/)

> **Enterprise-grade API management platform** with advanced security, certificate-coupled authentication, and comprehensive audit capabilities.

## 📋 Table of Contents

- [✨ Overview](#-overview)
- [🏗️ Architecture](#️-architecture)
- [🔐 Security Features](#-security-features)
- [🚀 Quick Start](#-quick-start)
- [📚 API Documentation](#-api-documentation)
- [🛠️ Development](#️-development)
- [🚢 Deployment](#-deployment)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)

## ✨ Overview

Sky Genesis Enterprise API Service is a robust, production-ready platform designed for enterprise API management and secure communication. Built with modern technologies and following security best practices, it provides:

- **🔑 Certificate-Coupled Authentication**: Two-factor authentication combining JWT tokens with digital signatures
- **🏢 Multi-Tenant Architecture**: Complete data isolation and organization management
- **🔒 Advanced Security**: Integration with HashiCorp Vault and Keycloak
- **📊 Comprehensive Audit**: Full request tracking and compliance logging
- **🎛️ Admin Portal**: Web-based management interface
- **📨 Messaging System**: Real-time communication capabilities

## 🏗️ Architecture

### System Components

```
┌─────────────────────────────────────────────────────────────┐
│                    🌐 Client Layer                           │
│  • REST API Clients    • Admin Portal    • Mobile Apps      │
└─────────────────────────────────────────────────────────────┘
                                 │
┌─────────────────────────────────────────────────────────────┐
│                 🚀 Application Layer                        │
│  ┌─────────────────┐    ┌─────────────────┐                 │
│  │   Next.js       │    │   Rust API      │                 │
│  │   Admin Portal  │    │   (Warp)        │                 │
│  └─────────────────┘    └─────────────────┘                 │
└─────────────────────────────────────────────────────────────┘
                                 │
┌─────────────────────────────────────────────────────────────┐
│                 🔧 Service Layer                            │
│  ┌─────────────────┐    ┌─────────────────┐                 │
│  │   Keycloak      │    │   Vault         │                 │
│  │   Auth Service  │    │   Secrets       │                 │
│  └─────────────────┘    └─────────────────┘                 │
└─────────────────────────────────────────────────────────────┘
                                 │
┌─────────────────────────────────────────────────────────────┐
│                 💾 Data Layer                               │
│  ┌─────────────────┐    ┌─────────────────┐                 │
│  │   PostgreSQL    │    │   Redis         │                 │
│  │   Primary DB    │    │   Cache         │                 │
│  └─────────────────┘    └─────────────────┘                 │
└─────────────────────────────────────────────────────────────┘
```

### Technology Stack

| Component | Technology | Version | Purpose |
|-----------|------------|---------|---------|
| **Backend API** | Rust + Warp | 1.70+ | High-performance REST API |
| **Frontend** | Next.js + TypeScript | 15+ | Admin portal interface |
| **Database** | PostgreSQL | 12+ | Primary data storage |
| **Authentication** | Keycloak | Latest | User identity management |
| **Secrets** | HashiCorp Vault | Latest | Secure credential storage |
| **Cache** | Redis | 6+ | Session and data caching |
| **Container** | Docker | Latest | Application containerization |

### Module Structure

```
api/                    # 🦀 Rust Backend API
├── src/
│   ├── controllers/    # 🎯 HTTP request handlers
│   ├── services/       # 🏢 Business logic layer
│   ├── middlewares/    # 🛡️ Authentication & validation
│   ├── models/         # 📊 Data structures
│   ├── routes/         # 🛣️ API endpoint definitions
│   ├── core/           # 🔗 External service clients
│   └── utils/          # 🔧 Cryptographic utilities
├── Cargo.toml         # 📦 Rust dependencies
└── Cargo.lock         # 🔒 Dependency lockfile

app/                    # ⚛️ Next.js Admin Portal
├── src/
│   ├── app/           # 📱 Next.js 13+ app directory
│   ├── components/    # 🧩 Reusable UI components
│   ├── lib/           # 🔌 API client utilities
│   └── styles/        # 🎨 Global stylesheets
├── package.json       # 📦 Node.js dependencies
└── next.config.ts     # ⚙️ Next.js configuration

data/                   # 🗄️ Database Assets
├── schema-pgsql.sql   # 🏗️ PostgreSQL schema
└── migrations/        # 🔄 Database migrations

docs/                   # 📚 Documentation
├── api-endpoints.md   # 🔗 API reference
├── certificate-auth-example.md  # 🔐 Auth guide
└── README.md          # 📖 Module documentation

infrastructure/         # 🏭 Deployment Assets
├── docker/            # 🐳 Container definitions
├── k8s/              # ☸️ Kubernetes manifests
└── terraform/        # 🌍 Infrastructure as Code
```

## 🔐 Security Features

### Certificate-Coupled Authentication

Our proprietary two-factor authentication system combines traditional JWT tokens with cryptographic certificate validation:

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant Vault
    participant Keycloak

    Client->>API: Request + JWT + Certificate Signature
    API->>Keycloak: Validate JWT Token
    API->>Vault: Retrieve Certificate Public Key
    API->>API: Verify Digital Signature
    API->>Client: Authenticated Response
```

**Key Benefits:**
- **🔒 Defense in Depth**: JWT compromise alone insufficient
- **✍️ Non-Repudiation**: Cryptographic proof of request origin
- **🛡️ Anti-Theft Protection**: Stolen credentials require both factors
- **⚡ Replay Prevention**: Timestamp-based signature validation

### Supported Algorithms

| Algorithm | Key Size | Use Case | Security Level |
|-----------|----------|----------|----------------|
| **RSA** | 2048-bit | General purpose | High |
| **ECDSA** | P-256 | Resource constrained | High |
| **SHA-256** | N/A | Hashing | Standard |

### Security Controls

- **🔐 Encrypted Secrets**: All sensitive data stored in Vault
- **👥 Multi-Tenant Isolation**: Complete data segregation
- **📊 Audit Logging**: Comprehensive request tracking
- **🚦 Rate Limiting**: DDoS protection and abuse prevention
- **🔍 Input Validation**: Strict parameter sanitization
- **🔒 TLS Enforcement**: HTTPS-only in production

## 🚀 Quick Start

### Prerequisites

- **Rust**: 1.70+ with Cargo
- **Node.js**: 18+ with pnpm
- **PostgreSQL**: 12+ with pgAdmin
- **Docker**: Optional, for containerized deployment

### 1. Clone & Setup

```bash
# Clone repository
git clone https://github.com/skygenesisenterprise/api-service.git
cd api-service

# Install Rust dependencies
cd api && cargo build --release && cd ..

# Install Node.js dependencies
pnpm install
```

### 2. Environment Configuration

```bash
# Copy environment template
cp .env.example .env

# Edit with your configuration
nano .env
```

**Required Environment Variables:**
```bash
# Database
DATABASE_URL=postgresql://user:password@localhost:5432/api_service

# Vault Configuration
VAULT_ADDR=https://vault.your-domain.com
VAULT_ROLE_ID=your_role_id
VAULT_SECRET_ID=your_secret_id

# Keycloak Configuration
KEYCLOAK_URL=https://keycloak.your-domain.com
KEYCLOAK_REALM=your_realm
KEYCLOAK_CLIENT_ID=api-client

# JWT Secret
JWT_SECRET=your_secure_jwt_secret

# Server Port
PORT=8080
```

### 3. Database Initialization

```bash
# Create database
createdb api_service

# Run schema
psql -U your_user -d api_service -f data/schema-pgsql.sql

# Create initial organization and admin key
psql -U your_user -d api_service << 'EOF'
INSERT INTO api_service.organizations (name, country_code)
VALUES ('Your Company', 'US');

INSERT INTO api_service.api_keys (organization_id, key_value, label, permissions)
VALUES (
  (SELECT id FROM api_service.organizations WHERE name = 'Your Company'),
  'sk_admin_' || encode(gen_random_bytes(32), 'hex'),
  'Admin Key',
  ARRAY['read', 'write', 'admin']
);
EOF
```

### 4. Start Services

```bash
# Terminal 1: Start Rust API backend
cd api && cargo run

# Terminal 2: Start Next.js admin portal
pnpm run dev:frontend

# Terminal 3: Start development database (optional)
docker run -d --name postgres -p 5432:5432 -e POSTGRES_PASSWORD=password postgres:13
```

### 5. Access Applications

- **🔗 API Endpoints**: `http://localhost:8080`
- **🎛️ Admin Portal**: `http://localhost:3000`
- **📚 API Documentation**: `http://localhost:8080/docs`

### 6. First API Call

```bash
# Test API connectivity
curl http://localhost:8080/api/health

# Create certificate-coupled API key
curl -X POST "http://localhost:8080/api/keys/with-certificate?type=client&tenant=your-org&cert_type=rsa" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## 🏭 Infrastructure as Code

Complete infrastructure setup available in [`infrastructure/`](./infrastructure/) directory:

- **🐳 Docker**: Multi-stage builds, security scanning, production containers
- **☸️ Kubernetes**: Helm charts, Kustomize overlays, production deployments
- **🌍 Terraform**: Multi-cloud infrastructure, automated provisioning
- **🔧 Ansible**: Configuration management, server provisioning
- **📊 Monitoring**: Prometheus/Grafana stack, alerting
- **🚀 CI/CD**: GitHub Actions, Jenkins, GitLab CI pipelines
- **🔒 Security**: Container scanning, runtime security, compliance
- **💾 Backup**: Automated backups, disaster recovery

### Quick Infrastructure Setup

```bash
# Local development with Docker
cd infrastructure/docker && docker-compose up -d

# Production deployment with Kubernetes
cd infrastructure/kubernetes && kubectl apply -k overlays/production

# Full infrastructure with Terraform
cd infrastructure/terraform && terraform apply
```

## 📚 API Documentation

### Core Endpoints

| Method | Endpoint | Description | Authentication |
|--------|----------|-------------|----------------|
| `GET` | `/api/health` | Health check | None |
| `POST` | `/api/keys` | Create API key | JWT |
| `POST` | `/api/keys/with-certificate` | Create certificate-coupled key | JWT |
| `GET` | `/api/keys/{id}/public-key` | Get public key | JWT |
| `DELETE` | `/api/keys/{id}/certificate` | Revoke certificate | JWT |
| `GET` | `/api/secure/cert` | Certificate-authenticated endpoint | JWT + Certificate |

### Authentication Examples

#### Standard JWT Authentication
```bash
curl -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..." \
  http://localhost:8080/api/keys
```

#### Certificate-Coupled Authentication
```bash
# Generate signature (see docs/certificate-auth-example.md)
SIGNATURE=$(echo -n "${API_KEY_ID}${TIMESTAMP}" | openssl dgst -sha256 -sign private_key.pem | base64 -w 0)

curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "X-API-Key: YOUR_API_KEY_ID" \
  -H "X-Timestamp: $(date +%s)" \
  -H "X-Signature: $SIGNATURE" \
  http://localhost:8080/api/secure/cert
```

### Response Format

```json
{
  "success": true,
  "data": { ... },
  "timestamp": "2024-01-01T00:00:00Z",
  "request_id": "req_1234567890"
}
```

## 🛠️ Development

### Development Commands

```bash
# Full development environment
pnpm run dev

# Backend only (Rust)
cd api && cargo run

# Frontend only (Next.js)
pnpm run dev:frontend

# Run tests
pnpm test

# Lint code
pnpm run lint

# Type checking
pnpm run typecheck
```

### Code Quality

```bash
# Rust code quality
cd api && cargo clippy && cargo fmt

# Security audit
cd api && cargo audit

# Performance profiling
cd api && cargo build --release --features profiling
```

### Testing Strategy

```bash
# Unit tests
cargo test --lib

# Integration tests
cargo test --test integration

# API tests
pnpm run test:api

# Load testing
pnpm run test:load
```

## 🚢 Deployment

### Docker Deployment

```bash
# Build production image
docker build -t skygenesisenterprise/api .

# Run with environment variables
docker run -d \
  --name skygenesisenterprise/api \
  -p 8080:8080 \
  -e DATABASE_URL=postgresql://... \
  -e VAULT_ADDR=https://... \
  skygenesisenterprise/api
```

### Kubernetes Deployment

```bash
# Deploy to Kubernetes
kubectl apply -f infrastructure/k8s/

# Check deployment status
kubectl get pods -l app=skygenesisenterprise/api
```

### Production Checklist

- [ ] Environment variables configured
- [ ] Database migrations applied
- [ ] SSL/TLS certificates installed
- [ ] Vault secrets populated
- [ ] Keycloak realm configured
- [ ] Monitoring and logging enabled
- [ ] Backup strategy implemented
- [ ] Security headers configured

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](./.github/CONTRIBUTING.md) for details.

### Development Workflow

1. **Fork** the repository
2. **Clone** your fork: `git clone https://github.com/skygenesisenterprise/api-service.git`
3. **Create** a feature branch: `git checkout -b feature/amazing-feature`
4. **Make** your changes with tests
5. **Commit** your changes: `git commit -m 'Add amazing feature'`
6. **Push** to your branch: `git push origin feature/amazing-feature`
7. **Open** a Pull Request

### Code Standards

- **Rust**: Follow `rustfmt` and `clippy` recommendations
- **TypeScript**: Use ESLint and Prettier
- **Testing**: Minimum 80% code coverage required
- **Documentation**: Update docs for any API changes

## 🆘 Support & Community

- **📚 Documentation**: [docs/](./docs/) directory
- **🐛 Bug Reports**: [GitHub Issues](https://github.com/skygenesisenterprise/api-service/issues)
- **💬 Discussions**: [GitHub Discussions](https://github.com/skygenesisenterprise/api-service/discussions)
- **📧 Email**: support@skygenesisenterprise.com

## 🙏 Acknowledgments

Built with ❤️ by the Sky Genesis Enterprise team. Special thanks to our contributors and the open-source community.

---
## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

**🔒 Secure • 🚀 Performant • 🏢 Enterprise-Ready**

*Sky Genesis Enterprise API Service - Powering the next generation of enterprise applications.*