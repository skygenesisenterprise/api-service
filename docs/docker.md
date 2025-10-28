# Docker Usage in Sky Genesis API

This document explains how to use Docker for developing, building, and deploying the Sky Genesis Enterprise API.

## Table of Contents

- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [Development Setup](#development-setup)
- [Production Setup](#production-setup)
- [Common Commands](#common-commands)
- [Security](#security)
- [Monitoring and Logging](#monitoring-and-logging)
- [Troubleshooting](#troubleshooting)
- [Additional Resources](#additional-resources)

## Introduction

The Sky Genesis Enterprise API uses Docker to containerize its main components:
- **API Backend**: Rust service exposed on port 8080
- **Frontend**: Next.js application exposed on port 3000
- **Database**: PostgreSQL for data storage
- **Cache**: Redis for caching
- **Secret Management**: Vault for secure secret management
- **Authentication**: Keycloak for identity management
- **Reverse Proxy**: NGINX for routing and security

## Prerequisites

Before starting, ensure you have installed:
- Docker (version 20.10 or higher)
- Docker Compose (version 2.0 or higher)
- At least 4GB of available RAM
- Ports 3000, 8080, 5432, 6379, 8200, and 8081 available

## Development Setup

### Quick Start

To start the complete development environment:

```bash
cd infrastructure/docker
docker-compose up -d
```

This launches all services:
- API backend on http://localhost:8080
- Frontend on http://localhost:3000
- PostgreSQL database on localhost:5432
- Redis on localhost:6379
- Vault on http://localhost:8200
- Keycloak on http://localhost:8081

### Included Services

The `docker-compose.yml` file defines the following services:

#### API (Rust)
- **Image**: Built from `Dockerfile.dev`
- **Port**: 8080
- **Environment Variables**:
  - `DATABASE_URL`: PostgreSQL connection
  - `VAULT_ADDR`: Vault address
  - `REDIS_URL`: Redis connection
  - `JWT_SECRET`: JWT secret key
- **Volumes**: Source code mounting for hot reloading

#### Frontend (Next.js)
- **Image**: Built from `Dockerfile.frontend.dev`
- **Port**: 3000
- **Environment Variables**:
  - `API_URL`: Backend API URL
  - `NEXT_PUBLIC_API_URL`: Public API URL
- **Volumes**: Source code mounting for hot reloading

#### Database (PostgreSQL)
- **Image**: postgres:15-alpine
- **Port**: 5432
- **Database**: api_service
- **User**: postgres
- **Password**: password (change in production)
- **Volume**: Data persistence
- **Initialization**: SQL script `schema-pgsql.sql`

#### Cache (Redis)
- **Image**: redis:7-alpine
- **Port**: 6379
- **Persistence**: Append-only file enabled

#### Secret Management (Vault)
- **Image**: vault:1.15
- **Port**: 8200
- **Mode**: Development (root token = "root")
- **Volume**: Vault data persistence

#### Authentication (Keycloak)
- **Image**: quay.io/keycloak/keycloak:22.0
- **Port**: 8081
- **Database**: Shared PostgreSQL
- **Admin**: admin/admin (change in production)

#### Reverse Proxy (NGINX)
- **Image**: nginx:alpine
- **Ports**: 80 and 443
- **Configuration**: Project root `nginx.conf`

### Development Commands

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop all services
docker-compose down

# Rebuild and restart specific service
docker-compose up -d --build api

# Access running container
docker-compose exec api bash
```

## Production Setup

### Building Images

To build production images:

```bash
# Build API
docker build -f infrastructure/docker/Dockerfile.api -t skygenesisenterprise/api:latest .

# Build frontend
docker build -f infrastructure/docker/Dockerfile.frontend -t sky-genesis/frontend:latest .
```

### Environment Variables

The backend automatically loads default values from the `.env.example` file if environment variables are not defined. This allows easy modification of server domains by editing this file.

In production, configure the following variables:

```bash
# Database
DATABASE_URL=postgresql://user:password@host:5432/api_service

# Redis Cache
REDIS_URL=redis://host:6379

# Authentication
JWT_SECRET=your_jwt_secret_key

# API
API_URL=https://api.example.com

# Frontend
NEXT_PUBLIC_API_URL=https://api.example.com

# External servers (default values in .env.example)
VAULT_ADDR=https://vault.skygenesisenterprise.com
KEYCLOAK_URL=https://keycloak.skygenesisenterprise.com
STALWART_URL=https://stalwart.skygenesisenterprise.com
```

#### Domain Modification

To change server domains (e.g., from `.com` to `.local`):

1. **Edit the `.env.example` file**:
   ```bash
   VAULT_ADDR=https://vault.skygenesisenterprise.local
   KEYCLOAK_URL=https://keycloak.skygenesisenterprise.local
   STALWART_URL=https://stalwart.skygenesisenterprise.local
   SESSION_COOKIE_DOMAIN=skygenesisenterprise.local
   ```

2. **Or set environment variables**:
   ```bash
   export VAULT_ADDR=https://vault.skygenesisenterprise.local
   export KEYCLOAK_URL=https://keycloak.skygenesisenterprise.local
   export STALWART_URL=https://stalwart.skygenesisenterprise.local
   export SESSION_COOKIE_DOMAIN=skygenesisenterprise.local
   ```

Environment variables take priority over values in `.env.example`.

#### Shared Session System

The API implements a shared session system similar to Google, allowing users to stay logged in across applications:

#### Two-Factor Authentication (2FA)

2FA is optionally supported to enhance security for sensitive applications:

- **TOTP**: Authenticator apps (Google Authenticator, Authy)
- **SMS**: Codes sent via SMS
- **Email**: Codes sent via email
- **Recovery codes**: One-time use backup codes

##### 2FA Endpoints

```http
POST /auth/2fa/setup     # Setup 2FA method
POST /auth/2fa/verify    # Verify and activate
GET  /auth/2fa/methods   # List methods
DELETE /auth/2fa/methods/{id}  # Remove method
```

##### Per-Application Configuration

```bash
# Applications requiring 2FA
AETHER_MAIL_REQUIRES_2FA=true
AETHER_DRIVE_REQUIRES_2FA=true
```

See [docs/two-factor-auth.md](two-factor-auth.md) for complete documentation.

- **Session Cookies**: Secure storage of session tokens in browser
- **Shared Sessions**: Valid session grants access to all applications
- **Auto-expiration**: Sessions expire after 7 days by default
- **Security**: HttpOnly, Secure, SameSite cookies

##### Session Endpoints

- `POST /auth/session/login`: Login with existing session token
- `POST /auth/logout`: Logout current session
- `POST /auth/logout/all`: Logout all sessions
- `GET /auth/sessions`: List user's active sessions

##### Session Configuration

```bash
# Session lifetime (seconds)
SESSION_TTL_SECONDS=604800

# Session cookie name
SESSION_COOKIE_NAME=sky_genesis_session

# Cookie domain
SESSION_COOKIE_DOMAIN=skygenesisenterprise.com

# Secure cookie (HTTPS only)
SESSION_COOKIE_SECURE=true
```

#### Unified Applications Ecosystem

The API acts as a **centralized intermediary** for authentication across the entire Sky Genesis ecosystem, enabling **"One Account for All the Ecosystem"**.

##### Supported Applications

- **Aether Search**: Search engine
- **Aether Mail**: Email service
- **Aether Drive**: Cloud storage
- **Aether Calendar**: Calendar management

##### Ecosystem Endpoints

```http
GET  /auth/applications           # List accessible applications
POST /auth/applications/access    # Request application access
```

##### Authentication Flow

1. **Initial Login**: User logs in via central API
2. **Session Created**: Shared session cookie across all applications
3. **Application Access**: Each application validates session via API
4. **Granular Permissions**: Access control per application and feature

##### Usage Example

```javascript
// 1. Get list of applications
const apps = await fetch('/auth/applications');

// 2. Request access to Aether Mail
const access = await fetch('/auth/applications/access', {
  method: 'POST',
  headers: { 'Authorization': 'Bearer ' + userToken },
  body: JSON.stringify({
    application_id: 'aether-mail',
    requested_permissions: ['mail:read', 'mail:write']
  })
});

// 3. Use application token to access Aether Mail
const mailToken = access.access_token;
// This token can be used directly with Aether Mail
```

##### Ecosystem Security

- **Specific Tokens**: Each application receives a dedicated token
- **Isolated Permissions**: Granular control per application
- **Independent Expiration**: Application tokens expire separately
- **Centralized Revocation**: Ability to revoke access to specific applications

### Deployment

Use the `docker-compose.prod.yml` file for production deployment:

```bash
docker-compose -f infrastructure/docker/docker-compose.prod.yml up -d
```

This file includes:
- Production-optimized images
- NGINX configuration for reverse proxy
- SSL certificates
- Resource limits
- Restart policies

## Common Commands

### Container Management

```bash
# List running containers
docker ps

# View container logs
docker logs sky-genesis-api

# Stop specific container
docker stop sky-genesis-api

# Remove stopped containers
docker container prune

# Clean unused images
docker image prune -a
```

### Debugging

```bash
# Access container shell
docker exec -it sky-genesis-api /bin/bash

# View container statistics
docker stats

# Inspect container
docker inspect sky-genesis-api
```

### Service Health

```bash
# Check API health
curl http://localhost:8080/health

# Check frontend health
curl http://localhost:3000/api/health

# Check PostgreSQL
docker exec sky-genesis-postgres pg_isready -U postgres -d api_service
```

## Security

### Best Practices

- **Non-root users**: All containers use non-privileged users
- **Minimal images**: Use Alpine and Debian slim images
- **External secrets**: Secrets are not stored in images
- **Security scans**: Integrate regular scans with Trivy

### Security Scanning

```bash
# Scan image for vulnerabilities
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasecurity/trivy image skygenesisenterprise/api:latest

# Scan for secrets
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  zricethezav/gitleaks:latest docker --image skygenesisenterprise/api:latest
```

### Secure NGINX Configuration

The `nginx.conf` file includes security headers:
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security`
- `Referrer-Policy`

## Monitoring and Logging

### Health Checks

All services include configured health checks:
- **Interval**: 30 seconds
- **Timeout**: 10 seconds
- **Retries**: 3
- **Start period**: 30-60 seconds depending on service

### Logging

JSON logging configuration with rotation:
```yaml
logging:
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"
```

### Metrics

For Prometheus metrics export, expose port 9090 and configure node_exporter.

## Troubleshooting

### Common Issues

#### Port Already in Use
```bash
# Identify process using the port
lsof -i :8080

# Kill the process
kill -9 <PID>
```

#### Container Won't Start
```bash
# View detailed logs
docker logs sky-genesis-api

# Start in debug mode
docker run -it --entrypoint /bin/bash skygenesisenterprise/api:latest
```

#### Database Connection Failed
```bash
# Check if PostgreSQL is running
docker ps | grep postgres

# View PostgreSQL logs
docker logs sky-genesis-postgres

# Test connection
docker exec sky-genesis-postgres pg_isready -U postgres -d api_service
```

#### Volume Issues
```bash
# List volumes
docker volume ls

# Inspect volume
docker volume inspect postgres_data

# Remove volume (WARNING: data loss)
docker volume rm postgres_data
```

### Diagnostic Commands

```bash
# Service status
docker-compose ps

# Logs from all services
docker-compose logs

# Resource usage
docker stats

# Docker events
docker events

# Clean system
docker system prune -a --volumes
```

## Additional Resources

- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose Guide](https://docs.docker.com/compose/)
- [Docker Best Practices](https://docs.docker.com/develop/dev-best-practices/)
- [Docker Security](https://docs.docker.com/engine/security/)
- [Multi-stage Builds](https://docs.docker.com/develop/dev-best-practices/)

---

**🐳 Containerized • 🔒 Secure • 🚀 Optimized**