# 🐳 Docker Infrastructure

Complete Docker setup for Sky Genesis Enterprise API Service with multi-stage builds, security scanning, and production-ready configurations.

## 📁 Structure

```
docker/
├── Dockerfile.api          # Rust API production build
├── Dockerfile.frontend     # Next.js production build
├── Dockerfile.dev          # Development build
├── docker-compose.yml      # Local development stack
├── docker-compose.prod.yml # Production stack
├── .dockerignore          # Docker ignore rules
└── scripts/               # Build and deployment scripts
```

## 🚀 Quick Start

### Development Environment

```bash
# Start full development stack
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Production Build

```bash
# Build production images
docker build -f infrastructure/docker/Dockerfile.api -t sky-genesis/api:latest .
docker build -f infrastructure/docker/Dockerfile.frontend -t sky-genesis/frontend:latest .

# Run production stack
docker-compose -f infrastructure/docker/docker-compose.prod.yml up -d
```

## 🏗️ Dockerfiles

### API Dockerfile (Production)

```dockerfile
# Multi-stage Rust build
FROM rust:1.70-slim AS builder

WORKDIR /api
COPY api/Cargo.toml api/Cargo.lock ./
COPY api/src ./src

# Build optimized release binary
RUN cargo build --release

# Runtime stage
FROM debian:12-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /api/target/release/api /usr/local/bin/api

# Create non-root user
RUN useradd -r -s /bin/false apiuser
USER apiuser

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

CMD ["api"]
```

### Frontend Dockerfile (Production)

```dockerfile
# Multi-stage Next.js build
FROM node:18-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

COPY . .
RUN npm run build

# Runtime stage
FROM node:18-alpine AS runner

WORKDIR /app
ENV NODE_ENV=production

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nextjs -u 1001

COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next ./.next
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json

USER nextjs

EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/api/health || exit 1

CMD ["npm", "start"]
```

## 🐙 Docker Compose Configurations

### Development Stack

```yaml
version: '3.8'

services:
  api:
    build:
      context: ../..
      dockerfile: infrastructure/docker/Dockerfile.dev
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=postgresql://postgres:password@postgres:5432/api_service
      - VAULT_ADDR=http://vault:8200
      - REDIS_URL=redis://redis:6379
    depends_on:
      - postgres
      - vault
      - redis
    volumes:
      - ../../api:/api
    command: cargo watch -x run

  frontend:
    build:
      context: ../..
      dockerfile: infrastructure/docker/Dockerfile.frontend.dev
    ports:
      - "3000:3000"
    environment:
      - API_URL=http://api:8080
    depends_on:
      - api
    volumes:
      - ../../app:/app
    command: npm run dev

  postgres:
    image: postgres:15
    ports:
      - "5432:5432"
    environment:
      - POSTGRES_DB=api_service
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ../../data/schema-pgsql.sql:/docker-entrypoint-initdb.d/schema.sql

  vault:
    image: vault:1.13
    ports:
      - "8200:8200"
    environment:
      - VAULT_DEV_ROOT_TOKEN_ID=root
      - VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200
    cap_add:
      - IPC_LOCK

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

volumes:
  postgres_data:
```

### Production Stack

```yaml
version: '3.8'

services:
  api:
    image: sky-genesis/api:latest
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=${DATABASE_URL}
      - VAULT_ADDR=${VAULT_ADDR}
      - REDIS_URL=${REDIS_URL}
      - JWT_SECRET=${JWT_SECRET}
    depends_on:
      - postgres
      - redis
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  frontend:
    image: sky-genesis/frontend:latest
    ports:
      - "3000:3000"
    environment:
      - API_URL=${API_URL}
    depends_on:
      - api
    restart: unless-stopped

  postgres:
    image: postgres:15
    environment:
      - POSTGRES_DB=api_service
      - POSTGRES_USER=${DB_USER}
      - POSTGRES_PASSWORD=${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ssl_certs:/etc/ssl/certs
    depends_on:
      - api
      - frontend
    restart: unless-stopped

volumes:
  postgres_data:
  ssl_certs:
```

## 🔒 Security Features

### Container Security

- **Non-root users** for all containers
- **Minimal base images** (Alpine Linux, Debian slim)
- **No secrets in images** (environment variables only)
- **Read-only filesystems** where possible

### Image Scanning

```bash
# Scan images for vulnerabilities
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasecurity/trivy image sky-genesis/api:latest

# Scan for secrets
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  zricethezav/gitleaks:latest docker --image sky-genesis/api:latest
```

### Security Headers

```nginx
# nginx.conf security headers
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

## 📊 Monitoring & Logging

### Health Checks

```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 40s
```

### Logging Configuration

```yaml
logging:
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"
```

### Metrics Export

```dockerfile
# Add Prometheus metrics endpoint
EXPOSE 9090
COPY --from=builder /api/target/release/api /usr/local/bin/api
COPY --from=prometheus-exporter /usr/local/bin/node_exporter /usr/local/bin/node_exporter

# Run both services
CMD ["sh", "-c", "node_exporter & api"]
```

## 🚀 Deployment Scripts

### Build Script

```bash
#!/bin/bash
# build.sh

set -e

echo "🏗️  Building Sky Genesis Docker images..."

# Build API
echo "📦 Building API image..."
docker build -f infrastructure/docker/Dockerfile.api -t sky-genesis/api:${TAG:-latest} .

# Build Frontend
echo "🎨 Building Frontend image..."
docker build -f infrastructure/docker/Dockerfile.frontend -t sky-genesis/frontend:${TAG:-latest} .

# Security scan
echo "🔍 Scanning for vulnerabilities..."
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasecurity/trivy image sky-genesis/api:${TAG:-latest}

echo "✅ Build complete!"
```

### Deploy Script

```bash
#!/bin/bash
# deploy.sh

set -e

ENVIRONMENT=${1:-development}

echo "🚀 Deploying to $ENVIRONMENT environment..."

case $ENVIRONMENT in
  development)
    docker-compose -f infrastructure/docker/docker-compose.yml up -d
    ;;
  staging)
    docker-compose -f infrastructure/docker/docker-compose.staging.yml up -d
    ;;
  production)
    docker-compose -f infrastructure/docker/docker-compose.prod.yml up -d
    ;;
  *)
    echo "❌ Unknown environment: $ENVIRONMENT"
    exit 1
    ;;
esac

echo "✅ Deployment to $ENVIRONMENT complete!"
```

## 🧪 Testing

### Container Tests

```bash
# Test API container
docker run --rm sky-genesis/api:latest curl -f http://localhost:8080/health

# Test frontend container
docker run --rm -p 3000:3000 sky-genesis/frontend:latest &
sleep 10
curl -f http://localhost:3000
```

### Integration Tests

```bash
# Run tests in containers
docker-compose -f infrastructure/docker/docker-compose.test.yml up --abort-on-container-exit

# Clean up
docker-compose -f infrastructure/docker/docker-compose.test.yml down -v
```

## 📈 Performance Optimization

### Multi-Stage Builds

```dockerfile
# Builder stage
FROM rust:1.70 AS builder
WORKDIR /api
COPY Cargo.toml Cargo.lock ./
RUN cargo build --release

# Runtime stage (much smaller)
FROM debian:12-slim
COPY --from=builder /api/target/release/api /usr/local/bin/api
```

### Layer Caching

```dockerfile
# Copy dependency files first for better caching
COPY package*.json ./
RUN npm ci --only=production

# Copy source code after dependencies
COPY . .
RUN npm run build
```

### Resource Limits

```yaml
services:
  api:
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 1G
        reservations:
          cpus: '0.5'
          memory: 512M
```

## 🔧 Troubleshooting

### Common Issues

**Port already in use:**
```bash
# Find process using port
lsof -i :8080

# Kill process
kill -9 <PID>
```

**Container won't start:**
```bash
# Check logs
docker logs <container_name>

# Debug interactively
docker run -it --entrypoint /bin/bash sky-genesis/api:latest
```

**Database connection failed:**
```bash
# Check if database is running
docker ps | grep postgres

# Check database logs
docker logs postgres
```

### Debug Commands

```bash
# View all running containers
docker ps

# View container logs
docker logs -f sky-genesis-api

# Execute commands in running container
docker exec -it sky-genesis-api /bin/bash

# View container resource usage
docker stats

# Clean up unused resources
docker system prune -a
```

## 📚 Additional Resources

- [Docker Best Practices](https://docs.docker.com/develop/dev-best-practices/)
- [Docker Security](https://docs.docker.com/engine/security/)
- [Multi-stage Builds](https://docs.docker.com/develop/dev-best-practices/)
- [Docker Compose](https://docs.docker.com/compose/)

---

**🐳 Containerized • 🔒 Secure • 🚀 Optimized**