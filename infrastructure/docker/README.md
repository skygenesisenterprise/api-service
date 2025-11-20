# API Service Docker Configuration

This directory contains Docker configuration files for running the Enterprise API Service in production.

## Files Overview

- `Dockerfile.api` - Backend API service (Node.js + Express + TypeScript)
- `Dockerfile.web` - Frontend web application (Next.js)
- `Dockerfile` - Multi-stage build for the complete application
- `docker-compose.yml` - Production-ready orchestration with database
- `docker-compose.dev.yml` - Development environment with hot reload
- `.dockerignore` - Files to exclude from Docker builds

## Quick Start

### Production
```bash
docker-compose up -d
```

### Development
```bash
docker-compose -f docker-compose.dev.yml up
```

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Frontend  │    │   API Backend   │    │   PostgreSQL    │
│   (Next.js)     │◄──►│   (Express)     │◄──►│   Database      │
│   Port: 3000    │    │   Port: 8080    │    │   Port: 5432    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Environment Variables

Create a `.env` file with the following variables:

```env
# Database
DATABASE_URL=postgresql://user:password@postgres:5432/api_service
DB_HOST=postgres
DB_PORT=5432
DB_NAME=api_service
DB_USER=api_user
DB_PASSWORD=secure_password

# API
NODE_ENV=production
PORT=8080
JWT_SECRET=your_jwt_secret_here
API_KEY_SECRET=your_api_key_secret_here

# Frontend
NEXT_PUBLIC_API_URL=http://localhost:8080
NEXTAUTH_SECRET=your_nextauth_secret_here
NEXTAUTH_URL=http://localhost:3000
```

## Development

For development with hot reload:

```bash
# Start with development configuration
docker-compose -f docker-compose.dev.yml up --build

# View logs
docker-compose -f docker-compose.dev.yml logs -f

# Stop services
docker-compose -f docker-compose.dev.yml down
```

## Production

For production deployment:

```bash
# Build and start production services
docker-compose up -d --build

# Scale services if needed
docker-compose up -d --scale api=2 --scale web=2

# View logs
docker-compose logs -f

# Update services
docker-compose pull && docker-compose up -d
```

## Health Checks

Both services include health checks:

- API: `GET /health`
- Web: `GET /api/health`

## Security Features

- Non-root user execution
- Minimal base images
- Security scanning with Docker Scout
- Secrets management through environment variables
- CORS configuration
- Rate limiting ready