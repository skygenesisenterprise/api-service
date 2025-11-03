# Sky Genesis Enterprise - Integration Guide

This guide explains how the Next.js frontend, Rust backend, and PostgreSQL database are integrated in the Sky Genesis Enterprise API service.

## Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Next.js App   │    │   Rust Backend  │    │  PostgreSQL DB  │
│   (Frontend)    │◄──►│   (API Server)  │◄──►│   (Database)    │
│   Port: 3000    │    │   Port: 8080    │    │   Port: 5432    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Components

### 1. Next.js Frontend (`/app/`)
- **Framework**: Next.js 14 with App Router
- **UI Components**: Shadcn/ui components
- **Authentication**: Custom JWT auth service with NextAuth compatibility
- **API Routes**: Proxy to Rust backend with fallback to mock data

### 2. Rust Backend (`/api/`)
- **Framework**: Warp web framework
- **Authentication**: JWT with OAuth2/OIDC support (Keycloak integration)
- **Database**: Multi-database support via Diesel ORM
- **Features**: Comprehensive API with security, monitoring, and audit logging

### 3. PostgreSQL Database (`/prisma/`)
- **ORM**: Prisma for schema management
- **Schema**: Role-based access control with users, projects, organizations
- **Features**: Audit logging, device management, messaging system

## Integration Services

### Backend Service (`/lib/services/backend-service.ts`)
Handles communication between Next.js and Rust backend:

```typescript
import { backendService } from '@/lib/services/backend-service'

// Get users from backend
const users = await backendService.getUsers({ page: 1, limit: 20 })

// Create project via backend
const project = await backendService.createProject({
  name: 'New Project',
  description: 'Project description'
})
```

### Authentication Service (`/lib/services/backend-auth-service.ts`)
Manages JWT authentication with backend:

```typescript
import { authService } from '@/lib/services/backend-auth-service'

// Login
const result = await authService.login({
  email: 'user@example.com',
  password: 'password'
})

// Check permissions
if (authService.hasPermission('users:read')) {
  // User can read users
}
```

## API Routes Integration

### Users API (`/app/api/users/route.ts`)
- **GET**: Fetch users from backend or fallback to mock data
- **POST**: Create users via backend or fallback to mock data

### Projects API (`/app/api/projects/route.ts`)
- **GET**: Fetch projects from backend or fallback to mock data
- **POST**: Create projects via backend or fallback to mock data

### Authentication API (`/app/api/auth/route.ts`)
- **POST**: Login with email/password
- **DELETE**: Logout current user

## Configuration

### Environment Variables (`.env`)
```env
# Database
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/sky_genesis_dev?schema=api_service

# Rust Backend
RUST_API_URL=http://localhost:8080
RUST_API_BASE_URL=http://localhost:8080/api/v1

# Next.js
NEXTAUTH_URL=http://localhost:3000
NEXTAUTH_SECRET=dev-secret-key

# Development
NODE_ENV=development
SGE_DEV_MODE=true
```

## Setup Instructions

### 1. Prerequisites
- Node.js 18+
- Rust 1.70+
- PostgreSQL 14+
- pnpm (recommended) or npm

### 2. Database Setup
```bash
# Create database
createdb sky_genesis_dev

# Install dependencies
pnpm install

# Generate Prisma client
npx prisma generate

# Push schema to database
npx prisma db push

# Seed database with test data
npx prisma db seed
```

### 3. Start Services

#### Start Rust Backend
```bash
cd api
cargo run
```
The backend will start on `http://localhost:8080`

#### Start Next.js Frontend
```bash
cd app
pnpm dev
```
The frontend will start on `http://localhost:3000`

### 4. Test Integration
```bash
# Run the integration test script
./test-integration.sh
```

## API Endpoints

### Rust Backend Endpoints
- `GET /hello` - Health check
- `GET /api-docs/openapi.json` - OpenAPI specification
- `GET /swagger-ui/` - API documentation
- `POST /api/v1/auth/login` - Login
- `GET /api/v1/auth/me` - Get current user
- `GET /api/v1/users` - List users
- `POST /api/v1/users` - Create user
- `GET /api/v1/projects` - List projects
- `POST /api/v1/projects` - Create project

### Next.js API Routes
- `GET /api/auth/me` - Get current user (proxies to backend)
- `POST /api/auth` - Login (proxies to backend)
- `DELETE /api/auth` - Logout (proxies to backend)
- `GET /api/users` - Get users (proxies to backend with fallback)
- `POST /api/users` - Create user (proxies to backend with fallback)
- `GET /api/projects` - Get projects (proxies to backend with fallback)
- `POST /api/projects` - Create project (proxies to backend with fallback)

## Authentication Flow

### 1. Login Process
```
Frontend → Next.js API → Rust Backend → Database
    ↓         ↓              ↓           ↓
  Form     /api/auth    /api/v1/auth   Users table
```

### 2. Token Management
- JWT tokens stored in localStorage
- Automatic token refresh
- Backend service configured with auth token

### 3. Permission System
- Role-based access control
- Permission checks in frontend
- Backend enforces permissions

## Development Features

### Fallback Mechanism
When the Rust backend is unavailable, the Next.js API routes automatically fall back to mock data, ensuring the frontend remains functional for development.

### Error Handling
- Graceful degradation when backend is down
- Comprehensive error logging
- User-friendly error messages

### Security
- JWT-based authentication
- Permission-based authorization
- CORS configuration
- Input validation

## Monitoring and Debugging

### Logs
- Rust backend: Console output
- Next.js: Console and file logs
- Database: Prisma query logs

### Health Checks
- Backend: `GET /hello`
- Frontend: Automatic connectivity tests
- Database: Connection validation

### Development Tools
- Prisma Studio: `npx prisma studio`
- API Documentation: `http://localhost:8080/swagger-ui/`
- Integration Tests: `./test-integration.sh`

## Production Considerations

### Security
- Use HTTPS in production
- Configure proper CORS origins
- Use environment-specific secrets
- Enable audit logging

### Performance
- Implement caching strategies
- Use connection pooling
- Optimize database queries
- Enable compression

### Scalability
- Load balancing for backend
- Database replication
- CDN for static assets
- Horizontal scaling

## Troubleshooting

### Common Issues

#### Backend Not Responding
```bash
# Check if backend is running
curl http://localhost:8080/hello

# Check backend logs
cd api && cargo run
```

#### Database Connection Issues
```bash
# Test database connection
psql -h localhost -U postgres -d sky_genesis_dev

# Reset database
npx prisma db push --force-reset
```

#### Frontend Build Errors
```bash
# Clear Next.js cache
rm -rf .next

# Reinstall dependencies
pnpm install --force
```

### Getting Help
- Check the integration test script output
- Review service logs
- Consult API documentation
- Check environment configuration

## Next Steps

1. **Database Setup**: Configure PostgreSQL and run migrations
2. **Service Testing**: Use the integration test script
3. **Feature Development**: Extend API endpoints and frontend components
4. **Production Deployment**: Configure production environment
5. **Monitoring**: Set up logging and monitoring tools

This integration provides a robust foundation for the Sky Genesis Enterprise API service with seamless communication between all components.