# Sky Genesis Enterprise API Service

A comprehensive messaging and API management platform built with Node.js, Express, TypeScript, and PostgreSQL. Includes both a REST API and a web-based admin portal for managing API keys and monitoring usage.

## 🚀 Features

- **API Key Authentication**: Secure API access with granular permissions
- **Real-time Messaging**: Full-featured messaging system with conversations, messages, reactions, and read receipts
- **Multi-Organization Support**: Isolated data and permissions per organization
- **Rate Limiting & Quotas**: Built-in API usage controls
- **Audit Logging**: Complete API access tracking
- **Admin Portal**: Web-based interface for API key management and analytics
- **TypeScript**: Full type safety throughout the application
- **RESTful API**: Clean, consistent API design

## 📁 Project Structure

```
├── api/                          # Backend API
│   ├── config/                   # Database configuration
│   ├── controllers/              # HTTP request handlers
│   ├── middlewares/              # Authentication & validation
│   ├── models/                   # TypeScript interfaces
│   ├── routes/                   # API route definitions
│   ├── services/                 # Business logic
│   ├── tests/                    # Test files
│   └── utils/                    # Utilities
├── app/                          # Next.js admin portal
│   ├── admin/                    # Admin pages
│   ├── lib/                      # API client utilities
│   └── ...                       # Next.js configuration
├── data/                         # Database schemas
├── docs/                         # Documentation
└── public/                       # Static assets
```

## 🛠️ Tech Stack

### Backend
- **Runtime**: Node.js v18+
- **Framework**: Express.js
- **Language**: TypeScript
- **Database**: PostgreSQL v12+
- **Testing**: Jest + Supertest

### Frontend (Admin Portal)
- **Framework**: Next.js 15
- **Language**: TypeScript
- **Styling**: Tailwind CSS
- **State Management**: React hooks

### Development Tools
- **Package Manager**: pnpm
- **Linting**: ESLint
- **Process Manager**: PM2
- **Container**: Docker

## 📚 Documentation

- [Getting Started](./docs/getting-started.md)
- [API Reference](./docs/api-reference.md)
- [Authentication Guide](./docs/authentication.md)
- [Database Schema](./docs/database-schema.md)
- [Deployment Guide](./docs/deployment.md)
- [Admin Portal Guide](./ADMIN_PORTAL_README.md)
- [Troubleshooting](./docs/troubleshooting.md)

## 🔧 Quick Start

### 1. Prerequisites

- Node.js v18 or later
- PostgreSQL v12 or later
- pnpm v8 or later

### 2. Installation

```bash
# Clone repository
git clone <repository-url>
cd api-service

# Install dependencies
pnpm install
```

### 3. Database Setup

```bash
# Create database
createdb api_service

# Set up environment variables
cp .env.example .env
# Edit .env with your database credentials

# Run schema
psql -U your_user -d api_service -f data/schema-pgsql.sql
```

### 4. Create Initial Data

```sql
-- Create organization
INSERT INTO api_service.organizations (name, country_code)
VALUES ('Your Company', 'US');

-- Create admin API key
INSERT INTO api_service.api_keys (organization_id, key_value, label, permissions)
VALUES (
  (SELECT id FROM api_service.organizations WHERE name = 'Your Company'),
  'sk_admin_' || encode(gen_random_bytes(32), 'hex'),
  'Admin Key',
  ARRAY['read', 'write', 'admin']
);
```

### 5. Start Services

```bash
# Start API backend
pnpm run dev:backend

# In another terminal, start admin portal
pnpm run dev:admin
```

### 6. Access the Application

- **API**: `http://localhost:3001/api/v1`
- **Admin Portal**: `http://localhost:8080`

## 🏗️ API Architecture

### Authentication Flow

```
Client Request → API Key Validation → Permission Check → Business Logic → Response
```

### Key Components

- **API Keys**: Organization-scoped authentication tokens
- **Permissions**: Granular access control (read, write, admin)
- **Quotas**: Rate limiting and usage tracking
- **Audit Logs**: Complete request tracking

### Example API Call

```bash
# Validate API key
curl -H "X-API-Key: sk_your_key" http://localhost:3001/api/v1/validate

# Create conversation
curl -X POST "http://localhost:3001/api/v1/messaging/organizations/org-123/conversations" \
  -H "X-API-Key: sk_your_key" \
  -H "Content-Type: application/json" \
  -d '{"title": "Team Chat", "type": "group", "participant_ids": ["user1", "user2"]}'
```

## 🎛️ Admin Portal

The web-based admin portal provides:

- **Dashboard**: Overview of API usage and key metrics
- **API Key Management**: Create, view, revoke, and monitor API keys
- **Analytics**: Usage patterns, performance metrics, error rates
- **Organization Management**: Administer organization settings
- **Settings**: Customize portal preferences

### Accessing the Admin Portal

1. Navigate to `http://localhost:8080`
2. Click "Access Admin Portal"
3. Enter your Organization ID and API key with admin permissions
4. Start managing your API ecosystem

## 🧪 Testing

```bash
# Run all tests
pnpm test

# Run tests in watch mode
pnpm run test:watch

# Run specific test file
npx jest api/tests/messaging.test.ts
```

## 🚀 Deployment

### Development

```bash
# Start all services
pnpm run dev
```

### Production

```bash
# Build admin portal
pnpm run build:admin

# Start production servers
pm2 start ecosystem.config.js
```

### Docker

```bash
# Build and run with Docker Compose
docker-compose up -d
```

## 🔒 Security

- API key-based authentication
- Organization data isolation
- Request rate limiting
- Comprehensive audit logging
- Input validation and sanitization
- HTTPS enforcement in production

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please read [CONTRIBUTING.md](./.github/CONTRIBUTING.md) for detailed guidelines.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: Check the [docs](./docs/) folder
- **Issues**: Create an issue on GitHub
- **Discussions**: Use GitHub Discussions for questions

---

Built with ❤️ for enterprise API management and messaging platforms.