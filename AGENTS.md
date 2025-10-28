# Agent Guidelines for Sky Genesis Enterprise API Service

This document provides essential information for AI coding agents working on this repository.

## Build/Lint/Test Commands

### Development
- **Start backend**: `pnpm run dev:backend` or `cargo run` (Rust API on port 8080)
- **Start frontend**: `pnpm run dev:frontend` or `next dev --turbopack`
- **Start both**: `pnpm run dev`

### Production
- **Build**: `next build --turbopack`
- **Start**: `next start`

### Testing
- **Run all tests**: `npm test` or `jest`
- **Run tests in watch mode**: `npm run test:watch` or `jest --watch`
- **Run single test file**: `jest api/tests/filename.test.ts`

### Code Quality
- **Lint**: `npm run lint` or `eslint`
- **Type check**: Run `tsc --noEmit` (TypeScript compiler)

## Code Style Guidelines

### TypeScript/JavaScript
- **Strict mode**: Enabled - all TypeScript code must pass strict type checking
- **Imports**: Use ES6 imports, prefer named imports over default
- **Types**: Define interfaces for all data structures, avoid `any` type
- **Error handling**: Use try/catch blocks, throw specific Error instances
- **Async/await**: Preferred over Promises for asynchronous code

### Naming Conventions
- **Files**: PascalCase for components (`UserProfile.tsx`), camelCase for utilities (`authService.ts`)
- **Variables**: camelCase (`userId`, `apiKeyData`)
- **Functions**: camelCase (`createConversation`, `validateApiKey`)
- **Classes**: PascalCase (`ApiKeyService`, `MessagingService`)
- **Interfaces**: PascalCase with 'I' prefix (`IUser`, `IApiKey`)
- **Constants**: UPPER_SNAKE_CASE (`JWT_SECRET`, `DB_PORT`)

### Database
- **Schema**: All tables in `api_service` schema
- **Naming**: snake_case for columns (`user_id`, `created_at`)
- **Primary keys**: UUID type using `gen_random_uuid()`
- **Timestamps**: `created_at` and `updated_at` columns
- **Foreign keys**: Named references to other tables

### API Design
- **Authentication**: API key-based authentication via headers
- **Versioning**: `/api/v1/` prefix for versioned endpoints
- **HTTP methods**: RESTful conventions (GET/POST/PUT/DELETE)
- **Response format**: JSON with consistent structure
- **Error handling**: Structured error responses with status codes

### Project Structure
```
api/
├── config/          # Database and configuration
├── controllers/     # Request handlers
├── middlewares/     # Authentication and validation
├── models/         # TypeScript interfaces
├── routes/         # API route definitions
├── services/       # Business logic
├── tests/          # Test files
└── utils/          # Utilities

app/                # Next.js frontend
data/               # Database schemas
```

### Security Practices
- **Input validation**: Validate all user inputs
- **SQL injection**: Use parameterized queries
- **Authentication**: Required for all API endpoints
- **Authorization**: Check permissions for sensitive operations
- **Secrets**: Never commit API keys or secrets
- **CORS**: Configure appropriate CORS policies

### Testing
- **Framework**: Jest with supertest for API testing
- **Coverage**: Aim for high test coverage
- **Mocking**: Mock external dependencies
- **Database**: Use test database for integration tests

### Git Workflow
- **Branch naming**: `feature/feature-name`, `fix/bug-name`, `docs/update-docs`
- **Commits**: Clear, descriptive commit messages
- **PRs**: Include description and link to issues

## Environment Variables

Required environment variables:
- `DB_HOST`: Database host
- `DB_PORT`: Database port
- `DB_NAME`: Database name
- `DB_USER`: Database user
- `DB_PASSWORD`: Database password
- `JWT_SECRET`: JWT secret (for legacy auth)

## Database Setup

1. Create PostgreSQL database
2. Run schema from `data/schema-pgsql.sql`
3. Set up environment variables
4. Run migrations if any

## API Key Authentication

All API requests require authentication via API keys:
- Header: `X-API-Key: your-key`
- Header: `Authorization: Bearer your-key`
- Query: `?api_key=your-key`

API keys are linked to organizations and have permissions.

## Common Patterns

### Service Layer
```typescript
export class ExampleService {
  static async exampleMethod(param: string): Promise<Result> {
    // Business logic here
  }
}
```

### Controller Pattern
```typescript
export const exampleController = async (req: Request, res: Response) => {
  try {
    const result = await ExampleService.exampleMethod(req.params.id);
    return res.status(200).json({ data: result });
  } catch (error) {
    return res.status(500).json({ error: 'Internal server error' });
  }
};
```

### Middleware Usage
```typescript
router.use(authenticateApiKey);
router.get('/protected', requirePermission('read'), controller);
```

## Performance Considerations

- Use database indexes for frequently queried columns
- Implement pagination for list endpoints
- Cache frequently accessed data
- Monitor query performance
- Use connection pooling for database

## Deployment

- Use environment-specific configurations
- Set up proper logging
- Configure monitoring and alerts
- Use HTTPS in production
- Implement rate limiting