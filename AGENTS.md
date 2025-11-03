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
- **Commits**: Clear, descriptive commit messages following Conventional Commits
- **PRs**: Include description and link to issues

## Commit Message Conventions

This project follows the [Conventional Commits](https://www.conventionalcommits.org/) specification. All commit messages must follow this format:

### Format
```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

### Types
- `feat`: New feature or enhancement
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code formatting, missing semicolons, etc. (no functional changes)
- `refactor`: Code refactoring that doesn't change functionality
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `chore`: Maintenance tasks, dependency updates, build process changes
- `ci`: CI/CD configuration changes
- `build`: Build system or dependency changes

### Examples

#### Good commit messages
```bash
feat(auth): add API key authentication middleware
fix(database): resolve connection pool timeout issue
docs(readme): update installation instructions
refactor(services): extract common validation logic
test(api): add integration tests for user endpoints
chore(deps): update prisma to v6.18.0
```

#### Commit with body and footer
```bash
feat(messaging): implement real-time chat functionality

Add WebSocket support for instant messaging between users.
Includes message history, typing indicators, and read receipts.

- Add WebSocket server configuration
- Implement message broadcasting
- Add client-side event handlers
- Update database schema for message status

Closes #123
```

### Guidelines
1. **Use imperative mood**: "add feature" not "added feature" or "adds feature"
2. **Keep description short**: Max 50 characters for the subject line
3. **Separate subject from body**: Use blank line between subject and body
4. **Explain what and why**: Focus on what the change does and why it's needed
5. **Reference issues**: Use `Closes #issue-number` or `Fixes #issue-number`
6. **One commit per feature**: Keep commits focused and atomic
7. **Avoid merge commits**: Use rebase to keep history clean

### Scope (optional)
Use parentheses to specify the scope of the change:
- `feat(auth):` - Authentication related changes
- `fix(database):` - Database related fixes
- `docs(api):` - API documentation changes
- `refactor(ui):` - UI component refactoring

### Breaking Changes
For breaking changes, add `!` after the type and include BREAKING CHANGE footer:
```bash
feat(api)!: remove deprecated user endpoints

BREAKING CHANGE: The /api/v1/users/legacy endpoints have been removed.
Use the new /api/v1/users endpoints instead.
```

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