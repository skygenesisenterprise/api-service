# Sky Genesis Enterprise API

Rust-based API service for the Sky Genesis Enterprise platform.

## Development

This directory contains the Rust API service. Use the provided Makefile for common development tasks.

### Prerequisites

- Rust 1.70 or later
- Docker and Docker Compose (for full development environment)
- PostgreSQL, Vault, and Redis (via Docker)

### Quick Start

1. **Setup environment:**
   ```bash
   make setup
   ```

2. **Start development environment:**
   ```bash
   make docker-up
   ```

3. **Run the API:**
   ```bash
   make dev
   ```

## Makefile Commands

### Development
- `make dev` - Run API in development mode
- `make build` - Build for release
- `make run` - Alias for dev
- `make watch` - Watch for changes and rebuild automatically

### Testing
- `make test` - Run all tests
- `make test-watch` - Run tests in watch mode
- `make test-unit` - Run unit tests only
- `make test-integration` - Run integration tests only

### Code Quality
- `make check` - Check for syntax and type errors
- `make clippy` - Run clippy linter
- `make fmt` - Format code with rustfmt
- `make fmt-check` - Check code formatting

### Documentation
- `make doc` - Generate and open documentation
- `make doc-private` - Generate docs including private items

### Docker
- `make docker-build` - Build Docker image
- `make docker-up` - Start all services
- `make docker-down` - Stop all services
- `make docker-logs` - Show container logs

### Maintenance
- `make clean` - Clean build artifacts
- `make update` - Update dependencies
- `make audit` - Audit dependencies for security issues
- `make outdated` - Check for outdated dependencies

### CI/CD
- `make ci` - Run CI pipeline (check, clippy, test)
- `make release` - Prepare for release

## Project Structure

```
api/
├── src/
│   ├── main.rs              # Application entry point
│   ├── websocket.rs         # WebSocket server implementation
│   ├── routes/              # API route definitions
│   │   ├── mod.rs
│   │   ├── websocket_routes.rs
│   │   ├── key_routes.rs
│   │   ├── auth_routes.rs
│   │   └── mail_routes.rs
│   ├── controllers/         # Request handlers
│   ├── services/            # Business logic
│   ├── middlewares/         # Authentication and validation
│   ├── models/              # Data models
│   ├── core/                # Core functionality (Vault, Keycloak)
│   ├── utils/               # Utility functions
│   ├── queries/             # Database queries
│   └── tests/               # Test files
├── Cargo.toml               # Rust dependencies
└── Makefile                 # Build automation
```

## API Endpoints

### Authentication
- `POST /api/v1/auth/login` - User authentication
- `POST /api/v1/auth/refresh` - Token refresh

### API Keys
- `POST /api/v1/keys` - Create API key
- `GET /api/v1/keys` - List API keys
- `DELETE /api/v1/keys/{id}` - Revoke API key

### WebSocket
- `GET /ws` - Public WebSocket connection
- `GET /ws/auth` - Authenticated WebSocket connection
- `GET /ws/status` - WebSocket server status

### Mail (Future)
- Mail management endpoints (design phase)

## Environment Variables

Required environment variables (see `.env.example`):

- `DATABASE_URL` - PostgreSQL connection string
- `VAULT_ADDR` - Vault server address
- `VAULT_ROLE_ID` - Vault AppRole ID
- `VAULT_SECRET_ID` - Vault AppRole secret
- `JWT_SECRET` - JWT signing secret
- `KEYCLOAK_URL` - Keycloak server URL
- `REDIS_URL` - Redis connection string

## Development Workflow

1. **Make changes** to the code
2. **Run tests:** `make test`
3. **Check code quality:** `make clippy`
4. **Format code:** `make fmt`
5. **Build and test:** `make build`

## Docker Development

For full development environment with all dependencies:

```bash
# Start all services
make docker-up

# View logs
make docker-logs

# Stop services
make docker-down
```

## Contributing

1. Follow Rust coding standards
2. Run `make ci` before submitting PRs
3. Add tests for new functionality
4. Update documentation as needed

## Troubleshooting

### Common Issues

**Cargo not found:**
- Install Rust: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`

**Port already in use:**
- Change port in `main.rs` or stop conflicting service

**Database connection failed:**
- Ensure Docker services are running: `make docker-up`

**Vault authentication failed:**
- Check Vault credentials in environment variables

### Getting Help

- Run `make help` for available commands
- Check logs: `make docker-logs`
- View API documentation: `make doc`