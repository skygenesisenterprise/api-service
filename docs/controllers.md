# Controllers

## Overview

Controllers handle HTTP requests and responses, acting as the interface between the web framework (Warp) and the business logic services. They are defined in the `api/src/controllers/` directory.

## Key Controller (`key_controller.rs`)

Handles API key management endpoints.

### `create_key`
```rust
pub async fn create_key(
    key_service: Arc<KeyService>,
    key_type: String,
    tenant: String,
    ttl: u64,
) -> Result<impl Reply, warp::Rejection>
```

**Purpose:** Creates a new API key.

**Parameters:**
- `key_service`: Shared KeyService instance
- `key_type`: String representation of key type ("client", "server", "database")
- `tenant`: Tenant identifier
- `ttl`: Time-to-live in seconds

**Process:**
1. Validates and converts key_type string to KeyType enum
2. Calls KeyService::create_key()
3. Returns JSON response or appropriate error

**Error Handling:**
- `InvalidKeyType`: For invalid key_type values
- `VaultError`: For service-level errors

**Response:** JSON representation of created ApiKey

### `revoke_key`
```rust
pub async fn revoke_key(
    key_service: Arc<KeyService>,
    id: String,
) -> Result<impl Reply, warp::Rejection>
```

**Purpose:** Revokes an API key.

**Parameters:**
- `key_service`: Shared KeyService instance
- `id`: Key identifier to revoke

**Process:**
1. Calls KeyService::revoke_key()
2. Returns success message

**Response:**
```json
{"message": "Key revoked"}
```

### `get_key`
```rust
pub async fn get_key(
    key_service: Arc<KeyService>,
    id: String,
) -> Result<impl Reply, warp::Rejection>
```

**Purpose:** Retrieves a specific API key.

**Parameters:**
- `key_service`: Shared KeyService instance
- `id`: Key identifier

**Response:** JSON representation of ApiKey

### `list_keys`
```rust
pub async fn list_keys(
    key_service: Arc<KeyService>,
    tenant: String,
) -> Result<impl Reply, warp::Rejection>
```

**Purpose:** Lists all API keys for a tenant.

**Parameters:**
- `key_service`: Shared KeyService instance
- `tenant`: Tenant identifier

**Response:** JSON array of ApiKey objects

## Auth Controller (`auth_controller.rs`)

Handles authentication-related endpoints.

### `login`
```rust
pub async fn login(
    auth_service: Arc<AuthService>,
    req: LoginRequest,
    app_token: String,
) -> Result<impl Reply, warp::Rejection>
```

**Purpose:** Authenticates a user.

**Parameters:**
- `auth_service`: Shared AuthService instance
- `req`: LoginRequest with email/password
- `app_token`: Application token from header

**Process:**
1. Calls AuthService::login()
2. Returns authentication response

**Response:** JSON LoginResponse with tokens and user data

### `register`
```rust
pub async fn register(
    auth_service: Arc<AuthService>,
    user: User,
    password: String,
) -> Result<impl Reply, warp::Rejection>
```

**Purpose:** Registers a new user.

**Parameters:**
- `auth_service`: Shared AuthService instance
- `user`: User data
- `password`: User password

**Process:**
1. Calls AuthService::register()
2. Returns success response

### `recover_password`
```rust
pub async fn recover_password(
    auth_service: Arc<AuthService>,
    email: String,
) -> Result<impl Reply, warp::Rejection>
```

**Purpose:** Initiates password recovery.

**Parameters:**
- `auth_service`: Shared AuthService instance
- `email`: User email

**Process:**
1. Calls AuthService::recover_password()
2. Returns success response

### `get_me`
```rust
pub async fn get_me(
    auth_service: Arc<AuthService>,
    token: String,
) -> Result<impl Reply, warp::Rejection>
```

**Purpose:** Returns current user information.

**Parameters:**
- `auth_service`: Shared AuthService instance
- `token`: JWT token (extracted from auth middleware)

**Process:**
1. Calls AuthService::get_me()
2. Returns user data

**Response:** JSON User object

## Controller Patterns

### Dependency Injection
All controllers receive service instances via Arc<T> for thread-safe sharing.

### Error Handling
Controllers use Warp's rejection system:
- Service errors are converted to Warp rejections
- Custom error types implement `warp::reject::Reject`
- HTTP status codes are mapped appropriately

### Response Formatting
- Success responses use `warp::reply::json()`
- Error responses are handled by rejection system
- Consistent JSON structure across endpoints

### Async/Await
All controller functions are async and use `.await` for service calls.

## Validation

### Input Validation
- Key types are validated against enum values
- Required fields are checked
- Data types are validated (UUIDs, emails, etc.)

### Authentication Validation
- JWT tokens are validated by middleware before reaching controllers
- App tokens are validated by services

## Security

### Authorization
- Protected endpoints require valid JWT tokens
- User permissions are checked at service level
- Tenant isolation is enforced

### Data Sanitization
- User inputs are validated before processing
- SQL injection prevention through parameterized queries (planned)
- XSS prevention through proper JSON handling

## Testing

Controllers include unit tests for:
- Successful operations
- Error conditions
- Input validation
- Authentication requirements

## Future Enhancements

- Request/response logging
- Rate limiting integration
- Request tracing
- Input sanitization middleware
- Response compression
- API versioning support