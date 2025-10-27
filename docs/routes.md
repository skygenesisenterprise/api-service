# Routes

## Overview

Routes define the API endpoints and their handlers using Warp's filter system. They are organized in the `api/src/routes/` directory with separate modules for different API domains.

## Route Structure

### Main Routes (`mod.rs`)
Combines all route modules into the final API router.

```rust
pub fn routes(
    vault_manager: Arc<VaultManager>,
    key_service: Arc<KeyService>,
    auth_service: Arc<AuthService>
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone
```

**Components:**
- Hello world endpoint for health checks
- Key management routes
- Authentication routes

**Route Composition:**
```rust
hello.or(key_routes).or(auth_routes)
```

## Key Routes (`key_routes.rs`)

Defines endpoints for API key management.

### Route Definitions

#### Create Key Route
```rust
let create = warp::path!("api" / "keys")
    .and(warp::post())
    .and(jwt_auth())
    .and(warp::query::<std::collections::HashMap<String, String>>())
    .and(warp::any().map(move || key_service.clone()))
    .and_then(|_claims, query, ks| async move {
        // Extract parameters and call controller
    });
```

**Filters Applied:**
- Path matching: `POST /api/keys`
- Authentication: `jwt_auth()` middleware
- Query parameters: HashMap for type, tenant, ttl
- Service injection: KeyService instance

#### Revoke Key Route
```rust
let revoke = warp::path!("api" / "keys" / String)
    .and(warp::delete())
    .and(jwt_auth())
    .and(warp::any().map(move || key_service.clone()))
    .and_then(|id, _claims, ks| async move {
        key_controller::revoke_key(ks, id).await
    });
```

**Filters Applied:**
- Path matching: `DELETE /api/keys/{id}`
- Authentication: JWT required
- Path parameter: Key ID as String

#### Get Key Route
```rust
let get = warp::path!("api" / "keys" / String)
    .and(warp::get())
    .and(jwt_auth())
    .and(warp::any().map(move || key_service.clone()))
    .and_then(|id, _claims, ks| async move {
        key_controller::get_key(ks, id).await
    });
```

#### List Keys Route
```rust
let list = warp::path!("api" / "keys")
    .and(warp::get())
    .and(jwt_auth())
    .and(warp::query::<std::collections::HashMap<String, String>>())
    .and(warp::any().map(move || key_service.clone()))
    .and_then(|_claims, query, ks| async move {
        // Extract tenant and call controller
    });
```

### Route Combination
```rust
create.or(revoke).or(get).or(list)
```

## Auth Routes (`auth_routes.rs`)

Defines endpoints for user authentication.

### Route Definitions

#### Login Route
```rust
let login = warp::path!("auth" / "login")
    .and(warp::post())
    .and(warp::header::<String>("x-app-token"))
    .and(warp::body::json())
    .and(warp::any().map(move || auth_service.clone()))
    .and_then(|app_token, req, as_| async move {
        auth_controller::login(as_, req, app_token).await
    });
```

**Filters Applied:**
- Path matching: `POST /auth/login`
- Header: `x-app-token` required
- Body: JSON LoginRequest
- Service injection: AuthService

#### Register Route
```rust
let register = warp::path!("auth" / "register")
    .and(warp::post())
    .and(warp::body::json::<(User, String)>())
    .and(warp::any().map(move || auth_service.clone()))
    .and_then(|(user, password), as_| async move {
        auth_controller::register(as_, user, password).await
    });
```

**Note:** Registration doesn't require authentication (public endpoint)

#### Recover Password Route
```rust
let recover = warp::path!("auth" / "recover")
    .and(warp::post())
    .and(warp::body::json::<serde_json::Value>())
    .and(warp::any().map(move || auth_service.clone()))
    .and_then(|body, as_| async move {
        let email = body["email"].as_str().unwrap_or("").to_string();
        auth_controller::recover_password(as_, email).await
    });
```

#### Get Me Route
```rust
let me = warp::path!("auth" / "me")
    .and(warp::get())
    .and(auth_guard())
    .and(warp::any().map(move || auth_service.clone()))
    .and_then(|claims, as_| async move {
        auth_controller::get_me(as_, "".to_string()).await
    });
```

**Filters Applied:**
- Authentication: `auth_guard()` (JWT required)

### Route Combination
```rust
login.or(register).or(recover).or(me)
```

## Route Patterns

### Filter Composition
Routes use Warp's functional composition:
- Path filters for URL matching
- Method filters for HTTP verbs
- Authentication filters for security
- Body filters for request parsing
- Service injection via `map` and `and_then`

### Parameter Extraction
- Path parameters: Extracted as tuple elements
- Query parameters: Parsed into HashMap
- Headers: Extracted using header filters
- Body: JSON deserialized into structs

### Service Injection
Services are cloned and injected using `Arc<T>` for thread safety:
```rust
.and(warp::any().map(move || service.clone()))
```

### Error Handling
Routes propagate errors through Warp's `Rejection` system, allowing centralized error handling.

## Middleware Integration

### Authentication Middleware
- `jwt_auth()`: Validates JWT tokens
- `auth_guard()`: Alternative auth mechanism

### Global Middleware
Routes can be composed with global middleware:
```rust
let routes = routes.with(logging_middleware).with(cors_middleware);
```

## Testing

Route modules include tests for:
- Endpoint accessibility
- Parameter parsing
- Authentication requirements
- Error responses

## Future Enhancements

- API versioning (e.g., `/api/v1/`)
- Rate limiting filters
- Request validation middleware
- Response compression
- OpenAPI/Swagger documentation generation
- GraphQL support
- WebSocket endpoints