# Utilities

## Overview

Utility modules provide common functionality used across the application. They are located in the `api/src/utils/` directory and contain helper functions for various operations.

## Key Utilities (`key_utils.rs`)

### `generate_id() -> String`
Generates a unique identifier using UUID v4.

**Returns:** UUID string (e.g., "550e8400-e29b-41d4-a716-446655440000")

**Usage:**
```rust
let id = generate_id(); // "550e8400-e29b-41d4-a716-446655440000"
```

### `generate_key() -> String`
Generates a random key value.

**Note:** Currently uses UUID v4; in production, should use cryptographically secure random generation.

**Returns:** Random key string

### `hash_key(key: &str) -> String`
Hashes a key for storage.

**Note:** Currently a placeholder implementation; should use proper cryptographic hashing in production.

**Parameters:**
- `key`: The key to hash

**Returns:** Hashed key string (prefixed with "hashed_")

### `calculate_ttl(ttl: u64) -> u64`
Calculates and validates TTL value.

**Parameters:**
- `ttl`: TTL in seconds

**Returns:** Validated TTL value

## Token Utilities (`tokens.rs`)

### JWT Token Management

#### `generate_jwt(user: &User) -> Result<String, Error>`
Generates a JWT token for a user.

**Parameters:**
- `user`: Reference to User struct

**Process:**
1. Sets expiration to 1 hour from now
2. Creates claims with user information
3. Signs token with HS256 algorithm
4. Returns encoded JWT string

**Claims Include:**
- `sub`: User ID
- `email`: User email
- `roles`: User roles
- `exp`: Expiration timestamp
- `iat`: Issued at timestamp

#### `validate_jwt(token: &str) -> Result<Claims, Error>`
Validates and decodes a JWT token.

**Parameters:**
- `token`: JWT token string

**Process:**
1. Decodes token using secret key
2. Validates signature and expiration
3. Returns claims if valid

**Returns:** `Claims` struct with token data

### Claims Structure
```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub email: String,
    pub roles: Vec<String>,
    pub exp: usize,
    pub iat: usize,
}
```

## Utility Dependencies

### External Crates
- `uuid`: For unique identifier generation
- `jsonwebtoken`: For JWT token handling
- `chrono`: For timestamp operations

### Environment Variables
- `JWT_SECRET`: Secret key for JWT signing/validation

## Security Considerations

### Key Generation
- Current implementation uses UUID which is not cryptographically secure
- Production should use `rand` crate with secure random number generation

### Key Hashing
- Current implementation is a placeholder
- Production should use proper hashing algorithms (e.g., bcrypt, Argon2)

### JWT Security
- Uses HS256 algorithm (symmetric signing)
- Tokens expire after 1 hour
- Secret key must be kept secure and rotated regularly

## Error Handling

Utilities return `Result<T, E>` types:
- `generate_jwt`: Returns `jsonwebtoken::errors::Error`
- `validate_jwt`: Returns `jsonwebtoken::errors::Error`
- Other functions: Return `Box<dyn std::error::Error>`

## Testing

Utility functions include unit tests for:
- ID generation uniqueness
- JWT token round-trip (generate → validate)
- Token expiration handling
- Invalid token rejection

## Performance Notes

- UUID generation is fast and suitable for high-throughput scenarios
- JWT operations are lightweight and don't require external calls
- Functions are stateless and thread-safe

## Future Enhancements

- Implement secure key generation using `rand` crate
- Add key encryption/decryption utilities
- Implement token refresh mechanisms
- Add token blacklisting capabilities
- Support for different JWT algorithms (RS256, etc.)
- Add utility functions for password hashing
- Implement secure random string generation
- Add validation utilities for input sanitization