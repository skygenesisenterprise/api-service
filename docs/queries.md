# Database Queries

## Overview

The queries module provides database abstraction for persistent storage operations. Currently implemented as placeholders, this module will handle all database interactions once PostgreSQL integration is complete.

## Current Implementation

The query functions are currently placeholders that simulate database operations through logging and mock responses.

## Key Queries (`key_queries.rs`)

### `log_key_creation(id: &str) -> Result<(), Box<dyn std::error::Error>>`
Logs the creation of a new API key.

**Parameters:**
- `id`: The unique identifier of the created key

**Current Implementation:**
```rust
println!("Logged key creation: {}", id);
Ok(())
```

**Future Implementation:**
- Insert record into `api_keys` table
- Log audit trail
- Update key metadata

### `revoke_key(id: &str) -> Result<(), Box<dyn std::error::Error>>`
Marks an API key as revoked.

**Parameters:**
- `id`: The key identifier to revoke

**Current Implementation:**
```rust
println!("Revoked key: {}", id);
Ok(())
```

**Future Implementation:**
- Update `revoked` flag in database
- Log revocation timestamp
- Notify dependent systems

### `get_key(id: &str) -> Result<ApiKey, Box<dyn std::error::Error>>`
Retrieves a specific API key by ID.

**Parameters:**
- `id`: The key identifier

**Current Implementation:**
```rust
Err("Not implemented".into())
```

**Future Implementation:**
- Query `api_keys` table by ID
- Return ApiKey struct if found
- Handle not found cases

### `list_keys_by_tenant(tenant: &str) -> Result<Vec<ApiKey>, Box<dyn std::error::Error>>`
Lists all API keys for a specific tenant.

**Parameters:**
- `tenant`: The tenant identifier

**Current Implementation:**
```rust
Ok(vec![])
```

**Future Implementation:**
- Query `api_keys` table with tenant filter
- Return array of ApiKey structs
- Support pagination and sorting

## Planned Database Schema

### API Keys Table
```sql
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_type VARCHAR(50) NOT NULL,
    tenant VARCHAR(255) NOT NULL,
    ttl BIGINT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    permissions TEXT[],
    vault_path VARCHAR(255) NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMP WITH TIME ZONE
);

-- Indexes
CREATE INDEX idx_api_keys_tenant ON api_keys(tenant);
CREATE INDEX idx_api_keys_key_type ON api_keys(key_type);
CREATE INDEX idx_api_keys_created_at ON api_keys(created_at);
```

### Users Table
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    roles TEXT[],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    enabled BOOLEAN DEFAULT TRUE,
    keycloak_id VARCHAR(255) UNIQUE
);

-- Indexes
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_enabled ON users(enabled);
```

### Audit Log Table
```sql
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    table_name VARCHAR(50) NOT NULL,
    record_id UUID NOT NULL,
    action VARCHAR(50) NOT NULL,
    old_values JSONB,
    new_values JSONB,
    user_id UUID,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_audit_log_table_record ON audit_log(table_name, record_id);
CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp);
```

## Query Patterns

### Connection Management
- Connection pooling with `bb8` or `deadpool`
- Transaction management for data consistency
- Connection retry logic

### Query Building
- Use `sqlx` or `diesel` for type-safe queries
- Prepared statements for security
- Parameterized queries to prevent SQL injection

### Error Handling
- Database-specific error types
- Connection error recovery
- Constraint violation handling

## Migration Strategy

### Current State
- No database dependency
- In-memory operations
- Console logging for audit

### Migration Steps
1. Add database crate to Cargo.toml
2. Create database schema
3. Implement connection pooling
4. Replace placeholder functions with real queries
5. Add database tests
6. Implement migrations

## Performance Considerations

### Indexing Strategy
- Primary keys on all tables
- Foreign key indexes
- Query-specific indexes for common filters

### Query Optimization
- Use EXPLAIN ANALYZE for query planning
- Implement pagination for list operations
- Cache frequently accessed data

### Connection Pooling
- Configure appropriate pool size
- Handle connection timeouts
- Monitor connection health

## Security

### Data Protection
- Encrypt sensitive data at rest
- Use parameterized queries
- Implement row-level security

### Audit Trail
- Log all data modifications
- Track user actions
- Maintain data integrity

## Testing

### Unit Tests
- Mock database connections
- Test query logic
- Validate parameter handling

### Integration Tests
- Test against real database
- Verify schema constraints
- Test concurrent operations

## Future Enhancements

- Implement full CRUD operations
- Add database migrations
- Support multiple database backends
- Implement caching layer
- Add database monitoring
- Support for database sharding