#!/bin/bash
set -e

# ================================
# Sky Genesis API - Database Initialization
# ================================

echo "========================================"
echo "Sky Genesis Database Initialization"
echo "========================================"

# Wait for PostgreSQL to be ready
echo "Waiting for PostgreSQL to be ready..."
until pg_isready -U postgres -d api_service; do
    echo "PostgreSQL is not ready - waiting..."
    sleep 2
done

echo "PostgreSQL is ready!"

# Check if schema already exists
echo "Checking if API schema exists..."
SCHEMA_EXISTS=$(psql -U postgres -d api_service -t -c "SELECT 1 FROM information_schema.schemata WHERE schema_name = 'api_service';" 2>/dev/null | tr -d ' ' || echo "0")

if [ "$SCHEMA_EXISTS" = "1" ]; then
    echo "✓ API schema already exists"
else
    echo "Creating API schema..."
    
    # Create schema
    psql -U postgres -d api_service -c "CREATE SCHEMA IF NOT EXISTS api_service;" || true
    
    # Set search path
    psql -U postgres -d api_service -c "SET search_path TO api_service;" || true
    
    echo "✓ Schema created successfully"
fi

# Check if organizations table exists
echo "Checking if tables exist..."
TABLES_EXIST=$(psql -U postgres -d api_service -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'api_service';" 2>/dev/null | tr -d ' ' || echo "0")

if [ "$TABLES_EXIST" -gt 0 ]; then
    echo "✓ Tables already exist"
else
    echo "Creating tables from schema file..."
    
    # Apply schema if it exists
    if [ -f /docker-entrypoint-initdb.d/01-schema.sql ]; then
        PGPASSWORD=password psql -U postgres -d api_service -f /docker-entrypoint-initdb.d/01-schema.sql || true
        echo "✓ Schema applied from file"
    else
        echo "⚠ Schema file not found, creating minimal schema..."
        
        # Create minimal schema for API keys
        psql -U postgres -d api_service -c "
        CREATE TABLE IF NOT EXISTS api_service.organizations (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name VARCHAR(255) NOT NULL UNIQUE,
            country_code CHAR(2),
            created_at TIMESTAMP DEFAULT now(),
            updated_at TIMESTAMP DEFAULT now()
        );
        
        CREATE TABLE IF NOT EXISTS api_service.api_keys (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id UUID REFERENCES api_service.organizations(id) ON DELETE CASCADE,
            key_value TEXT UNIQUE NOT NULL,
            key_type VARCHAR(20) NOT NULL CHECK (key_type IN ('client', 'server', 'database')),
            label VARCHAR(255),
            permissions TEXT[],
            quota_limit INTEGER DEFAULT 100000,
            usage_count INTEGER DEFAULT 0,
            status VARCHAR(50) DEFAULT 'active',
            public_key TEXT,
            private_key TEXT,
            certificate_type VARCHAR(50),
            certificate_fingerprint VARCHAR(128),
            private_key_path TEXT,
            db_type VARCHAR(50),
            db_host VARCHAR(255),
            db_port INTEGER,
            db_name VARCHAR(255),
            db_username VARCHAR(255),
            db_password_encrypted TEXT,
            server_endpoint TEXT,
            server_region VARCHAR(50),
            client_origin VARCHAR(255),
            client_scopes TEXT[],
            expires_at TIMESTAMP,
            last_used_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT now(),
            updated_at TIMESTAMP DEFAULT now()
        );
        " || true
        
        echo "✓ Minimal schema created"
    fi
fi

# Create default organization if it doesn't exist
echo "Checking for default organization..."
ORG_EXISTS=$(psql -U postgres -d api_service -t -c "SELECT COUNT(*) FROM api_service.organizations WHERE name = 'Default Organization';" 2>/dev/null | tr -d ' ' || echo "0")

if [ "$ORG_EXISTS" -eq 0 ]; then
    echo "Creating default organization..."
    psql -U postgres -d api_service -c "
    INSERT INTO api_service.organizations (name, country_code) 
    VALUES ('Default Organization', 'US');
    " || true
    echo "✓ Default organization created"
else
    echo "✓ Default organization already exists"
fi

echo ""
echo "========================================"
echo "Database initialization completed!"
echo "========================================"