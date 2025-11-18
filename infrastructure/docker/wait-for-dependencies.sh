#!/bin/bash
set -e

# ================================
# Sky Genesis API - Dependency Wait Script
# ================================

echo "Waiting for dependencies to be ready..."

# Function to wait for a service
wait_for_service() {
    local host=$1
    local port=$2
    local service_name=$3
    local max_attempts=30
    local attempt=1

    echo "Waiting for $service_name at $host:$port..."

    while [ $attempt -le $max_attempts ]; do
        if nc -z "$host" "$port" 2>/dev/null; then
            echo "$service_name is ready!"
            return 0
        fi

        echo "Attempt $attempt/$max_attempts: $service_name not ready yet, waiting..."
        sleep 2
        ((attempt++))
    done

    echo "ERROR: $service_name failed to become ready after $max_attempts attempts"
    return 1
}

# Wait for PostgreSQL
if [ -n "$DATABASE_URL" ]; then
    # Extract host and port from DATABASE_URL
    # DATABASE_URL format: postgresql://user:pass@host:port/db
    DB_HOST=$(echo "$DATABASE_URL" | sed -n 's|.*@\([^:]*\):\([^/]*\)/.*|\1|p')
    DB_PORT=$(echo "$DATABASE_URL" | sed -n 's|.*@\([^:]*\):\([^/]*\)/.*|\2|p')

    if [ -n "$DB_HOST" ] && [ -n "$DB_PORT" ]; then
        wait_for_service "$DB_HOST" "$DB_PORT" "PostgreSQL"
    else
        echo "WARNING: Could not parse DATABASE_URL for PostgreSQL check"
    fi
else
    echo "WARNING: DATABASE_URL not set, skipping PostgreSQL check"
fi

# Wait for Vault (optional)
if [ -n "$VAULT_ADDR" ]; then
    # Extract host and port from VAULT_ADDR
    VAULT_HOST=$(echo "$VAULT_ADDR" | sed -n 's|.*://\([^:]*\):\([^/]*\).*|\1|p')
    VAULT_PORT=$(echo "$VAULT_ADDR" | sed -n 's|.*://\([^:]*\):\([^/]*\).*|\2|p')
    
    if [ -n "$VAULT_HOST" ] && [ -n "$VAULT_PORT" ]; then
        wait_for_service "$VAULT_HOST" "$VAULT_PORT" "Vault" || echo "WARNING: Vault not ready, but continuing..."
    else
        echo "WARNING: Could not parse VAULT_ADDR for Vault check"
    fi
else
    echo "INFO: VAULT_ADDR not set, skipping Vault check"
fi

# Wait for Redis
if [ -n "$REDIS_URL" ]; then
    # Extract host and port from REDIS_URL
    REDIS_HOST=$(echo "$REDIS_URL" | sed -n 's|.*://\([^:]*\):\([^/]*\).*|\1|p')
    REDIS_PORT=$(echo "$REDIS_URL" | sed -n 's|.*://\([^:]*\):\([^/]*\).*|\2|p')

    if [ -n "$REDIS_HOST" ] && [ -n "$REDIS_PORT" ]; then
        wait_for_service "$REDIS_HOST" "$REDIS_PORT" "Redis"
    else
        echo "WARNING: Could not parse REDIS_URL for Redis check"
    fi
else
    echo "WARNING: REDIS_URL not set, skipping Redis check"
fi

# Wait for Keycloak (optional)
if [ -n "$KEYCLOAK_URL" ]; then
    KEYCLOAK_HOST=$(echo "$KEYCLOAK_URL" | sed -n 's|.*://\([^:]*\):\([^/]*\).*|\1|p')
    KEYCLOAK_PORT=$(echo "$KEYCLOAK_URL" | sed -n 's|.*://\([^:]*\):\([^/]*\).*|\2|p')

    if [ -n "$KEYCLOAK_HOST" ] && [ -n "$KEYCLOAK_PORT" ]; then
        wait_for_service "$KEYCLOAK_HOST" "$KEYCLOAK_PORT" "Keycloak" || echo "WARNING: Keycloak not ready, but continuing..."
    fi
fi

echo "All dependencies are ready!"