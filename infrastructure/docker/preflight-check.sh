#!/bin/bash
set -e

# ================================
# Sky Genesis API - Pre-flight Check
# ================================

echo "========================================"
echo "Sky Genesis API - Pre-flight Check"
echo "========================================"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Run environment validation
echo ""
echo "1. Validating environment variables..."
"$SCRIPT_DIR/validate-env.sh"

# Wait for dependencies
echo ""
echo "2. Waiting for dependencies..."
"$SCRIPT_DIR/wait-for-dependencies.sh"

# Validate database schema
echo ""
echo "3. Validating database schema..."
"$SCRIPT_DIR/validate-db-schema.sh"

# Optional: Test Vault connectivity
echo ""
echo "4. Testing Vault connectivity..."
if [ -n "$VAULT_ADDR" ] && [ -n "$VAULT_ROLE_ID" ] && [ -n "$VAULT_SECRET_ID" ]; then
    # Simple vault status check (requires vault CLI)
    if command -v vault &> /dev/null; then
        if vault status >/dev/null 2>&1; then
            echo "✓ Vault is accessible"
        else
            echo "WARNING: Cannot connect to Vault, but continuing..."
        fi
    else
        echo "INFO: Vault CLI not available, skipping Vault connectivity test"
    fi
else
    echo "INFO: Vault credentials not fully configured, skipping Vault test"
fi

# Optional: Test Redis connectivity
echo ""
echo "5. Testing Redis connectivity..."
if [ -n "$REDIS_URL" ]; then
    if command -v redis-cli &> /dev/null; then
        REDIS_HOST=$(echo "$REDIS_URL" | sed -n 's|.*://\([^:]*\):\([^/]*\).*|\1|p')
        REDIS_PORT=$(echo "$REDIS_URL" | sed -n 's|.*://\([^:]*\):\([^/]*\).*|\2|p')
        if [ -n "$REDIS_HOST" ] && [ -n "$REDIS_PORT" ]; then
            if redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ping >/dev/null 2>&1; then
                echo "✓ Redis is accessible"
            else
                echo "WARNING: Cannot connect to Redis, but continuing..."
            fi
        fi
    else
        echo "INFO: redis-cli not available, skipping Redis connectivity test"
    fi
else
    echo "INFO: REDIS_URL not set, skipping Redis test"
fi

echo ""
echo "========================================"
echo "Pre-flight check completed successfully!"
echo "Starting Sky Genesis API..."
echo "========================================"