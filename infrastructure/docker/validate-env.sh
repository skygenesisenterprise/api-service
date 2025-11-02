#!/bin/bash
set -e

# ================================
# Sky Genesis API - Environment Validation
# ================================

echo "Validating environment variables..."

# Required environment variables
REQUIRED_VARS=(
    "DATABASE_URL"
    "VAULT_ADDR"
    "VAULT_ROLE_ID"
    "VAULT_SECRET_ID"
    "JWT_SECRET"
)

# Optional but recommended environment variables
RECOMMENDED_VARS=(
    "REDIS_URL"
    "KEYCLOAK_URL"
    "APP_ENV"
)

# Check required variables
MISSING_REQUIRED=()
for var in "${REQUIRED_VARS[@]}"; do
    if [ -z "${!var}" ]; then
        MISSING_REQUIRED+=("$var")
    else
        echo "✓ $var is set"
    fi
done

# Check recommended variables
MISSING_RECOMMENDED=()
for var in "${RECOMMENDED_VARS[@]}"; do
    if [ -z "${!var}" ]; then
        MISSING_RECOMMENDED+=("$var")
    else
        echo "✓ $var is set"
    fi
done

# Report missing required variables
if [ ${#MISSING_REQUIRED[@]} -gt 0 ]; then
    echo "ERROR: Missing required environment variables:"
    for var in "${MISSING_REQUIRED[@]}"; do
        echo "  - $var"
    done
    echo "Please set these variables before starting the API."
    exit 1
fi

# Report missing recommended variables
if [ ${#MISSING_RECOMMENDED[@]} -gt 0 ]; then
    echo "WARNING: Missing recommended environment variables:"
    for var in "${MISSING_RECOMMENDED[@]}"; do
        echo "  - $var"
    done
    echo "The API may not function optimally without these variables."
fi

# Validate DATABASE_URL format
if [[ ! "$DATABASE_URL" =~ ^postgresql:// ]]; then
    echo "ERROR: DATABASE_URL must start with 'postgresql://'"
    exit 1
fi

# Validate VAULT_ADDR format
if [[ ! "$VAULT_ADDR" =~ ^https?:// ]]; then
    echo "ERROR: VAULT_ADDR must start with 'http://' or 'https://'"
    exit 1
fi

# Validate JWT_SECRET length
if [ ${#JWT_SECRET} -lt 32 ]; then
    echo "WARNING: JWT_SECRET is shorter than 32 characters. Consider using a longer secret for better security."
fi

# Validate APP_ENV
if [ -n "$APP_ENV" ]; then
    case "$APP_ENV" in
        development|staging|production)
            echo "✓ APP_ENV is set to valid value: $APP_ENV"
            ;;
        *)
            echo "WARNING: APP_ENV should be one of: development, staging, production"
            ;;
    esac
fi

# Check for development vs production settings
if [ "$APP_ENV" = "production" ]; then
    if [ "$JWT_SECRET" = "development_secret_key_change_in_production" ]; then
        echo "ERROR: JWT_SECRET is still set to the default development value in production!"
        exit 1
    fi

    if [[ "$DATABASE_URL" =~ password ]]; then
        echo "✓ DATABASE_URL appears to contain authentication"
    else
        echo "WARNING: DATABASE_URL may not contain authentication credentials"
    fi
fi

echo "Environment validation completed successfully!"