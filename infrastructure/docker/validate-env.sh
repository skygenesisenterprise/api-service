#!/bin/bash
set -e

# ================================
# Sky Genesis API - Environment Validation
# ================================

echo "Validating environment variables..."

# Required environment variables for our simplified setup
REQUIRED_VARS=(
    "DATABASE_URL"
    "API_KEY_ENCRYPTION_KEY"
)

# Optional environment variables
OPTIONAL_VARS=(
    "RUST_LOG"
    "APP_ENV"
    "PORT"
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

# Check optional variables
for var in "${OPTIONAL_VARS[@]}"; do
    if [ -z "${!var}" ]; then
        echo "⚠ $var is not set (using default)"
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

# Validate DATABASE_URL format
if [[ ! "$DATABASE_URL" =~ ^postgresql:// ]]; then
    echo "ERROR: DATABASE_URL must start with 'postgresql://'"
    exit 1
fi

# Validate API_KEY_ENCRYPTION_KEY length
if [ ${#API_KEY_ENCRYPTION_KEY} -lt 16 ]; then
    echo "WARNING: API_KEY_ENCRYPTION_KEY is shorter than 16 characters."
fi

# Set defaults for optional variables
export RUST_LOG=${RUST_LOG:-"info"}
export APP_ENV=${APP_ENV:-"development"}
export PORT=${PORT:-"8080"}

echo "Environment validation completed successfully!"
echo "Configuration:"
echo "  - Database: ${DATABASE_URL%%:*}://***:***@${DATABASE_URL##*@}"
echo "  - Log Level: $RUST_LOG"
echo "  - Environment: $APP_ENV"
echo "  - Port: $PORT"