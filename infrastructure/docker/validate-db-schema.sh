#!/bin/bash
set -e

# ================================
# Sky Genesis API - Database Schema Validation
# ================================

echo "Validating database schema..."

# Check if DATABASE_URL is set
if [ -z "$DATABASE_URL" ]; then
    echo "ERROR: DATABASE_URL environment variable is not set"
    exit 1
fi

# Extract database connection details from DATABASE_URL
# Format: postgresql://user:pass@host:port/db
DB_USER=$(echo "$DATABASE_URL" | sed -n 's|.*://\([^:]*\):.*|\1|p')
DB_PASS=$(echo "$DATABASE_URL" | sed -n 's|.*://[^:]*:\([^@]*\)@.*|\1|p')
DB_HOST=$(echo "$DATABASE_URL" | sed -n 's|.*@\([^:]*\):\([^/]*\)/.*|\1|p')
DB_PORT=$(echo "$DATABASE_URL" | sed -n 's|.*@\([^:]*\):\([^/]*\)/.*|\2|p')
DB_NAME=$(echo "$DATABASE_URL" | sed -n 's|.*/\([^?]*\).*|\1|p')

echo "Database connection: $DB_HOST:$DB_PORT/$DB_NAME"

# Wait for database to be ready
echo "Checking database connectivity..."
max_attempts=30
attempt=1
while [ $attempt -le $max_attempts ]; do
    if pg_isready -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" 2>/dev/null; then
        echo "Database is ready!"
        break
    fi

    echo "Attempt $attempt/$max_attempts: Database not ready yet, waiting..."
    sleep 2
    ((attempt++))

    if [ $attempt -gt $max_attempts ]; then
        echo "ERROR: Database failed to become ready after $max_attempts attempts"
        exit 1
    fi
done

# Check if api_service schema exists
echo "Checking if api_service schema exists..."
SCHEMA_EXISTS=$(PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT 1 FROM information_schema.schemata WHERE schema_name = 'api_service';" 2>/dev/null | tr -d ' ')

if [ "$SCHEMA_EXISTS" = "1" ]; then
    echo "✓ api_service schema exists"

    # Check for essential tables
    echo "Checking for essential tables..."
    TABLES=("users" "api_keys" "organizations" "audit_logs")
    MISSING_TABLES=()

    for table in "${TABLES[@]}"; do
        TABLE_EXISTS=$(PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT 1 FROM information_schema.tables WHERE table_schema = 'api_service' AND table_name = '$table';" 2>/dev/null | tr -d ' ')
        if [ "$TABLE_EXISTS" = "1" ]; then
            echo "✓ Table $table exists"
        else
            echo "✗ Table $table missing"
            MISSING_TABLES+=("$table")
        fi
    done

    if [ ${#MISSING_TABLES[@]} -gt 0 ]; then
        echo "WARNING: Some essential tables are missing: ${MISSING_TABLES[*]}"
        echo "The API may not function correctly without these tables."
    else
        echo "✓ All essential tables present"
    fi
else
    echo "ERROR: api_service schema does not exist"
    echo "Please ensure the database schema has been properly initialized."
    echo "You can initialize it by mounting the schema file and running the init script."
    exit 1
fi

# Check database connectivity with a simple query
echo "Testing database connectivity with a simple query..."
TEST_RESULT=$(PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT version();" 2>/dev/null | head -1)
if [ -n "$TEST_RESULT" ]; then
    echo "✓ Database connectivity test passed"
else
    echo "ERROR: Database connectivity test failed"
    exit 1
fi

echo "Database schema validation completed successfully!"