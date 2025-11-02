#!/bin/bash
set -e

# Wait for PostgreSQL to be ready
until pg_isready -U postgres -d api_service; do
  echo "Waiting for PostgreSQL api_service database to be ready..."
  sleep 2
done

echo "Checking if API schema is already initialized..."

# Check if the schema exists
SCHEMA_EXISTS=$(psql -U postgres -d api_service -t -c "SELECT 1 FROM information_schema.schemata WHERE schema_name = 'api_service';" | tr -d ' ')

if [ "$SCHEMA_EXISTS" = "1" ]; then
    echo "API schema already exists, skipping initialization"
else
    echo "Initializing API schema..."
    # The schema should be automatically loaded by the volume mount
    # But let's verify it was applied correctly
    sleep 5

    # Check again
    SCHEMA_EXISTS=$(psql -U postgres -d api_service -t -c "SELECT 1 FROM information_schema.schemata WHERE schema_name = 'api_service';" | tr -d ' ')

    if [ "$SCHEMA_EXISTS" = "1" ]; then
        echo "API schema initialized successfully"
    else
        echo "ERROR: API schema was not initialized properly"
        exit 1
    fi
fi

echo "API database initialization completed"