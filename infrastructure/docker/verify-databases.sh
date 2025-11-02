#!/bin/bash
set -e

echo "=== Database Verification Script ==="
echo "Verifying all databases are properly initialized..."
echo

# Function to check database connectivity and schema
check_database() {
    local db_name=$1
    local db_user=$2
    local expected_schema=$3

    echo "Checking database: $db_name"

    # Check if database exists
    if ! pg_isready -U postgres -d "$db_name" >/dev/null 2>&1; then
        echo "❌ Database $db_name is not accessible"
        return 1
    fi

    # Check if expected schema exists (if specified)
    if [ -n "$expected_schema" ]; then
        local schema_exists
        schema_exists=$(psql -U postgres -d "$db_name" -t -c "SELECT 1 FROM information_schema.schemata WHERE schema_name = '$expected_schema';" | tr -d ' ')

        if [ "$schema_exists" != "1" ]; then
            echo "❌ Schema $expected_schema does not exist in database $db_name"
            return 1
        fi
    fi

    # Check if we can connect with the service user
    if [ -n "$db_user" ] && [ "$db_user" != "postgres" ]; then
        if ! psql -U "$db_user" -d "$db_name" -c "SELECT 1;" >/dev/null 2>&1; then
            echo "❌ Cannot connect to $db_name as user $db_user"
            return 1
        fi
    fi

    echo "✅ Database $db_name is ready"
    return 0
}

# Wait for PostgreSQL to be fully ready
echo "Waiting for PostgreSQL to be ready..."
until pg_isready -U postgres; do
    echo "PostgreSQL is not ready yet..."
    sleep 2
done

echo "PostgreSQL is ready. Checking databases..."
echo

# Check api_service database
if ! check_database "api_service" "postgres" "api_service"; then
    echo "❌ API database check failed"
    exit 1
fi

# Check keycloak database
if ! check_database "keycloak" "keycloak" ""; then
    echo "❌ Keycloak database check failed"
    exit 1
fi

echo
echo "=== All Databases Verified Successfully ==="
echo "✅ api_service database: Ready with api_service schema"
echo "✅ keycloak database: Ready for Keycloak"
echo
echo "You can now start the application services."