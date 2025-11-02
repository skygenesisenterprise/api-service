#!/bin/bash
set -e

# Wait for PostgreSQL to be ready
until pg_isready -U postgres; do
  echo "Waiting for PostgreSQL to be ready..."
  sleep 2
done

# Create Keycloak database and user if they don't exist
psql -v ON_ERROR_STOP=1 --username postgres --dbname postgres <<-EOSQL
  -- Create Keycloak database
  SELECT 'CREATE DATABASE keycloak OWNER keycloak'
  WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'keycloak')\gexec

  -- Create Keycloak user with password
  DO \$\$
  BEGIN
     IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'keycloak') THEN
        CREATE ROLE keycloak LOGIN PASSWORD 'keycloak';
     END IF;
  END
  \$\$;

  -- Grant permissions
  GRANT ALL PRIVILEGES ON DATABASE keycloak TO keycloak;
EOSQL

echo "Keycloak database initialized successfully"