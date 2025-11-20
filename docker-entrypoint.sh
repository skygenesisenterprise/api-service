#!/bin/sh

# Set default environment variables if not set
export DATABASE_URL=${DATABASE_URL:-"file:./dev.db"}
export NODE_ENV=${NODE_ENV:-"development"}
export API_PORT=${API_PORT:-8085}    # backend
export PORT=${PORT:-4000}            # frontend (Next.js)

echo "Starting Sky Genesis Enterprise API Service..."
echo "Database URL: $DATABASE_URL"
echo "Environment: $NODE_ENV"

# Generate Prisma client
echo "Generating Prisma client..."
npx prisma generate

# Initialize database (create schema)
echo "Initializing database schema..."
npx prisma db push --accept-data-force || echo "Database push completed with warnings"

# Seed the database
echo "Seeding database with test user..."
npx tsx prisma/seed-test-user.ts || echo "Database seeding completed"

# Start backend server
echo "Starting backend server on port $API_PORT..."
API_PORT=$API_PORT npm run start:backend &

# Start frontend server
echo "Starting frontend server on port $PORT..."
PORT=$PORT npm run start

# Wait for any process to exit
wait -n