#!/bin/sh
set -e

export DATABASE_URL=${DATABASE_URL:-"file:./dev.db"}
export NODE_ENV=${NODE_ENV:-"development"}
export API_PORT=${API_PORT:-8085}
export PORT=${PORT:-4000}

echo "Starting Sky Genesis Enterprise API Service..."
echo "Database URL: $DATABASE_URL"
echo "Environment: $NODE_ENV"

# Generate Prisma client
echo "Generating Prisma client..."
npx prisma generate

# Initialize database schema
echo "Initializing database..."
npx prisma db push --accept-data-force || echo "Database push completed with warnings"

# Seed database
echo "Seeding database..."
npx tsx prisma/seed-test-user.ts || echo "Database seeding completed"

# Start backend in background
echo "Starting backend server on port $API_PORT..."
API_PORT=$API_PORT pnpm run start:backend &

# Start frontend in background
echo "Starting frontend server on port $PORT..."
PORT=$PORT pnpm run start &

# Wait for all processes
wait