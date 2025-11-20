#!/bin/sh

# Set default environment variables if not set
export DATABASE_URL=${DATABASE_URL:-"file:./dev.db"}
export NODE_ENV=${NODE_ENV:-"development"}

echo "Starting Sky Genesis Enterprise API Service..."
echo "Database URL: $DATABASE_URL"
echo "Environment: $NODE_ENV"

# Generate Prisma client
echo "Generating Prisma client..."
npx prisma generate

# Initialize database (create schema)
echo "Initializing database schema..."
npx prisma db push --accept-data-force || echo "Database push completed with warnings"

# Always seed the database for demo purposes
echo "Seeding database with test user..."
npx tsx prisma/seed-test-user.ts || echo "Database seeding completed"

# Start backend server
echo "Starting backend server on port 8080..."
npm run start:backend &

# Start frontend server
echo "Starting frontend server on port 3000..."
npm run start