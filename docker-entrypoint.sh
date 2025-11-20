#!/bin/sh

# Wait for database to be ready (if using external database)
# echo "Waiting for database..."
# while ! nc -z $DB_HOST $DB_PORT; do
#   sleep 0.1
# done
# echo "Database is ready!"

# Generate Prisma client
echo "Generating Prisma client..."
npx prisma generate

# Push database schema
echo "Pushing database schema..."
npx prisma db push --accept-data-loss

# Seed the database
echo "Seeding database with test user..."
npx tsx prisma/seed-test-user.ts

# Start the backend server
echo "Starting backend server..."
npm run start:backend &

# Start the frontend server
echo "Starting frontend server..."
npm run start