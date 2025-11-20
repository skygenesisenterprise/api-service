#!/bin/sh

echo "=== Sky Genesis Health Check ==="

# Vérifier le frontend Next.js
echo "Checking frontend on port $PORT..."
if curl -f -s http://localhost:$PORT/api/health > /dev/null 2>&1; then
    echo "✅ Frontend Next.js: OK"
else
    echo "❌ Frontend Next.js: FAILED"
fi

# Vérifier le backend API
echo "Checking backend on port $API_PORT..."
if curl -f -s http://localhost:$API_PORT/health > /dev/null 2>&1; then
    echo "✅ Backend API: OK"
else
    echo "❌ Backend API: FAILED"
fi

# Vérifier la base de données
echo "Checking database..."
if [ -f "./dev.db" ]; then
    echo "✅ Database: OK"
else
    echo "❌ Database: NOT FOUND"
fi

echo "=== End Health Check ==="