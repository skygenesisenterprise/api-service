#!/bin/bash

echo "🧪 Test de validation des identifiants de connexion"
echo "=================================================="

echo ""
echo "1. Test avec identifiants valides:"
echo "   Email: admin@skygenesisenterprise.com"
echo "   Password: admin123"

response=$(curl -s -X POST http://localhost:8080/api/v1/accounts/authenticate \
  -H "Content-Type: application/json" \
  -d '{"identifier": "admin@skygenesisenterprise.com", "password": "admin123"}')

if echo "$response" | grep -q "Authentication successful"; then
    echo "   ✅ Succès: Identifiants valides acceptés"
    email=$(echo "$response" | grep -o '"email":"[^"]*"' | cut -d'"' -f4)
    echo "   📧 Email: $email"
else
    echo "   ❌ Échec: Identifiants valides rejetés"
fi

echo ""
echo "2. Test avec mot de passe incorrect:"
echo "   Email: admin@skygenesisenterprise.com"
echo "   Password: wrongpassword"

response=$(curl -s -X POST http://localhost:8080/api/v1/accounts/authenticate \
  -H "Content-Type: application/json" \
  -d '{"identifier": "admin@skygenesisenterprise.com", "password": "wrongpassword"}')

if echo "$response" | grep -q "Invalid credentials"; then
    echo "   ✅ Succès: Mot de passe incorrect rejeté"
else
    echo "   ❌ Échec: Mot de passe incorrect accepté"
fi

echo ""
echo "3. Test avec email inexistant:"
echo "   Email: nonexistent@email.com"
echo "   Password: admin123"

response=$(curl -s -X POST http://localhost:8080/api/v1/accounts/authenticate \
  -H "Content-Type: application/json" \
  -d '{"identifier": "nonexistent@email.com", "password": "admin123"}')

if echo "$response" | grep -q "Invalid credentials"; then
    echo "   ✅ Succès: Email inexistant rejeté"
else
    echo "   ❌ Échec: Email inexistant accepté"
fi

echo ""
echo "4. Test avec champs manquants:"

response=$(curl -s -X POST http://localhost:8080/api/v1/accounts/authenticate \
  -H "Content-Type: application/json" \
  -d '{"identifier": "", "password": ""}')

if echo "$response" | grep -q "required"; then
    echo "   ✅ Succès: Champs manquants détectés"
else
    echo "   ❌ Échec: Champs manquants non détectés"
fi

echo ""
echo "=================================================="
echo "🎯 Test terminé !"
echo ""
echo "📝 Résumé:"
echo "   - Backend API: http://localhost:8080/api/v1/accounts/authenticate"
echo "   - Frontend Login: http://localhost:3000/login"
echo "   - Identifiants de démo: admin@skygenesisenterprise.com / admin123"