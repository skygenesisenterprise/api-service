# Système de Gestion des Utilisateurs Unifiés

Ce document décrit l'implémentation complète d'un système d'authentification unique (SSO) avec gestion des permissions basée sur les rôles (RBAC) pour l'API Sky Genesis Enterprise.

## 🏗️ Architecture

### Base de Données
Le système utilise une structure de base de données unifiée avec les tables principales :
- `UnifiedAccount` - Compte utilisateur principal
- `AccountIdentifier` - Identifiants multiples (email, username, téléphone, OAuth)
- `OrganizationMembership` - Appartenance aux organisations avec rôles
- `Session` - Sessions utilisateur avec gestion des devices

### Services
- `UnifiedAuthService` - Authentification et validation des tokens
- `UnifiedUserService` - Gestion CRUD des utilisateurs
- `UnifiedAccountService` - Gestion des comptes et organisations

### Contrôleurs
- `UnifiedAuthController` - Endpoints d'authentification
- `UnifiedUserController` - Endpoints de gestion des utilisateurs
- `AccessController` - Vérification des accès aux services/applications

## 🔐 Authentification

### Connexion Unifiée
```typescript
POST /api/v1/auth/login
{
  "identifier": "user@example.com", // email, username, ou téléphone
  "password": "password123",
  "deviceInfo": {
    "userAgent": "Mozilla/5.0...",
    "ip": "192.168.1.1"
  }
}
```

**Réponse :**
```json
{
  "success": true,
  "data": {
    "user": {
      "id": "user_123",
      "globalId": "USR_1641234567890_ABC123",
      "primaryEmail": "user@example.com",
      "username": "johndoe"
    },
    "token": "eyJhbGciOiJIUzI1NiIs...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIs...",
    "session": {
      "id": "session_456",
      "expiresAt": "2025-01-22T10:30:00Z"
    }
  }
}
```

### Rafraîchissement du Token
```typescript
POST /api/v1/auth/refresh
{
  "refreshToken": "eyJhbGciOiJIUzI1NiIs..."
}
```

### Validation des Permissions
```typescript
GET /api/v1/auth/permissions
Authorization: Bearer <token>

// Réponse
{
  "success": true,
  "data": {
    "applications": ["admin-console", "logs"],
    "services": ["logs", "dashboard", "api-gateway"],
    "roles": ["admin", "member"],
    "permissions": [
      "logs:*",
      "dashboard:read",
      "user:read"
    ],
    "organizations": ["org_123", "org_456"]
  }
}
```

## 🛡️ Gestion des Accès

### Vérification d'Accès à un Service
```typescript
GET /api/v1/access/services/logs
Authorization: Bearer <token>

// Réponse
{
  "success": true,
  "data": {
    "serviceId": "logs",
    "serviceName": "Log Management",
    "hasAccess": true,
    "permissions": ["logs:read", "logs:write", "logs:export"]
  }
}
```

### Vérification d'Accès à une Application
```typescript
GET /api/v1/access/applications/admin-console
Authorization: Bearer <token>

// Réponse
{
  "success": true,
  "data": {
    "applicationId": "admin-console",
    "applicationName": "Admin Console",
    "hasAccess": true,
    "role": "admin",
    "permissions": ["app:admin-console:*"]
  }
}
```

### Lister les Services Accessibles
```typescript
GET /api/v1/access/services
Authorization: Bearer <token>

// Réponse
{
  "success": true,
  "data": {
    "services": [
      {
        "id": "logs",
        "name": "Log Management",
        "description": "View and analyze system logs",
        "permissions": ["logs:read", "logs:write"]
      },
      {
        "id": "dashboard",
        "name": "Dashboard",
        "description": "Main dashboard and analytics",
        "permissions": ["dashboard:read"]
      }
    ],
    "total": 2
  }
}
```

## 👥 Gestion des Utilisateurs

### Création d'Utilisateur
```typescript
POST /api/v1/users
Authorization: Bearer <admin_token>
{
  "primaryEmail": "newuser@example.com",
  "username": "newuser",
  "password": "securePassword123",
  "organizationId": "org_123",
  "role": "member",
  "permissions": ["logs:read"],
  "profile": {
    "firstName": "John",
    "lastName": "Doe"
  }
}
```

### Mise à Jour d'Utilisateur
```typescript
PUT /api/v1/users/user_123
Authorization: Bearer <token>
{
  "profile": {
    "firstName": "John Updated"
  },
  "preferences": {
    "theme": "dark",
    "language": "fr"
  }
}
```

### Gestion des Organisations
```typescript
// Ajouter à une organisation
POST /api/v1/users/user_123/organizations
{
  "organizationId": "org_456",
  "role": "admin",
  "permissions": ["organization:manage", "user:write"]
}

// Mettre à jour le rôle
PUT /api/v1/users/user_123/organizations/org_456
{
  "role": "owner",
  "permissions": ["organization:*"]
}

// Retirer d'une organisation
DELETE /api/v1/users/user_123/organizations/org_456
```

## 🔧 Middlewares d'Authentification

### Utilisation dans les Routes
```typescript
import { authenticateToken, requirePermission, requireServiceAccess } from '../middlewares/auth';

// Route nécessitant une authentification simple
router.get('/profile', authenticateToken, (req, res) => {
  const user = (req as any).user;
  res.json({ user });
});

// Route nécessitant une permission spécifique
router.get('/admin', 
  authenticateToken, 
  requirePermission('admin:access'), 
  (req, res) => {
    res.json({ message: 'Admin access granted' });
  }
);

// Route nécessitant l'accès à un service spécifique
router.get('/logs', 
  authenticateToken, 
  requireServiceAccess('logs', 'read'), 
  (req, res) => {
    res.json({ message: 'Logs access granted' });
  }
);
```

### Types de Permissions
```typescript
// Format des permissions
"resource:action:scope"

// Exemples
"logs:read"           // Lire les logs
"logs:write"           // Écrire les logs
"logs:*"               // Tous les droits sur les logs
"service:logs:access"  // Accès au service logs
"app:admin-console:*" // Tous les droits sur l'admin console
"organization:manage"  // Gérer l'organisation
"user:delete"          // Supprimer des utilisateurs
```

### Hiérarchie des Rôles
```typescript
// Owner - Accès complet à l'organisation
{
  "permissions": [
    "organization:*",
    "app:*",
    "service:*",
    "user:*",
    "logs:*",
    "billing:*"
  ]
}

// Admin - Gestion sauf facturation
{
  "permissions": [
    "organization:read",
    "organization:write",
    "app:*",
    "service:*",
    "user:read",
    "user:write",
    "logs:*"
  ]
}

// Member - Accès de base
{
  "permissions": [
    "organization:read",
    "app:read",
    "service:read",
    "logs:read"
  ]
}

// Viewer - Lecture seule
{
  "permissions": [
    "organization:read",
    "app:read",
    "service:read",
    "logs:read"
  ]
}
```

## 🚀 Intégration Client

### Exemple avec JavaScript/TypeScript
```typescript
class SkyGenesisAuth {
  private baseURL: string;
  private token: string | null = null;
  private refreshToken: string | null = null;

  constructor(baseURL: string) {
    this.baseURL = baseURL;
  }

  async login(identifier: string, password: string) {
    const response = await fetch(`${this.baseURL}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier, password })
    });

    const result = await response.json();
    
    if (result.success) {
      this.token = result.data.token;
      this.refreshToken = result.data.refreshToken;
      localStorage.setItem('token', this.token);
      localStorage.setItem('refreshToken', this.refreshToken);
    }
    
    return result;
  }

  async checkServiceAccess(serviceId: string): Promise<boolean> {
    if (!this.token) throw new Error('Not authenticated');
    
    const response = await fetch(
      `${this.baseURL}/api/v1/access/services/${serviceId}`,
      {
        headers: { 'Authorization': `Bearer ${this.token}` }
      }
    );
    
    const result = await response.json();
    return result.success && result.data.hasAccess;
  }

  async getAccessibleServices() {
    if (!this.token) throw new Error('Not authenticated');
    
    const response = await fetch(
      `${this.baseURL}/api/v1/access/services`,
      {
        headers: { 'Authorization': `Bearer ${this.token}` }
      }
    );
    
    return await response.json();
  }

  // Auto-rafraîchissement du token
  private async refreshAccessToken() {
    if (!this.refreshToken) return false;
    
    try {
      const response = await fetch(`${this.baseURL}/api/v1/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken: this.refreshToken })
      });
      
      const result = await response.json();
      
      if (result.success) {
        this.token = result.data.token;
        this.refreshToken = result.data.refreshToken;
        localStorage.setItem('token', this.token);
        localStorage.setItem('refreshToken', this.refreshToken);
        return true;
      }
    } catch (error) {
      console.error('Token refresh failed:', error);
    }
    
    return false;
  }
}

// Utilisation
const auth = new SkyGenesisAuth('https://api.skygenesis.com');

// Connexion
await auth.login('user@example.com', 'password');

// Vérifier l'accès aux logs
const canAccessLogs = await auth.checkServiceAccess('logs');
if (canAccessLogs) {
  // Rediriger vers la page des logs
}

// Obtenir tous les services accessibles
const services = await auth.getAccessibleServices();
console.log('Services accessibles:', services.data.services);
```

## 📊 Monitoring et Sécurité

### Événements d'Audit
Le système génère automatiquement des logs d'audit pour :
- Connexions et déconnexions
- Changements de permissions
- Création/suppression d'utilisateurs
- Accès refusés
- Modifications de rôles

### Sécurité
- **Tokens JWT** avec expiration configurable
- **Refresh tokens** avec rotation automatique
- **Rate limiting** par utilisateur
- **Device management** avec suivi des sessions
- **Password hashing** avec bcrypt
- **Input validation** et sanitization

## 🔧 Configuration

### Variables d'Environnement
```bash
# JWT Secrets
JWT_SECRET=votre-secret-key-tres-securise
REFRESH_TOKEN_SECRET=votre-refresh-secret

# Database
DATABASE_URL=postgresql://user:password@localhost:5432/skygenesis

# Email (pour réinitialisation mots de passe)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=noreply@skygenesis.com
SMTP_PASS=votre-mot-de-passe-app

# Session
SESSION_EXPIRY=7d
TOKEN_EXPIRY=15m
```

Ce système complet permet une gestion centralisée des utilisateurs avec authentification unique et des permissions granulaires pour tous les services et applications de l'écosystème Sky Genesis Enterprise.