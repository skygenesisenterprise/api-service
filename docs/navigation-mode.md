# Navigation Mode Configuration

Ce système permet de contrôler la navigation dans l'application selon le mode (développement ou production).

## Configuration

### Variable d'environnement

Ajoutez cette variable à votre fichier `.env`:

```bash
# Mode de navigation
# development: Navigation libre sans authentification
# production: Authentification requise pour les routes protégées
NEXT_PUBLIC_NAVIGATION_MODE=development
```

### Modes disponibles

#### Development Mode (`development`)
- **Navigation libre**: Toutes les pages sont accessibles sans authentification
- **Idéal pour**: Développement, tests, démonstrations
- **Comportement**: Aucune redirection vers la page de login

#### Production Mode (`production`)
- **Navigation sécurisée**: L'authentification est requise pour les routes protégées
- **Idéal pour**: Environnement de production, environnement de staging
- **Comportement**: Redirection automatique vers `/login` pour les routes protégées

## Routes protégées

Les routes suivantes nécessitent une authentification en mode production:

- `/dashboard` - Tableau de bord
- `/projects` - Gestion des projets
- `/users` - Gestion des utilisateurs
- `/settings` - Paramètres
- `/profile` - Profil utilisateur
- `/inbox` - Boîte de réception
- `/logs` - Journaux système

## Routes publiques

Ces routes sont toujours accessibles:

- `/` - Page d'accueil
- `/login` - Page de connexion
- `/auth/forgot-password` - Mot de passe oublié
- `/auth/reset-password` - Réinitialisation du mot de passe
- `/docs/swagger` - Documentation API

## Utilisation dans le code

### Vérifier si une route nécessite une authentification

```typescript
import { requiresAuthentication } from '@/lib/navigation-config';

if (requiresAuthentication('/dashboard')) {
  // La route nécessite une authentification en mode production
}
```

### Utiliser le composant de protection

```typescript
import { ProtectedRoute } from '@/components/ProtectedRoute';

function MyProtectedPage() {
  return (
    <ProtectedRoute>
      <div>Contenu protégé</div>
    </ProtectedRoute>
  );
}
```

### Utiliser le hook personnalisé

```typescript
import { useNavigationAuth } from '@/hooks/useNavigationAuth';

function MyComponent() {
  const { canAccessRoute, isDevelopmentMode } = useNavigationAuth();
  
  if (canAccessRoute('/dashboard')) {
    // L'utilisateur peut accéder à la route
  }
}
```

## Indicateur visuel

Un indicateur en haut à droite de l'écran affiche le mode actuel:
- 🛠️ **Development Mode** (vert)
- 🔒 **Production Mode** (rouge)

## Middleware

Le middleware `middleware.ts` gère la redirection au niveau serveur pour les routes protégées en mode production.

## Bonnes pratiques

1. **Développement**: Utilisez `development` pour faciliter les tests et le développement
2. **Production**: Utilisez `production` pour sécuriser l'application
3. **Tests**: Vous pouvez tester les deux modes en changeant simplement la variable d'environnement
4. **CI/CD**: Configurez votre pipeline pour utiliser `production` en environnement de production

## Exemples de configuration

### Développement local
```bash
NEXT_PUBLIC_NAVIGATION_MODE=development
```

### Staging
```bash
NEXT_PUBLIC_NAVIGATION_MODE=production
```

### Production
```bash
NEXT_PUBLIC_NAVIGATION_MODE=production
```