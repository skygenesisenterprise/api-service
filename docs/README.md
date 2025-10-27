# Sky Genesis Enterprise API Documentation

Cette documentation couvre l'architecture complète de l'API Sky Genesis Enterprise, un service web en Rust pour la gestion sécurisée de clés et l'authentification.

## Architecture Générale

L'API suit une architecture modulaire en couches avec séparation claire des responsabilités :

```
┌─────────────────────────────────────────────────────────────┐
│                    HTTP Layer (Warp)                        │
│  ┌─────────────────┐    ┌─────────────────┐                 │
│  │   Routes        │    │   Middlewares   │                 │
│  │ • /auth/*       │    │ • JWT Auth      │                 │
│  │ • /api/keys/*   │    │ • Validation    │                 │
│  └─────────────────┘    └─────────────────┘                 │
└─────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────┐
│                   Business Layer                            │
│  ┌─────────────────┐    ┌─────────────────┐                 │
│  │  Controllers    │    │   Services      │                 │
│  │ • Auth Ctrl     │    │ • AuthService   │                 │
│  │ • Key Ctrl      │    │ • KeyService    │                 │
│  └─────────────────┘    └─────────────────┘                 │
└─────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────┐
│                   Integration Layer                         │
│  ┌─────────────────┐    ┌─────────────────┐                 │
│  │  Core Clients   │    │   Data Access   │                 │
│  │ • VaultClient   │    │ • Queries       │                 │
│  │ • KeycloakClient│    │ • Models        │                 │
│  └─────────────────┘    └─────────────────┘                 │
└─────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────┐
│                   External Services                          │
│  • HashiCorp Vault    • Keycloak    • PostgreSQL (planned)  │
└─────────────────────────────────────────────────────────────┘
```

## Structure de la Documentation

### 📋 Vue d'Ensemble
- **[API Overview](api-overview.md)** - Architecture globale, technologies et fonctionnalités clés
- **[API Endpoints](api-endpoints.md)** - Référence complète des endpoints avec exemples
- **[Data Models](data-models.md)** - Structures de données et règles de validation

### 🏗️ Architecture Technique
- **[Main Entry Point](main.md)** - Initialisation de l'application et flux de démarrage
- **[Routes](routes.md)** - Définition des routes API avec filtres Warp
- **[Controllers](controllers.md)** - Gestionnaires de requêtes HTTP et formatage des réponses
- **[Services](services.md)** - Logique métier et intégrations externes
- **[Core Integrations](core.md)** - Clients Vault et Keycloak avec gestion des connexions
- **[Middlewares](middlewares.md)** - Authentification JWT et traitement des requêtes
- **[Utilities](utils.md)** - Fonctions utilitaires (tokens, clés, hachage)

### 🔧 Composants Planifiés
- **[Configuration](config.md)** - Gestion centralisée de la configuration (à implémenter)
- **[Database Queries](queries.md)** - Couche d'abstraction base de données (actuellement placeholder)

## Flux de Données

### Authentification Utilisateur
```
Client Request → JWT Middleware → Auth Controller → Auth Service → Keycloak Client
                                                                      ↓
                                                            Token Generation → JWT Response
```

### Gestion des Clés API
```
Client Request → JWT Middleware → Key Controller → Key Service → Vault Client
                                                                    ↓
                                                          Key Rotation → Database Log
```

### Points d'Intégration Externes
- **Vault** : Stockage sécurisé des secrets et rotation automatique des clés
- **Keycloak** : Gestion des utilisateurs et authentification OAuth2
- **PostgreSQL** (planifié) : Persistance des données d'audit et métadonnées

## Patterns Architecturaux

### Injection de Dépendances
- Utilisation d'`Arc<T>` pour le partage thread-safe des services
- Injection constructeur pour faciliter les tests
- Séparation claire entre logique métier et infrastructure

### Gestion d'Erreurs
- Types d'erreur spécifiques par couche
- Propagation via `Result<T, Box<dyn std::error::Error>>`
- Gestion centralisée des rejets HTTP

### Programmation Asynchrone
- Runtime Tokio pour les opérations I/O
- `async/await` pour la lisibilité du code
- Gestion des timeouts et reconnexions

### Sécurité
- Authentification multi-niveaux (JWT + App Token)
- Validation stricte des entrées
- Audit logging des opérations sensibles
- Chiffrement des secrets via Vault

## Technologies et Dépendances

### Stack Technique
- **Langage** : Rust 1.70+ avec édition 2021
- **Framework Web** : Warp (async, type-safe)
- **Authentification** : JWT (jsonwebtoken) + Keycloak OAuth2
- **Secrets** : HashiCorp Vault avec AppRole
- **Base de données** : PostgreSQL (planifié)
- **Async Runtime** : Tokio
- **Sérialisation** : Serde (JSON)
- **Logs** : env_logger (configuration future)

### Dépendances Clés
```toml
[dependencies]
warp = "0.3"           # Framework web
tokio = { version = "1", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
jsonwebtoken = "8.0"   # JWT handling
reqwest = "0.11"       # HTTP client
uuid = "1.0"           # ID generation
chrono = "0.4"         # Date/time handling
dotenv = "0.15"        # Environment variables
```

## État d'Implémentation

### ✅ Implémenté
- Architecture modulaire complète
- Authentification JWT + Keycloak
- Gestion des clés API avec Vault
- Routes REST complètes
- Gestion d'erreurs structurée
- Tests unitaires de base

### 🚧 En Développement
- Intégration PostgreSQL complète
- Configuration centralisée
- Métriques et monitoring
- Cache et optimisation performance

### 📋 Planifié
- Migration système
- Interface d'administration
- Support multi-tenant avancé
- API versioning
- Documentation OpenAPI

## Structure des Modules

```
api/src/
├── main.rs              # 🚀 Point d'entrée et orchestration
├── config/              # ⚙️ Configuration (placeholder)
├── controllers/         # 🎯 Gestion requêtes HTTP
├── core/                # 🔗 Clients externes (Vault/Keycloak)
├── middlewares/         # 🛡️ Authentification et validation
├── models/              # 📊 Structures de données
├── queries/             # 💾 Accès base de données (placeholder)
├── routes/              # 🛣️ Définition des endpoints
├── services/            # 🏢 Logique métier
├── tests/               # ✅ Tests unitaires
└── utils/               # 🔧 Utilitaires (tokens, clés)
```

## Principes de Conception

### Séparation des Responsabilités
- **Routes** : Définition des endpoints uniquement
- **Controllers** : Parsing/validation des requêtes
- **Services** : Logique métier pure
- **Core** : Communication avec services externes

### Programmation Fonctionnelle
- Fonctions pures où possible
- Immuabilité des données
- Gestion d'erreurs explicite
- Composition plutôt qu'héritage

### Sécurité First
- Validation en entrée systématique
- Authentification obligatoire
- Audit logging complet
- Secrets jamais en dur

---

*Pour des exemples d'utilisation pratiques, consultez [API Endpoints](api-endpoints.md). Pour le développement local, voir [API Overview](api-overview.md).*