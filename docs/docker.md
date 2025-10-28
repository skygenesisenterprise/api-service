# Utilisation de Docker dans l'API Sky Genesis

Ce document explique comment utiliser Docker pour développer, construire et déployer l'API Sky Genesis Enterprise.

## Table des matières

- [Introduction](#introduction)
- [Prérequis](#prérequis)
- [Configuration de développement](#configuration-de-développement)
- [Configuration de production](#configuration-de-production)
- [Commandes communes](#commandes-communes)
- [Sécurité](#sécurité)
- [Monitoring et logging](#monitoring-et-logging)
- [Dépannage](#dépannage)
- [Ressources supplémentaires](#ressources-supplémentaires)

## Introduction

L'API Sky Genesis Enterprise utilise Docker pour containeriser ses composants principaux :
- **API Backend** : Service Rust exposé sur le port 8080
- **Frontend** : Application Next.js exposée sur le port 3000
- **Base de données** : PostgreSQL pour le stockage des données
- **Cache** : Redis pour la mise en cache
- **Gestion des secrets** : Vault pour la gestion sécurisée des secrets
- **Authentification** : Keycloak pour la gestion des identités
- **Proxy inverse** : NGINX pour le routage et la sécurité

## Prérequis

Avant de commencer, assurez-vous d'avoir installé :
- Docker (version 20.10 ou supérieure)
- Docker Compose (version 2.0 ou supérieure)
- Au moins 4GB de RAM disponible
- Ports 3000, 8080, 5432, 6379, 8200 et 8081 libres

## Configuration de développement

### Démarrage rapide

Pour démarrer l'environnement de développement complet :

```bash
cd infrastructure/docker
docker-compose up -d
```

Cela lance tous les services :
- API backend sur http://localhost:8080
- Frontend sur http://localhost:3000
- Base de données PostgreSQL sur localhost:5432
- Redis sur localhost:6379
- Vault sur http://localhost:8200
- Keycloak sur http://localhost:8081

### Services inclus

Le fichier `docker-compose.yml` définit les services suivants :

#### API (Rust)
- **Image** : Construit à partir de `Dockerfile.dev`
- **Port** : 8080
- **Variables d'environnement** :
  - `DATABASE_URL` : Connexion PostgreSQL
  - `VAULT_ADDR` : Adresse Vault
  - `REDIS_URL` : Connexion Redis
  - `JWT_SECRET` : Clé secrète JWT
- **Volumes** : Montage du code source pour le développement à chaud

#### Frontend (Next.js)
- **Image** : Construit à partir de `Dockerfile.frontend.dev`
- **Port** : 3000
- **Variables d'environnement** :
  - `API_URL` : URL de l'API backend
  - `NEXT_PUBLIC_API_URL` : URL publique de l'API
- **Volumes** : Montage du code source pour le développement à chaud

#### Base de données (PostgreSQL)
- **Image** : postgres:15-alpine
- **Port** : 5432
- **Base de données** : api_service
- **Utilisateur** : postgres
- **Mot de passe** : password (à changer en production)
- **Volume** : Persistance des données
- **Initialisation** : Script SQL `schema-pgsql.sql`

#### Cache (Redis)
- **Image** : redis:7-alpine
- **Port** : 6379
- **Persistance** : Append-only file activé

#### Gestion des secrets (Vault)
- **Image** : vault:1.15
- **Port** : 8200
- **Mode** : Développement (token root = "root")
- **Volume** : Persistance des données Vault

#### Authentification (Keycloak)
- **Image** : quay.io/keycloak/keycloak:22.0
- **Port** : 8081
- **Base de données** : PostgreSQL partagée
- **Admin** : admin/admin (à changer en production)

#### Proxy inverse (NGINX)
- **Image** : nginx:alpine
- **Ports** : 80 et 443
- **Configuration** : `nginx.conf` du projet racine

### Commandes de développement

```bash
# Démarrer tous les services
docker-compose up -d

# Voir les logs
docker-compose logs -f

# Arrêter tous les services
docker-compose down

# Reconstruire et redémarrer un service spécifique
docker-compose up -d --build api

# Accéder à un conteneur en cours d'exécution
docker-compose exec api bash
```

## Configuration de production

### Construction des images

Pour construire les images de production :

```bash
# Construire l'API
docker build -f infrastructure/docker/Dockerfile.api -t skygenesisenterprise/api:latest .

# Construire le frontend
docker build -f infrastructure/docker/Dockerfile.frontend -t sky-genesis/frontend:latest .
```

### Variables d'environnement

En production, configurez les variables suivantes :

```bash
# Base de données
DATABASE_URL=postgresql://user:password@host:5432/api_service

# Cache Redis
REDIS_URL=redis://host:6379

# Gestion des secrets
VAULT_ADDR=https://vault.example.com:8200

# Authentification
JWT_SECRET=votre_cle_secrete_jwt

# API
API_URL=https://api.example.com

# Frontend
NEXT_PUBLIC_API_URL=https://api.example.com
```

### Déploiement

Utilisez le fichier `docker-compose.prod.yml` pour le déploiement en production :

```bash
docker-compose -f infrastructure/docker/docker-compose.prod.yml up -d
```

Ce fichier inclut :
- Images optimisées pour la production
- Configuration NGINX pour le proxy inverse
- Certificats SSL
- Limites de ressources
- Politiques de redémarrage

## Commandes communes

### Gestion des conteneurs

```bash
# Lister les conteneurs en cours d'exécution
docker ps

# Voir les logs d'un conteneur
docker logs sky-genesis-api

# Arrêter un conteneur spécifique
docker stop sky-genesis-api

# Supprimer les conteneurs arrêtés
docker container prune

# Nettoyer les images non utilisées
docker image prune -a
```

### Debugging

```bash
# Accéder au shell d'un conteneur
docker exec -it sky-genesis-api /bin/bash

# Voir les statistiques des conteneurs
docker stats

# Inspecter un conteneur
docker inspect sky-genesis-api
```

### Santé des services

```bash
# Vérifier la santé de l'API
curl http://localhost:8080/health

# Vérifier la santé du frontend
curl http://localhost:3000/api/health

# Vérifier PostgreSQL
docker exec sky-genesis-postgres pg_isready -U postgres -d api_service
```

## Sécurité

### Bonnes pratiques

- **Utilisateurs non-root** : Tous les conteneurs utilisent des utilisateurs non-privilégiés
- **Images minimales** : Utilisation d'images Alpine et Debian slim
- **Secrets externes** : Les secrets ne sont pas stockés dans les images
- **Scans de sécurité** : Intégrez des scans réguliers avec Trivy

### Scan de sécurité

```bash
# Scanner une image pour les vulnérabilités
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasecurity/trivy image skygenesisenterprise/api:latest

# Scanner pour les secrets
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  zricethezav/gitleaks:latest docker --image skygenesisenterprise/api:latest
```

### Configuration NGINX sécurisée

Le fichier `nginx.conf` inclut des en-têtes de sécurité :
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security`
- `Referrer-Policy`

## Monitoring et logging

### Health checks

Tous les services incluent des health checks configurés :
- **Intervalle** : 30 secondes
- **Timeout** : 10 secondes
- **Retries** : 3
- **Start period** : 30-60 secondes selon le service

### Logging

Configuration de logging JSON avec rotation :
```yaml
logging:
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"
```

### Métriques

Pour l'export de métriques Prometheus, exposez le port 9090 et configurez node_exporter.

## Dépannage

### Problèmes courants

#### Port déjà utilisé
```bash
# Identifier le processus utilisant le port
lsof -i :8080

# Tuer le processus
kill -9 <PID>
```

#### Conteneur ne démarre pas
```bash
# Voir les logs détaillés
docker logs sky-genesis-api

# Démarrer en mode debug
docker run -it --entrypoint /bin/bash skygenesisenterprise/api:latest
```

#### Connexion à la base de données échoue
```bash
# Vérifier que PostgreSQL fonctionne
docker ps | grep postgres

# Voir les logs PostgreSQL
docker logs sky-genesis-postgres

# Tester la connexion
docker exec sky-genesis-postgres pg_isready -U postgres -d api_service
```

#### Problèmes de volumes
```bash
# Lister les volumes
docker volume ls

# Inspecter un volume
docker volume inspect postgres_data

# Supprimer un volume (ATTENTION : perte de données)
docker volume rm postgres_data
```

### Commandes de diagnostic

```bash
# État des services
docker-compose ps

# Logs de tous les services
docker-compose logs

# Utilisation des ressources
docker stats

# Événements Docker
docker events

# Nettoyer le système
docker system prune -a --volumes
```

## Ressources supplémentaires

- [Documentation Docker](https://docs.docker.com/)
- [Guide Docker Compose](https://docs.docker.com/compose/)
- [Bonnes pratiques Docker](https://docs.docker.com/develop/dev-best-practices/)
- [Sécurité Docker](https://docs.docker.com/engine/security/)
- [Multi-stage builds](https://docs.docker.com/develop/dev-best-practices/)

---

**🐳 Containerisé • 🔒 Sécurisé • 🚀 Optimisé**