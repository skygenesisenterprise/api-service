# Sky Genesis Enterprise - Main Makefile
# ======================================

# Variables
PNPM ?= pnpm
DOCKER_COMPOSE ?= docker-compose
DOCKER_COMPOSE_FILE ?= infrastructure/docker/docker-compose.yml

# Default target
.PHONY: help
help: ## Show this help message
	@echo "Sky Genesis Enterprise - Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-25s %s\n", $$1, $$2}'

# Development commands
.PHONY: dev
dev: ## Start both backend and frontend in development mode
	$(PNPM) run dev

.PHONY: dev-backend
dev-backend: ## Start only the backend API
	$(PNPM) run dev:backend

.PHONY: dev-frontend
dev-frontend: ## Start only the frontend
	$(PNPM) run dev:frontend

.PHONY: build
build: ## Build all components
	$(PNPM) run build

.PHONY: start
start: ## Start production servers
	$(PNPM) run start

# API specific commands (delegate to api/Makefile)
.PHONY: api-%
api-%: ## Run API-specific commands (e.g., make api-build, make api-test)
	$(MAKE) -C api $*

# Testing commands
.PHONY: test
test: ## Run all tests
	$(PNPM) run test

.PHONY: test-watch
test-watch: ## Run tests in watch mode
	$(PNPM) run test:watch

.PHONY: lint
lint: ## Run linting
	$(PNPM) run lint

# Docker commands
.PHONY: docker-build
docker-build: ## Build all Docker images
	$(DOCKER_COMPOSE) -f $(DOCKER_COMPOSE_FILE) build

.PHONY: docker-up
docker-up: ## Start all services with Docker Compose
	$(DOCKER_COMPOSE) -f $(DOCKER_COMPOSE_FILE) up -d

.PHONY: docker-down
docker-down: ## Stop all services with Docker Compose
	$(DOCKER_COMPOSE) -f $(DOCKER_COMPOSE_FILE) down

.PHONY: docker-dev
docker-dev: ## Run development environment with Docker
	$(DOCKER_COMPOSE) -f $(DOCKER_COMPOSE_FILE) up

.PHONY: docker-logs
docker-logs: ## Show logs from all Docker containers
	$(DOCKER_COMPOSE) -f $(DOCKER_COMPOSE_FILE) logs -f

.PHONY: docker-clean
docker-clean: ## Clean Docker containers and volumes
	$(DOCKER_COMPOSE) -f $(DOCKER_COMPOSE_FILE) down -v --remove-orphans

# Database commands
.PHONY: db-setup
db-setup: ## Setup database (requires Docker services running)
	@echo "Database setup requires running Docker services"
	@echo "Run: make docker-up"

.PHONY: db-migrate
db-migrate: ## Run database migrations
	@echo "Database migrations handled by Docker containers"

# Installation and setup
.PHONY: install
install: ## Install all dependencies
	$(PNPM) install

.PHONY: setup
setup: ## Setup development environment
	@echo "Setting up development environment..."
	$(PNPM) install
	@echo "Development environment setup complete!"
	@echo ""
	@echo "Next steps:"
	@echo "1. Copy .env.example to .env and configure your environment variables"
	@echo "2. Run 'make docker-up' to start supporting services (DB, Vault, etc.)"
	@echo "3. Run 'make dev' to start development servers"

# Cleanup commands
.PHONY: clean
clean: ## Clean all build artifacts
	$(PNPM) run clean 2>/dev/null || true
	$(MAKE) -C api clean 2>/dev/null || true
	find . -name "*.log" -delete 2>/dev/null || true
	find . -name ".DS_Store" -delete 2>/dev/null || true

.PHONY: clean-all
clean-all: clean docker-clean ## Clean everything including Docker

# Health checks
.PHONY: health
health: ## Check health of all services
	@echo "Checking API health..."
	curl -f http://localhost:8080/health 2>/dev/null && echo "✅ API healthy" || echo "❌ API not responding"
	@echo ""
	@echo "Checking Frontend health..."
	curl -f http://localhost:3000/api/health 2>/dev/null && echo "✅ Frontend healthy" || echo "❌ Frontend not responding"

# CI/CD commands
.PHONY: ci
ci: lint test build ## Run CI pipeline

.PHONY: release
release: clean ci ## Prepare for release

# Utility commands
.PHONY: env-example
env-example: ## Create .env file from example
	@if [ ! -f .env ]; then \
		cp .env.example .env 2>/dev/null || echo "No .env.example found at root"; \
		echo ".env file created (if example existed)"; \
	else \
		echo ".env file already exists"; \
	fi

.PHONY: update
update: ## Update all dependencies
	$(PNPM) update

# Help for specific targets
.PHONY: help-dev
help-dev: ## Show development-related commands
	@echo "Development commands:"
	@echo "  make dev             - Start all services"
	@echo "  make dev-backend     - Start only API"
	@echo "  make dev-frontend    - Start only frontend"
	@echo "  make build           - Build all components"
	@echo "  make test            - Run all tests"
	@echo "  make lint            - Run linting"
	@echo "  make setup           - Setup development environment"

.PHONY: help-docker
help-docker: ## Show Docker-related commands
	@echo "Docker commands:"
	@echo "  make docker-up       - Start all services"
	@echo "  make docker-down     - Stop all services"
	@echo "  make docker-dev      - Run development environment"
	@echo "  make docker-logs     - Show container logs"
	@echo "  make docker-clean    - Clean containers and volumes"

.PHONY: help-api
help-api: ## Show API-specific commands
	@echo "API commands (prefix with 'api-'):"
	@echo "  make api-build      - Build API"
	@echo "  make api-test       - Test API"
	@echo "  make api-dev        - Run API in dev mode"
	@echo "  make api-check      - Check API code"
	@echo "  make api-clippy     - Lint API code"
	@echo "  make api-fmt        - Format API code"
	@echo "  make api-doc        - Generate API docs"
	@echo ""
	@echo "For more API commands, run: make api-help"