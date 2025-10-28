# Sky Genesis Enterprise API - Makefile
# =====================================

# Variables
CARGO ?= cargo
DOCKER_COMPOSE ?= docker-compose
DOCKER_COMPOSE_FILE ?= ../infrastructure/docker/docker-compose.yml

# Default target
.PHONY: help
help: ## Show this help message
	@echo "Sky Genesis Enterprise API - Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}'

# Development commands
.PHONY: dev
dev: ## Run the API in development mode
	$(CARGO) run

.PHONY: build
build: ## Build the API in release mode
	$(CARGO) build --release

.PHONY: build-dev
build-dev: ## Build the API in development mode
	$(CARGO) build

.PHONY: run
run: ## Run the API (alias for dev)
	$(MAKE) dev

.PHONY: clean
clean: ## Clean build artifacts
	$(CARGO) clean

# Testing commands
.PHONY: test
test: ## Run all tests
	$(CARGO) test

.PHONY: test-watch
test-watch: ## Run tests in watch mode
	$(CARGO) test -- --nocapture --test-threads=1

.PHONY: test-unit
test-unit: ## Run unit tests only
	$(CARGO) test --lib

.PHONY: test-integration
test-integration: ## Run integration tests only
	$(CARGO) test --test integration

# Code quality commands
.PHONY: check
check: ## Run cargo check for syntax and type errors
	$(CARGO) check

.PHONY: clippy
clippy: ## Run clippy for linting
	$(CARGO) clippy -- -D warnings

.PHONY: fmt
fmt: ## Format code with rustfmt
	$(CARGO) fmt

.PHONY: fmt-check
fmt-check: ## Check code formatting
	$(CARGO) fmt -- --check

# Documentation commands
.PHONY: doc
doc: ## Generate documentation
	$(CARGO) doc --open --no-deps

.PHONY: doc-private
doc-private: ## Generate documentation including private items
	$(CARGO) doc --open --no-deps --document-private-items

# Docker commands
.PHONY: docker-build
docker-build: ## Build Docker image
	$(DOCKER_COMPOSE) -f $(DOCKER_COMPOSE_FILE) build api

.PHONY: docker-up
docker-up: ## Start all services with Docker Compose
	$(DOCKER_COMPOSE) -f $(DOCKER_COMPOSE_FILE) up -d

.PHONY: docker-down
docker-down: ## Stop all services with Docker Compose
	$(DOCKER_COMPOSE) -f $(DOCKER_COMPOSE_FILE) down

.PHONY: docker-logs
docker-logs: ## Show logs from Docker containers
	$(DOCKER_COMPOSE) -f $(DOCKER_COMPOSE_FILE) logs -f api

.PHONY: docker-dev
docker-dev: ## Run development environment with Docker
	$(DOCKER_COMPOSE) -f $(DOCKER_COMPOSE_FILE) up

# Database commands
.PHONY: db-migrate
db-migrate: ## Run database migrations (placeholder)
	@echo "Database migrations not yet implemented"
	@echo "Run: diesel migration run"

.PHONY: db-reset
db-reset: ## Reset database (placeholder)
	@echo "Database reset not yet implemented"

# Utility commands
.PHONY: install
install: ## Install dependencies
	$(CARGO) build

.PHONY: update
update: ## Update dependencies
	$(CARGO) update

.PHONY: audit
audit: ## Audit dependencies for security vulnerabilities
	cargo audit

.PHONY: outdated
outdated: ## Check for outdated dependencies
	cargo outdated

# CI/CD commands
.PHONY: ci
ci: check clippy test ## Run CI pipeline (check, clippy, test)

.PHONY: release
release: clean fmt check clippy test build ## Prepare for release

# Development setup
.PHONY: setup
setup: ## Setup development environment
	@echo "Setting up development environment..."
	$(CARGO) install cargo-watch
	$(CARGO) install cargo-audit
	$(CARGO) install cargo-outdated
	@echo "Development environment setup complete!"

.PHONY: watch
watch: ## Watch for changes and rebuild automatically
	cargo watch -x run

# Health check
.PHONY: health
health: ## Check API health (requires running server)
	curl -f http://localhost:8080/health || echo "API not running or health check failed"

# Environment setup
.PHONY: env-example
env-example: ## Create .env file from example
	@if [ ! -f .env ]; then \
		cp ../.env.example .env 2>/dev/null || echo "No .env.example found"; \
		echo ".env file created (if example existed)"; \
	else \
		echo ".env file already exists"; \
	fi

# Help for specific targets
.PHONY: help-dev
help-dev: ## Show development-related commands
	@echo "Development commands:"
	@echo "  make dev          - Run API in development mode"
	@echo "  make build        - Build for release"
	@echo "  make test         - Run all tests"
	@echo "  make check        - Check for errors"
	@echo "  make clippy       - Run linter"
	@echo "  make fmt          - Format code"
	@echo "  make watch        - Watch for changes"

.PHONY: help-docker
help-docker: ## Show Docker-related commands
	@echo "Docker commands:"
	@echo "  make docker-build - Build Docker image"
	@echo "  make docker-up    - Start services"
	@echo "  make docker-down  - Stop services"
	@echo "  make docker-logs  - Show logs"