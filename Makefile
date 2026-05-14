.PHONY: help build dev prod clean test lint

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build all containers
	docker-compose build

dev: ## Start development environment
	docker-compose -f docker-compose.dev.yml up --build

prod: ## Start production environment
	docker-compose up --build -d

stop: ## Stop all containers
	docker-compose down
	docker-compose -f docker-compose.dev.yml down

clean: ## Clean up containers and images
	docker-compose down --rmi all --volumes --remove-orphans
	docker-compose -f docker-compose.dev.yml down --rmi all --volumes --remove-orphans

test-backend: ## Run backend tests
	docker-compose exec backend pytest

test-frontend: ## Run frontend tests
	docker-compose exec frontend npm test

lint-backend: ## Lint backend code
	docker-compose exec backend black --check .
	docker-compose exec backend isort --check-only .
	docker-compose exec backend flake8 .

lint-frontend: ## Lint frontend code
	docker-compose exec frontend npm run lint

logs: ## Show logs from all services
	docker-compose logs -f

logs-backend: ## Show backend logs
	docker-compose logs -f backend

logs-frontend: ## Show frontend logs
	docker-compose logs -f frontend