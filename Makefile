# SpecForge — developer and CI entry points.
#
# Every target here runs identically on a laptop and in CI. Where a check exists
# in CI but not here, people discover failures late; where it exists only here,
# it stops being enforced. So CI calls these targets rather than reimplementing
# them.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

MODULE      := github.com/specforge/specforge
BINDIR      := bin
CMDS        := specforge-api specforge-worker specforge-migrate specforge-cli
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
# SOURCE_DATE_EPOCH keeps the build reproducible: the same source must produce
# the same binary, or a signed provenance attestation proves nothing.
BUILD_DATE  ?= $(shell date -u -d "@$${SOURCE_DATE_EPOCH:-$$(git log -1 --format=%ct 2>/dev/null || echo 0)}" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)
LDFLAGS     := -s -w \
	-X $(MODULE)/internal/platform/buildinfo.Version=$(VERSION) \
	-X $(MODULE)/internal/platform/buildinfo.Commit=$(COMMIT) \
	-X $(MODULE)/internal/platform/buildinfo.Date=$(BUILD_DATE)

# Local development database. Overridable for CI.
DEV_DSN     ?= host=127.0.0.1 port=5432 user=specforge password=specforge dbname=specforge sslmode=disable
TEST_DSN    ?= host=127.0.0.1 port=5432 user=specforge password=specforge dbname=specforge_test sslmode=disable

COMPOSE     := docker compose -f deploy/docker/docker-compose.yml
IMAGE_REPO  ?= ghcr.io/specforge

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z0-9_./-]+:.*?## ' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# --------------------------------------------------------------- Build ------

.PHONY: build
build: ## Build all binaries into bin/
	@mkdir -p $(BINDIR)
	@for cmd in $(CMDS); do \
		echo "  building $$cmd"; \
		CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BINDIR)/$$cmd ./cmd/$$cmd; \
	done

.PHONY: clean
clean: ## Remove build output
	rm -rf $(BINDIR) coverage.out coverage.html

# --------------------------------------------------------------- Checks -----

.PHONY: check
check: fmt-check vet lint-deps lint-routes test ## Everything CI runs on a pull request

.PHONY: hooks
hooks: ## Install the git hooks (formatting, route lint, commit message)
	@git config core.hooksPath .githooks
	@chmod +x .githooks/*
	@echo "hooks installed: $$(ls .githooks | tr '\n' ' ')"
	@echo "bypass a single commit with --no-verify, and say so in review"

.PHONY: verify-release
verify-release: ## Everything that must hold before tagging a release
	$(MAKE) check
	$(MAKE) test-integration
	$(MAKE) test-isolation
	@echo
	@echo "Chart version:    $$(grep '^version:' deploy/helm/specforge/Chart.yaml | awk '{print $$2}')"
	@echo "Chart appVersion: $$(grep '^appVersion:' deploy/helm/specforge/Chart.yaml | awk '{print $$2}' | tr -d '\"')"
	@echo "Build version:    $(VERSION)"
	@echo
	@echo "These three must match the tag you are about to create."

.PHONY: fmt
fmt: ## Format the code
	gofmt -w -s cmd internal test

.PHONY: fmt-check
fmt-check: ## Fail if any file is unformatted
	@out=$$(gofmt -l -s cmd internal test); \
	if [ -n "$$out" ]; then echo "these files need gofmt:"; echo "$$out"; exit 1; fi

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: lint-routes
lint-routes: ## Fail if any route is registered without a permission
	@go run ./tools/lintroutes

.PHONY: lint-deps
lint-deps: ## Fail if a third-party dependency has been introduced
	@if [ -s go.sum ]; then \
		echo "go.sum is not empty: a third-party dependency has been added."; \
		echo "That is allowed, but it is a deliberate decision — see docs/architecture/19-repository-structure.md."; \
		exit 1; \
	fi
	@echo "no third-party dependencies"

.PHONY: test
test: ## Unit and contract tests (no database required)
	go test ./internal/... ./test/contract/... -race -count=1

.PHONY: test-integration
test-integration: ## Integration tests (requires PostgreSQL)
	SF_TEST_DSN="$(TEST_DSN)" go test ./test/integration/... -count=1 -v

.PHONY: test-isolation
test-isolation: ## Assert the database invariants (RLS, immutability, audit)
	psql "$(TEST_DSN)" -v ON_ERROR_STOP=1 -f test/isolation/invariants.sql

.PHONY: cover
cover: ## Test with a coverage report
	go test ./internal/... ./test/contract/... -coverprofile=coverage.out -covermode=atomic
	go tool cover -html=coverage.out -o coverage.html
	@go tool cover -func=coverage.out | tail -1

.PHONY: test-all
test-all: test test-integration test-isolation ## Every test, including the database ones

# --------------------------------------------------------------- Database ---

.PHONY: migrate
migrate: ## Apply migrations to the development database
	SF_DB_DSN="$(DEV_DSN)" go run ./cmd/specforge-migrate up

.PHONY: migrate-status
migrate-status: ## Show which migrations have been applied
	SF_DB_DSN="$(DEV_DSN)" go run ./cmd/specforge-migrate status

.PHONY: seed
seed: ## Create the demo tenant, project and traceable artifact graph
	SF_DB_DSN="$(DEV_DSN)" go run ./cmd/specforge-cli seed

# --------------------------------------------------------------- Run --------

.PHONY: run-api
run-api: ## Run the API against the development stack
	SF_DB_DSN="$(DEV_DSN)" SF_AUTH_DEV_IDP=true go run ./cmd/specforge-api

.PHONY: run-worker
run-worker: ## Run the worker against the development stack
	SF_DB_DSN="$(DEV_DSN)" go run ./cmd/specforge-worker

.PHONY: dev
dev: ## Start the full local stack, migrate and seed
	$(COMPOSE) up -d --build
	@echo "waiting for the database..."
	@$(COMPOSE) exec -T postgres bash -c 'until pg_isready -U specforge -q; do sleep 1; done'
	$(MAKE) migrate
	$(MAKE) seed
	@# The development identity provider must issue tokens scoped to the tenant
	@# the seeder just created, and it reads that from its environment at
	@# startup. Wiring it here rather than telling the developer to export it
	@# removes the one step that, if skipped, makes everything else look broken.
	@tenant=$$($(MAKE) -s tenant-id); \
		echo "SF_DEV_TENANT_ID=$$tenant" > deploy/docker/.env; \
		echo "wiring the development identity provider to tenant $$tenant"
	$(COMPOSE) up -d api
	@echo
	@echo "  API        http://localhost:8080"
	@echo "  Web        http://localhost:3000"
	@echo "  Dev IdP    http://localhost:8081/.well-known/openid-configuration"
	@echo "  Grafana    http://localhost:3001"
	@echo "  Jaeger     http://localhost:16686"
	@echo "  MinIO      http://localhost:9001"
	@echo
	@echo "  Check all of it:  make smoke"

.PHONY: smoke
smoke: ## Verify a running local stack end to end
	@./scripts/smoke.sh

.PHONY: token
token: ## Print a development access token (ROLE=analyst)
	@./scripts/dev-token.sh $(or $(ROLE),owner)

.PHONY: tenant-id
tenant-id: ## Print the demo tenant's id (SLUG=acme)
	@SF_DB_DSN="$(DEV_DSN)" go run ./cmd/specforge-cli tenant-id --slug $(or $(SLUG),acme)

.PHONY: dev-down
dev-down: ## Stop the local stack, keeping volumes
	$(COMPOSE) down

.PHONY: dev-clean
dev-clean: ## Stop the local stack and delete its data
	$(COMPOSE) down -v

.PHONY: logs
logs: ## Tail the local stack logs
	$(COMPOSE) logs -f --tail=100

# --------------------------------------------------------------- Images -----

.PHONY: docker-build
docker-build: ## Build the container images
	docker build -f deploy/docker/Dockerfile.api    -t $(IMAGE_REPO)/specforge-api:$(VERSION)    --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) .
	docker build -f deploy/docker/Dockerfile.worker -t $(IMAGE_REPO)/specforge-worker:$(VERSION) --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) .
	docker build -f deploy/docker/Dockerfile.web    -t $(IMAGE_REPO)/specforge-web:$(VERSION)    .

# --------------------------------------------------------------- Verify -----

.PHONY: verify-audit
verify-audit: ## Recompute a tenant's audit chain (TENANT=<uuid>)
	@test -n "$(TENANT)" || (echo "usage: make verify-audit TENANT=<uuid>"; exit 1)
	SF_DB_DSN="$(DEV_DSN)" go run ./cmd/specforge-cli verify-audit --tenant $(TENANT)

.PHONY: openapi
openapi: ## Check the OpenAPI document against the router
	go test ./test/contract/... -count=1

# --------------------------------------------------------------- Web --------

.PHONY: web-install
web-install: ## Install the frontend dependencies
	cd web && npm ci

.PHONY: web-dev
web-dev: ## Run the frontend in development mode
	cd web && npm run dev

.PHONY: web-build
web-build: ## Build the frontend
	cd web && npm run build

.PHONY: web-check
web-check: ## Type-check and lint the frontend
	cd web && npm run typecheck && npm run lint
