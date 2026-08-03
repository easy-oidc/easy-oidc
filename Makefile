# Easy OIDC <https://easy-oidc.dev>
# Copyright The Easy OIDC Authors
# SPDX-License-Identifier: Apache-2.0

.DEFAULT_GOAL := help

VERSION_TAG := $(shell if [ -z "$$(git status --porcelain)" ]; then tag=$$(git describe --tags --exact-match 2>/dev/null); echo "$$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$$' && echo "$$tag"; fi)
BUILD_VERSION := $(if $(VERSION_TAG),$(VERSION_TAG),dev)
BUILD_DATE := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
COMMIT_HASH := $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
COMMIT_DATE := $(shell TZ=UTC git log -1 --format=%cd --date=format-local:'%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo unknown)
COMMIT_BRANCH := $(shell branch=$$(git symbolic-ref --short -q HEAD); if [ -n "$$branch" ]; then echo "$$branch"; else echo unknown; fi)

BUILDVARS_PKG := github.com/easy-oidc/easy-oidc/internal/buildvars

BINARY_DIR := bin

# SQLite requires CGO
export CGO_ENABLED=1

LDFLAGS := -X $(BUILDVARS_PKG).buildVersion=$(BUILD_VERSION) \
           -X $(BUILDVARS_PKG).buildDate=$(BUILD_DATE) \
           -X $(BUILDVARS_PKG).commitHash=$(COMMIT_HASH) \
           -X $(BUILDVARS_PKG).commitDate=$(COMMIT_DATE) \
           -X $(BUILDVARS_PKG).commitBranch=$(COMMIT_BRANCH)

.PHONY: help setup fmt lint precommit test test-postgresql e2e check build dev clean tag

help: ## Show available targets
	@echo "Usage: make <target>"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

setup: ## Verify required tools and install git hooks
	@command -v go >/dev/null 2>&1 || { echo "go is required but not installed"; exit 1; }
	@command -v cc >/dev/null 2>&1 || { echo "a C compiler is required but not installed"; exit 1; }
	@go tool golangci-lint version >/dev/null 2>&1 || { echo "golangci-lint is required as a Go tool"; exit 1; }
	@echo "All required tools are installed."
	@echo "Installing git hooks..."
	@mkdir -p .git/hooks
	@cp scripts/git-hooks/pre-commit .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@cp scripts/git-hooks/commit-msg .git/hooks/commit-msg
	@chmod +x .git/hooks/commit-msg
	@echo "Setup complete. Git hooks installed."

fmt: ## Format Go source files
	@echo "Formatting code..."
	go fmt ./...

lint: ## Run golangci-lint
	@echo "Running linter..."
	go tool golangci-lint run

precommit: ## Check modules, formatting, and linters (read-only)
	@echo "Checking module files..."
	@go mod tidy -diff
	@echo "Checking formatting..."
	@UNFORMATTED=$$(gofmt -l . 2>&1); \
	if [ -n "$$UNFORMATTED" ]; then \
		echo "The following files need formatting (run 'make fmt'):"; \
		echo "$$UNFORMATTED"; \
		exit 1; \
	fi
	@$(MAKE) lint

test: ## Run tests with race detector
	@echo "Running tests..."
	go test -v -race -coverprofile=coverage.out ./...

test-postgresql: ## Start/reuse local PostgreSQL and run real state database tests
	@set -e; CONTAINER_CMD=$${CONTAINER_CMD:-$$(command -v podman || command -v docker)}; test -n "$$CONTAINER_CMD" || { echo "podman or docker is required"; exit 1; }; \
	$$CONTAINER_CMD inspect easy-oidc-state-test >/dev/null 2>&1 || $$CONTAINER_CMD run -d --name easy-oidc-state-test -p 55435:5432 -e POSTGRES_USER=easy_oidc -e POSTGRES_PASSWORD=easy_oidc -e POSTGRES_DB=easy_oidc_state docker.io/library/postgres@sha256:6567bca8d7bc8c82c5922425a0baee57be8402df92bae5eacad5f01ae9544daa >/dev/null; \
	$$CONTAINER_CMD start easy-oidc-state-test >/dev/null 2>&1 || true; \
	ready=0; for i in $$(seq 1 30); do $$CONTAINER_CMD exec easy-oidc-state-test pg_isready -U easy_oidc -d easy_oidc_state >/dev/null 2>&1 && ready=1 && break; sleep 1; done; \
	test "$$ready" = 1 || { echo "PostgreSQL did not become ready"; exit 1; }; \
	EASYOIDC_STATE_TEST_DB_URL='postgresql://easy_oidc:easy_oidc@127.0.0.1:55435/easy_oidc_state?sslmode=disable' go test -v -race -count=1 ./internal/statedb -run PostgreSQL

e2e: ## Run E2E tests with Dex upstream
	@echo "Running E2E tests..."
	./scripts/e2e/run-e2e-test.sh

check: fmt lint test ## Format, lint, and test

build: ## Build the easy-oidc binary
	@echo "Building easy-oidc..."
	@mkdir -p $(BINARY_DIR)
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY_DIR)/easy-oidc ./cmd/easy-oidc

dev: ## Run the template development server
	go run ./cmd/easy-oidc dev --templates-dir ./templates

clean: ## Remove build artifacts
	@echo "Cleaning build artifacts..."
	rm -rf $(BINARY_DIR)/
	rm -rf temp/
	rm -f coverage.out

tag: ## Tag the current commit with a version (VERSION=vX.Y.Z)
	@if [ -z "$(VERSION)" ]; then \
		echo "Usage: make tag VERSION=v1.0.0"; \
		exit 1; \
	elif ! echo "$(VERSION)" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$$'; then \
		echo "VERSION must be a semantic version tag such as v1.2.3"; \
		exit 1; \
	fi; \
	[ -z "$$(git status --porcelain)" ] || { echo "Working tree must be clean before tagging"; exit 1; }; \
	git tag -a $(VERSION) -m "$(VERSION)"; \
	echo "Tagged $(VERSION)"; \
	echo ""; \
	echo "To push the tag, run:"; \
	echo "  git push origin $(VERSION)"
