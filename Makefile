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

.PHONY: help setup fmt lint precommit test e2e check build clean tag

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

e2e: ## Run E2E tests with Dex upstream
	@echo "Running E2E tests..."
	./scripts/e2e/run-e2e-test.sh

check: fmt lint test ## Format, lint, and test

build: ## Build the easy-oidc binary
	@echo "Building easy-oidc..."
	@mkdir -p $(BINARY_DIR)
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY_DIR)/easy-oidc ./cmd/easy-oidc

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
