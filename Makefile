# Copyright 2025 Nadrama Pty Ltd
# SPDX-License-Identifier: Apache-2.0

BUILD_VERSION := $(shell git describe --tags --dirty --always)
BUILD_DATE := $(shell date -u '+%Y-%m-%dT%H:%M:%S')
COMMIT_HASH := $(shell git rev-parse --short HEAD)
COMMIT_DATE := $(shell git log -1 --format=%cd --date=format:'%Y-%m-%dT%H:%M:%S')
COMMIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)

BUILDVARS_PKG := github.com/easy-oidc/easy-oidc/internal/buildvars

BINARY_DIR := bin

# SQLite requires CGO
export CGO_ENABLED=1

LDFLAGS := -X $(BUILDVARS_PKG).buildVersion=$(BUILD_VERSION) \
           -X $(BUILDVARS_PKG).buildDate=$(BUILD_DATE) \
           -X $(BUILDVARS_PKG).commitHash=$(COMMIT_HASH) \
           -X $(BUILDVARS_PKG).commitDate=$(COMMIT_DATE) \
           -X $(BUILDVARS_PKG).commitBranch=$(COMMIT_BRANCH)

.PHONY: help git-hooks fmt lint test e2e check build clean tag

help:
	@echo "Available targets:"
	@echo "  git-hooks  - Install git pre-commit hook"
	@echo "  fmt        - Format code"
	@echo "  lint       - Run golangci-lint"
	@echo "  test       - Run tests"
	@echo "  e2e        - Run E2E test with Dex upstream"
	@echo "  check      - Run fmt, lint, and test"
	@echo "  build      - Build the easy-oidc binary"
	@echo "  clean      - Remove build artifacts"
	@echo "  tag        - Tag the current commit with a version"

git-hooks:
	@echo "Installing git hooks..."
	@mkdir -p .git/hooks
	@cp scripts/pre-commit .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "Git hooks installed!"

fmt:
	@echo "Formatting code..."
	go fmt ./...

lint:
	@echo "Running linter..."
	golangci-lint run

test:
	@echo "Running tests..."
	go test -v -race -coverprofile=coverage.out ./...

e2e:
	@echo "Running E2E tests..."
	./scripts/e2e/run-e2e-test.sh

check: fmt lint test

build:
	@echo "Building easy-oidc..."
	@mkdir -p $(BINARY_DIR)
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY_DIR)/easy-oidc ./cmd/easy-oidc

clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BINARY_DIR)/
	rm -rf temp/
	rm -f coverage.out

tag:
	@if [ -z "$(VERSION)" ]; then \
		echo "Usage: make tag VERSION=v1.0.0"; \
		exit 1; \
	fi; \
	git tag -a $(VERSION) -m "$(VERSION)"; \
	echo "Tagged $(VERSION)"; \
	echo ""; \
	echo "To push the tag, run:"; \
	echo "  git push origin $(VERSION)"
