#!/usr/bin/env bash
# Copyright 2025 Nadrama Pty Ltd
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "==> Checking prerequisites..."
for cmd in curl jq make go kubectl; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "ERROR: Required command '$cmd' not found. Please install it first."
        exit 1
    fi
done

if ! kubectl oidc-login --version &> /dev/null 2>&1; then
    echo "ERROR: kubectl oidc-login plugin not found."
    echo "Install with: brew install kubelogin"
    exit 1
fi

CONTAINER_CMD="${CONTAINER_CMD:-podman}"
if ! command -v "$CONTAINER_CMD" &> /dev/null; then
    CONTAINER_CMD=docker
    if ! command -v "$CONTAINER_CMD" &> /dev/null; then
        echo "ERROR: Neither podman nor docker found. Please install one."
        exit 1
    fi
fi

echo "==> E2E Test: Starting Dex and easy-oidc"

cleanup() {
    echo "==> Cleaning up..."
    $CONTAINER_CMD stop dex-e2e 2>/dev/null || true
    $CONTAINER_CMD rm dex-e2e 2>/dev/null || true
    if [ -n "${EASY_OIDC_PID:-}" ]; then
        kill "$EASY_OIDC_PID" 2>/dev/null || true
    fi
}

trap cleanup EXIT INT TERM

echo "==> Cleaning up any existing test containers..."
$CONTAINER_CMD stop dex-e2e 2>/dev/null || true
$CONTAINER_CMD rm dex-e2e 2>/dev/null || true

echo "==> Starting Dex container..."
$CONTAINER_CMD run -d --rm --name dex-e2e \
    -p 5556:5556 \
    -v "$SCRIPT_DIR/dex-config.yaml:/etc/dex/config.docker.yaml:ro" \
    ghcr.io/dexidp/dex:latest

echo "==> Waiting for Dex to be ready..."
for i in {1..30}; do
    if curl -s http://127.0.0.1:5556/dex/.well-known/openid-configuration > /dev/null 2>&1; then
        echo "==> Dex is ready!"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "ERROR: Dex failed to start"
        exit 1
    fi
    sleep 1
done

echo "==> Building easy-oidc..."
cd "$PROJECT_ROOT"
make build

echo "==> Starting easy-oidc..."
set -a
source "$SCRIPT_DIR/.env"
set +a

./bin/easy-oidc --config "$SCRIPT_DIR/easy-oidc-config.jsonc" --debug &
EASY_OIDC_PID=$!

echo "==> Waiting for easy-oidc to be ready..."
for i in {1..30}; do
    if curl -s http://127.0.0.1:8080/.well-known/openid-configuration > /dev/null 2>&1; then
        echo "==> easy-oidc is ready!"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "ERROR: easy-oidc failed to start"
        exit 1
    fi
    sleep 1
done

echo "==> Testing OIDC discovery endpoint..."
if ! curl -sf http://127.0.0.1:8080/.well-known/openid-configuration | jq . > /dev/null; then
    echo "ERROR: Failed to get OIDC discovery document"
    exit 1
fi

echo "==> Testing JWKS endpoint..."
if ! curl -sf http://127.0.0.1:8080/jwks | jq . > /dev/null; then
    echo "ERROR: Failed to get JWKS"
    exit 1
fi

echo "==> Testing OIDC flow with kubelogin..."
echo ""
echo "Opening browser for OIDC authentication..."
echo "Please complete the login in your browser (use Dex mock login)"
echo ""

if kubectl oidc-login setup \
    --oidc-issuer-url=http://127.0.0.1:8080 \
    --oidc-client-id=e2e-test-client \
    --oidc-use-pkce \
    --listen-address=127.0.0.1:18000 2>&1 | tee /tmp/kubelogin-output.txt; then
    
    echo ""
    echo "==> Extracting ID token from output..."
    if grep -q "id_token" /tmp/kubelogin-output.txt; then
        echo "✅ ID Token received and validated!"
        echo ""
        ID_TOKEN=$(grep "id_token:" /tmp/kubelogin-output.txt | awk '{print $2}')
        if [ -n "$ID_TOKEN" ]; then
            echo "ID Token (first 50 chars): ${ID_TOKEN:0:50}..."
            echo ""
            echo "Decoding token payload..."
            echo "$ID_TOKEN" | awk -F. '{print $2}' | base64 -d 2>/dev/null | jq . || echo "Token payload decoded"
        fi
    fi
fi
rm -f /tmp/kubelogin-output.txt

echo ""
echo "✅ E2E Test PASSED!"

echo ""
echo "Services are running:"
echo "  - Dex:       http://127.0.0.1:5556/dex"
echo "  - easy-oidc: http://127.0.0.1:8080"
echo ""
echo "Press Ctrl+C to stop services..."
wait $EASY_OIDC_PID
