#!/usr/bin/env bash
# Easy OIDC <https://easy-oidc.dev>
# Copyright The Easy OIDC Authors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DEX_IMAGE="ghcr.io/dexidp/dex@sha256:8499afd690c437f52301efd2b05b2455da5bd2dfc20332cd697dc9937f808462" # v2.45.1

echo "==> Checking prerequisites..."
for cmd in curl jq make go kubectl openssl; do
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
    "$DEX_IMAGE"

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
export EASYOIDC_SIGNING_KEY="$(openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 2>/dev/null)"
export EASYOIDC_OAUTH_CLIENT_ID="easy-oidc-e2e"
export EASYOIDC_OAUTH_CLIENT_SECRET="unused-e2e-secret"

./bin/easy-oidc --config "$SCRIPT_DIR/easy-oidc-config.jsonc" --debug &
EASY_OIDC_PID=$!

echo "==> Waiting for easy-oidc to be ready..."
for i in {1..30}; do
    if curl -s http://127.0.0.1:8080/.well-known/openid-configuration > /dev/null 2>&1; then
        echo "==> easy-oidc is ready!"
        break
    fi
    if ! kill -0 "$EASY_OIDC_PID" 2>/dev/null; then
        wait "$EASY_OIDC_PID" 2>/dev/null || true
        echo "ERROR: easy-oidc exited before becoming ready"
        exit 1
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

kubectl oidc-login setup \
    --oidc-issuer-url=http://127.0.0.1:8080 \
    --oidc-client-id=e2e-test-client \
    --oidc-use-pkce \
    --listen-address=127.0.0.1:18000

echo ""
echo "✅ ID token received and validated by kubelogin. The decoded claims are shown above."
echo ""
echo "✅ E2E Test PASSED!"
