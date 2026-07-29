#!/usr/bin/env bash
# Easy OIDC <https://easy-oidc.dev>
# Copyright The Easy OIDC Authors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DEX_IMAGE="ghcr.io/dexidp/dex@sha256:8499afd690c437f52301efd2b05b2455da5bd2dfc20332cd697dc9937f808462" # v2.45.1
DEX_ISSUER="http://127.0.0.1:5556/dex"
DEX_SUBJECT="CiQwOGE4Njg0Yi1kYjg4LTRiNzMtOTBhOS0zY2QxNjYxZjU0NjYSBWxvY2Fs"
TRUST_CLIENT_ID="ci-token-exchange-e2e"
ID_TOKEN_TYPE="urn:ietf:params:oauth:token-type:id_token"

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
    if [ -n "${E2E_TEMP_DIR:-}" ]; then
        rm -rf "$E2E_TEMP_DIR"
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
export EASYOIDC_ENCRYPTION_KEY="$(openssl rand -hex 32)"
export EASYOIDC_DEX_CREDENTIALS='{"client_id":"easy-oidc-interactive-e2e","client_secret":"easy-oidc-interactive-e2e-secret"}'
E2E_TEMP_DIR="$(mktemp -d)"
EASY_OIDC_LOG="$E2E_TEMP_DIR/easy-oidc.log"
TOKEN_CACHE_DIR="$E2E_TEMP_DIR/cache"
BROWSER_COMMAND="$E2E_TEMP_DIR/open-browser"
# See README.md for sequence diagrams of both E2E login flows.
mkdir -p "$TOKEN_CACHE_DIR"
cat > "$BROWSER_COMMAND" <<'EOF'
#!/usr/bin/env bash
echo "Open this URL to complete the E2E login:"
echo "$1"
open "$1"
EOF
chmod +x "$BROWSER_COMMAND"

(
    cd "$E2E_TEMP_DIR"
    exec "$PROJECT_ROOT/bin/easy-oidc" --config "$SCRIPT_DIR/easy-oidc-config.jsonc" --debug
) > "$EASY_OIDC_LOG" 2>&1 &
EASY_OIDC_PID=$!

echo "==> Waiting for easy-oidc to be ready..."
for i in {1..30}; do
    if curl -s http://127.0.0.1:8080/.well-known/openid-configuration > /dev/null 2>&1; then
        echo "==> easy-oidc is ready!"
        break
    fi
    if ! kill -0 "$EASY_OIDC_PID" 2>/dev/null; then
        wait "$EASY_OIDC_PID" 2>/dev/null || true
        cat "$EASY_OIDC_LOG"
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

echo "==> Testing trusted service login..."
DEX_TOKEN_RESPONSE="$E2E_TEMP_DIR/dex-token-response.json"
DEX_TOKEN_STATUS="$(curl -sS -o "$DEX_TOKEN_RESPONSE" -w '%{http_code}' \
    -u "$TRUST_CLIENT_ID:ci-token-exchange-e2e-secret" \
    --data-urlencode grant_type=password \
    --data-urlencode username=test@example.com \
    --data-urlencode password=easy-oidc-e2e-password \
    --data-urlencode 'scope=openid email' \
    "$DEX_ISSUER/token")"
if [ "$DEX_TOKEN_STATUS" != 200 ]; then
    echo "ERROR: Dex did not issue the trusted service test token (HTTP $DEX_TOKEN_STATUS)"
    exit 1
fi
DEX_ID_TOKEN="$(jq -er '.id_token | select(type == "string" and length > 0)' "$DEX_TOKEN_RESPONSE")"

EXCHANGE_RESPONSE="$E2E_TEMP_DIR/token-exchange-response.json"
EXCHANGE_HEADERS="$E2E_TEMP_DIR/token-exchange-headers.txt"
EXCHANGE_STATUS="$(curl -sS -D "$EXCHANGE_HEADERS" -o "$EXCHANGE_RESPONSE" -w '%{http_code}' \
    --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
    --data-urlencode "client_id=$TRUST_CLIENT_ID" \
    --data-urlencode "subject_token=$DEX_ID_TOKEN" \
    --data-urlencode "subject_token_type=$ID_TOKEN_TYPE" \
    --data-urlencode "requested_token_type=$ID_TOKEN_TYPE" \
    http://127.0.0.1:8080/token)"
unset DEX_ID_TOKEN
if [ "$EXCHANGE_STATUS" != 200 ]; then
    cat "$EASY_OIDC_LOG"
    echo "ERROR: Easy OIDC rejected the trusted service login (HTTP $EXCHANGE_STATUS)"
    exit 1
fi
if ! grep -Eiq '^cache-control:[[:space:]]*no-store\r?$' "$EXCHANGE_HEADERS" ||
   ! grep -Eiq '^pragma:[[:space:]]*no-cache\r?$' "$EXCHANGE_HEADERS"; then
    echo "ERROR: Trusted service login response is missing no-cache headers"
    exit 1
fi
if ! jq -e --arg token_type "$ID_TOKEN_TYPE" '
    (.access_token | type == "string" and length > 0) and
    .issued_token_type == $token_type and
    .token_type == "Bearer" and
    (.expires_in | type == "number" and . > 0 and . <= 900) and
    (has("id_token") | not) and
    (has("refresh_token") | not)
' "$EXCHANGE_RESPONSE" > /dev/null; then
    echo "ERROR: Trusted service login returned an invalid token response"
    exit 1
fi

MINTED_TOKEN_PAYLOAD="$(jq -er '
    .access_token | split(".")[1] |
    gsub("-"; "+") | gsub("_"; "/") |
    . + ("=" * ((4 - (length % 4)) % 4)) |
    @base64d | fromjson
' "$EXCHANGE_RESPONSE")"
if ! jq -e \
    --arg audience "$TRUST_CLIENT_ID" \
    --arg issuer "$DEX_ISSUER" \
    --arg subject "$DEX_SUBJECT" '
    .sub == "trusted:e2e:ci" and
    .aud == [$audience] and
    .groups == ["e2e:ci"] and
    .upstream_issuer == $issuer and
    .upstream_subject == $subject and
    (.jti | type == "string" and length > 0) and
    (has("sid") | not)
' <<< "$MINTED_TOKEN_PAYLOAD" > /dev/null; then
    jq . <<< "$MINTED_TOKEN_PAYLOAD"
    echo "ERROR: Trusted service token contains unexpected claims"
    exit 1
fi
unset MINTED_TOKEN_PAYLOAD
echo "✅ Trusted service token minted from the Dex-issued OIDC token."

echo "==> Testing OIDC login and refresh with kubelogin..."
echo ""
echo "Opening browser for OIDC authentication..."
echo "Please complete the login in your browser (use Dex mock login)"
echo ""

FIRST_TOKEN="$E2E_TEMP_DIR/first.json"
SECOND_TOKEN="$E2E_TEMP_DIR/second.json"
kubectl oidc-login get-token \
    --oidc-issuer-url=http://127.0.0.1:8080 \
    --oidc-client-id=kubelogin-interactive-e2e \
    --oidc-use-pkce \
    --listen-address=127.0.0.1:18000 \
    --browser-command="$BROWSER_COMMAND" \
    --authentication-timeout-sec=300 \
    --token-cache-dir="$TOKEN_CACHE_DIR" > "$FIRST_TOKEN"

echo "==> Waiting for the initial ID token to expire..."
sleep 6

echo "==> Refreshing without opening a browser..."
kubectl oidc-login get-token \
    --oidc-issuer-url=http://127.0.0.1:8080 \
    --oidc-client-id=kubelogin-interactive-e2e \
    --oidc-use-pkce \
    --listen-address=127.0.0.1:18000 \
    --token-cache-dir="$TOKEN_CACHE_DIR" \
    --skip-open-browser \
    --authentication-timeout-sec=10 > "$SECOND_TOKEN"

if [ "$(jq -r '.status.token // empty' "$FIRST_TOKEN")" = "$(jq -r '.status.token // empty' "$SECOND_TOKEN")" ]; then
    echo "ERROR: kubelogin did not return a fresh ID token"
    exit 1
fi
if ! jq -s -e 'any(.[]; .msg == "refresh attempt" and .result == 200 and .client_id == "kubelogin-interactive-e2e")' "$EASY_OIDC_LOG" > /dev/null; then
    cat "$EASY_OIDC_LOG"
    echo "ERROR: no successful kubelogin refresh exchange was logged"
    exit 1
fi

echo ""
echo "✅ ID token received and refreshed by kubelogin without another browser login."
echo ""
echo "✅ E2E Test PASSED!"
