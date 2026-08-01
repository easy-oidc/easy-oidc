#!/usr/bin/env bash
# Easy OIDC <https://easy-oidc.dev>
# Copyright The Easy OIDC Authors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DEX_IMAGE="ghcr.io/dexidp/dex@sha256:8499afd690c437f52301efd2b05b2455da5bd2dfc20332cd697dc9937f808462" # v2.45.1
POSTGRES_IMAGE="docker.io/library/postgres@sha256:6567bca8d7bc8c82c5922425a0baee57be8402df92bae5eacad5f01ae9544daa" # 17.5-alpine3.22
DEX_CONTAINER_NAME="easy-oidc-e2e-dex"
POSTGRES_CONTAINER_NAME="easy-oidc-e2e-postgres"
DEX_ISSUER="http://127.0.0.1:5556/dex"
DEX_SUBJECT="CiQwOGE4Njg0Yi1kYjg4LTRiNzMtOTBhOS0zY2QxNjYxZjU0NjYSBWxvY2Fs"
EASY_OIDC_ISSUER="http://127.0.0.1:18080"
EASY_OIDC_TOKEN_URL="$EASY_OIDC_ISSUER/token"
EASY_OIDC_LISTEN_ADDRESS="127.0.0.1:18000"
STATIC_TRUST_CLIENT_ID="static-ci-token-exchange-e2e"
STATIC_TRUST_CLIENT_SECRET="static-ci-token-exchange-e2e-secret"
STATIC_INTERACTIVE_CLIENT_ID="static-kubelogin-interactive-e2e"
DB_TRUST_CLIENT_ID="db-ci-token-exchange-e2e"
DB_TRUST_CLIENT_SECRET="db-ci-token-exchange-e2e-secret"
DB_TRUST_BINDING_ID="db-dex-ci-exchange-e2e"
DB_INTERACTIVE_CLIENT_ID="db-kubelogin-interactive-e2e"
ID_TOKEN_TYPE="urn:ietf:params:oauth:token-type:id_token"
JWT_PAYLOAD_FILTER='split(".")[1] | gsub("-"; "+") | gsub("_"; "/") | . + ("=" * ((4 - (length % 4)) % 4)) | @base64d | fromjson'

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

remove_test_containers() {
    $CONTAINER_CMD stop "$DEX_CONTAINER_NAME" 2>/dev/null || true
    $CONTAINER_CMD rm "$DEX_CONTAINER_NAME" 2>/dev/null || true
    $CONTAINER_CMD stop "$POSTGRES_CONTAINER_NAME" 2>/dev/null || true
    $CONTAINER_CMD rm "$POSTGRES_CONTAINER_NAME" 2>/dev/null || true
}

cleanup() {
    echo "==> Cleaning up..."
    remove_test_containers
    if [ -n "${EASY_OIDC_PID:-}" ]; then
        kill "$EASY_OIDC_PID" 2>/dev/null || true
    fi
    if [ -n "${E2E_TEMP_DIR:-}" ]; then
        rm -rf "$E2E_TEMP_DIR"
    fi
}

kubelogin_get_token() {
    local client_id="$1"
    local cache_dir="$2"
    local output_file="$3"
    local mode="$4"
    local -a mode_args

    case "$mode" in
        interactive)
            mode_args=(--browser-command="$BROWSER_COMMAND" --authentication-timeout-sec=300)
            ;;
        refresh)
            mode_args=(--skip-open-browser --authentication-timeout-sec=10)
            ;;
        *)
            echo "ERROR: Unknown kubelogin mode '$mode'"
            return 1
            ;;
    esac

    kubectl oidc-login get-token \
        --oidc-issuer-url="$EASY_OIDC_ISSUER" \
        --oidc-client-id="$client_id" \
        --oidc-use-pkce \
        --listen-address="$EASY_OIDC_LISTEN_ADDRESS" \
        --token-cache-dir="$cache_dir" \
        "${mode_args[@]}" > "$output_file"
}

trap cleanup EXIT INT TERM

echo "==> Cleaning up any existing test containers..."
remove_test_containers

echo "==> Starting PostgreSQL policy database container..."
$CONTAINER_CMD run -d --rm --name "$POSTGRES_CONTAINER_NAME" -p 55434:5432 \
    -e POSTGRES_PASSWORD=e2e-admin -e POSTGRES_DB=easy_oidc_e2e "$POSTGRES_IMAGE"
for i in {1..30}; do
    if $CONTAINER_CMD exec "$POSTGRES_CONTAINER_NAME" pg_isready -U postgres -d easy_oidc_e2e >/dev/null 2>&1; then break; fi
    if [ "$i" -eq 30 ]; then echo "ERROR: PostgreSQL failed to start"; exit 1; fi
    sleep 1
done
$CONTAINER_CMD exec -i "$POSTGRES_CONTAINER_NAME" psql -v ON_ERROR_STOP=1 \
    -U postgres -d easy_oidc_e2e >/dev/null < "$PROJECT_ROOT/examples/policy-db/postgresql.sql"
$CONTAINER_CMD exec -i "$POSTGRES_CONTAINER_NAME" psql -v ON_ERROR_STOP=1 \
    -v db_interactive_client_id="$DB_INTERACTIVE_CLIENT_ID" \
    -v db_trust_client_id="$DB_TRUST_CLIENT_ID" \
    -v db_trust_binding_id="$DB_TRUST_BINDING_ID" \
    -v dex_subject="$DEX_SUBJECT" \
    -U postgres -d easy_oidc_e2e >/dev/null <<'SQL'
CREATE ROLE easy_oidc_policy LOGIN PASSWORD 'e2e-read-only';
INSERT INTO easy_oidc_policy.clients VALUES (:'db_interactive_client_id'), (:'db_trust_client_id');
-- Dex's mockCallback connector returns this fixed, non-configurable identity.
INSERT INTO easy_oidc_policy.users VALUES (:'db_interactive_client_id', 'kilgore@kilgore.trout', ARRAY['admins','developers']);
INSERT INTO easy_oidc_policy.trust_bindings VALUES (:'db_trust_client_id','dex',:'db_trust_binding_id','trusted:e2e:ci', jsonb_build_object('sub', jsonb_build_object('const', :'dex_subject')),'{}','{}',ARRAY['e2e:ci']);
GRANT CONNECT ON DATABASE easy_oidc_e2e TO easy_oidc_policy;
GRANT USAGE ON SCHEMA easy_oidc_policy TO easy_oidc_policy;
GRANT SELECT ON ALL TABLES IN SCHEMA easy_oidc_policy TO easy_oidc_policy;
ALTER ROLE easy_oidc_policy SET default_transaction_read_only = on;
SQL

echo "==> Starting Dex container..."
$CONTAINER_CMD run -d --rm --name "$DEX_CONTAINER_NAME" \
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
export EASYOIDC_POLICY_DB_URL='postgresql://easy_oidc_policy:e2e-read-only@127.0.0.1:55434/easy_oidc_e2e?sslmode=disable'
E2E_TEMP_DIR="$(mktemp -d)"
EASY_OIDC_LOG="$E2E_TEMP_DIR/easy-oidc.log"
BROWSER_COMMAND="$E2E_TEMP_DIR/open-browser"
# See README.md for sequence diagrams of both E2E login flows.
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
    if curl -s "$EASY_OIDC_ISSUER/.well-known/openid-configuration" > /dev/null 2>&1; then
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
if ! curl -sf "$EASY_OIDC_ISSUER/.well-known/openid-configuration" | jq . > /dev/null; then
    curl -sS -i "$EASY_OIDC_ISSUER/.well-known/openid-configuration" || true
    cat "$EASY_OIDC_LOG"
    echo "ERROR: Failed to get OIDC discovery document"
    exit 1
fi

echo "==> Testing JWKS endpoint..."
if ! curl -sf "$EASY_OIDC_ISSUER/jwks" | jq . > /dev/null; then
    echo "ERROR: Failed to get JWKS"
    exit 1
fi

echo "==> Testing statically configured OIDC federation..."
STATIC_DEX_TOKEN_RESPONSE="$E2E_TEMP_DIR/static-dex-token-response.json"
STATIC_DEX_TOKEN_STATUS="$(curl -sS -o "$STATIC_DEX_TOKEN_RESPONSE" -w '%{http_code}' \
    -u "$STATIC_TRUST_CLIENT_ID:$STATIC_TRUST_CLIENT_SECRET" \
    --data-urlencode grant_type=password \
    --data-urlencode username=test@example.com \
    --data-urlencode password=easy-oidc-e2e-password \
    --data-urlencode 'scope=openid email' \
    "$DEX_ISSUER/token")"
if [ "$STATIC_DEX_TOKEN_STATUS" != 200 ]; then
    echo "ERROR: Dex did not issue the static federation test token (HTTP $STATIC_DEX_TOKEN_STATUS)"
    exit 1
fi
STATIC_DEX_ID_TOKEN="$(jq -er '.id_token | select(type == "string" and length > 0)' "$STATIC_DEX_TOKEN_RESPONSE")"
STATIC_DEX_TOKEN_FILE="$E2E_TEMP_DIR/static-dex-id-token"
printf '%s' "$STATIC_DEX_ID_TOKEN" > "$STATIC_DEX_TOKEN_FILE"
chmod 600 "$STATIC_DEX_TOKEN_FILE"

if ! "$PROJECT_ROOT/bin/easy-oidc" check trust --config "$SCRIPT_DIR/easy-oidc-config.jsonc" --client-id "$STATIC_TRUST_CLIENT_ID" --token-file "$STATIC_DEX_TOKEN_FILE" > /dev/null; then
    echo "ERROR: easy-oidc check trust rejected the static client token"
    exit 1
fi

STATIC_EXCHANGE_RESPONSE="$E2E_TEMP_DIR/static-token-exchange-response.json"
STATIC_EXCHANGE_STATUS="$(curl -sS -o "$STATIC_EXCHANGE_RESPONSE" -w '%{http_code}' \
    --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
    --data-urlencode "client_id=$STATIC_TRUST_CLIENT_ID" \
    --data-urlencode "subject_token=$STATIC_DEX_ID_TOKEN" \
    --data-urlencode "subject_token_type=$ID_TOKEN_TYPE" \
    --data-urlencode "requested_token_type=$ID_TOKEN_TYPE" \
    "$EASY_OIDC_TOKEN_URL")"
unset STATIC_DEX_ID_TOKEN
if [ "$STATIC_EXCHANGE_STATUS" != 200 ] || ! jq -e --arg audience "$STATIC_TRUST_CLIENT_ID" --arg issuer "$DEX_ISSUER" --arg subject "$DEX_SUBJECT" '
    .access_token |
    '"$JWT_PAYLOAD_FILTER"' |
    .sub == "trusted:e2e:static" and
    .aud == [$audience] and
    .groups == ["e2e:static"] and
    .upstream_issuer == $issuer and
    .upstream_subject == $subject
' "$STATIC_EXCHANGE_RESPONSE" > /dev/null; then
    echo "ERROR: static OIDC federation returned unexpected claims"
    exit 1
fi
echo "✅ Static trust policy and binding minted the expected service token."

echo "==> Testing static client, group override, and refresh with kubelogin..."
STATIC_TOKEN_CACHE_DIR="$E2E_TEMP_DIR/static-cache"
STATIC_FIRST_TOKEN="$E2E_TEMP_DIR/static-first.json"
STATIC_SECOND_TOKEN="$E2E_TEMP_DIR/static-second.json"
mkdir -p "$STATIC_TOKEN_CACHE_DIR"
kubelogin_get_token "$STATIC_INTERACTIVE_CLIENT_ID" "$STATIC_TOKEN_CACHE_DIR" "$STATIC_FIRST_TOKEN" interactive

if ! jq -er '
    .status.token |
    '"$JWT_PAYLOAD_FILTER"' |
    .groups == ["static-admins", "static-developers"]
' "$STATIC_FIRST_TOKEN" >/dev/null; then
    echo "ERROR: static client ID token did not contain configured group overrides"
    exit 1
fi

sleep 6
kubelogin_get_token "$STATIC_INTERACTIVE_CLIENT_ID" "$STATIC_TOKEN_CACHE_DIR" "$STATIC_SECOND_TOKEN" refresh

if [ "$(jq -r '.status.token // empty' "$STATIC_FIRST_TOKEN")" = "$(jq -r '.status.token // empty' "$STATIC_SECOND_TOKEN")" ]; then
    echo "ERROR: static client refresh did not return a fresh ID token"
    exit 1
fi
if ! jq -er '
    .status.token |
    '"$JWT_PAYLOAD_FILTER"' |
    .groups == ["static-admins", "static-developers"]
' "$STATIC_SECOND_TOKEN" >/dev/null; then
    echo "ERROR: refreshed static client token did not preserve configured group overrides"
    exit 1
fi
if ! jq -s -e --arg client "$STATIC_INTERACTIVE_CLIENT_ID" 'any(.[]; .msg == "refresh attempt" and .result == 200 and .client_id == $client)' "$EASY_OIDC_LOG" > /dev/null; then
    cat "$EASY_OIDC_LOG"
    echo "ERROR: no successful static client refresh exchange was logged"
    exit 1
fi
if jq -s -e --arg trust "$STATIC_TRUST_CLIENT_ID" --arg interactive "$STATIC_INTERACTIVE_CLIENT_ID" 'any(.[]; .msg == "policy database query" and (.client_id == $trust or .client_id == $interactive))' "$EASY_OIDC_LOG" > /dev/null; then
    cat "$EASY_OIDC_LOG"
    echo "ERROR: a statically configured client caused a policy database query"
    exit 1
fi
echo "✅ Static client group overrides and refresh succeeded without policy database queries."

echo "==> Testing trusted service login with database policy..."
DB_DEX_TOKEN_RESPONSE="$E2E_TEMP_DIR/db-dex-token-response.json"
DB_DEX_TOKEN_STATUS="$(curl -sS -o "$DB_DEX_TOKEN_RESPONSE" -w '%{http_code}' \
    -u "$DB_TRUST_CLIENT_ID:$DB_TRUST_CLIENT_SECRET" \
    --data-urlencode grant_type=password \
    --data-urlencode username=test@example.com \
    --data-urlencode password=easy-oidc-e2e-password \
    --data-urlencode 'scope=openid email' \
    "$DEX_ISSUER/token")"
if [ "$DB_DEX_TOKEN_STATUS" != 200 ]; then
    echo "ERROR: Dex did not issue the trusted service test token for the database policy flow (HTTP $DB_DEX_TOKEN_STATUS)"
    exit 1
fi
DB_DEX_ID_TOKEN="$(jq -er '.id_token | select(type == "string" and length > 0)' "$DB_DEX_TOKEN_RESPONSE")"
DB_DEX_TOKEN_FILE="$E2E_TEMP_DIR/db-dex-id-token"
printf '%s' "$DB_DEX_ID_TOKEN" > "$DB_DEX_TOKEN_FILE"
chmod 600 "$DB_DEX_TOKEN_FILE"

if ! "$PROJECT_ROOT/bin/easy-oidc" check trust --config "$SCRIPT_DIR/easy-oidc-config.jsonc" --client-id "$DB_TRUST_CLIENT_ID" --token-file "$DB_DEX_TOKEN_FILE" > /dev/null; then
    echo "ERROR: easy-oidc check trust rejected the client supplied by database policy"
    exit 1
fi

DB_EXCHANGE_RESPONSE="$E2E_TEMP_DIR/db-token-exchange-response.json"
DB_EXCHANGE_HEADERS="$E2E_TEMP_DIR/db-token-exchange-headers.txt"
DB_EXCHANGE_STATUS="$(curl -sS -D "$DB_EXCHANGE_HEADERS" -o "$DB_EXCHANGE_RESPONSE" -w '%{http_code}' \
    --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
    --data-urlencode "client_id=$DB_TRUST_CLIENT_ID" \
    --data-urlencode "subject_token=$DB_DEX_ID_TOKEN" \
    --data-urlencode "subject_token_type=$ID_TOKEN_TYPE" \
    --data-urlencode "requested_token_type=$ID_TOKEN_TYPE" \
    "$EASY_OIDC_TOKEN_URL")"
unset DB_DEX_ID_TOKEN
if [ "$DB_EXCHANGE_STATUS" != 200 ]; then
    cat "$EASY_OIDC_LOG"
    echo "ERROR: Easy OIDC rejected the trusted service login using database policy (HTTP $DB_EXCHANGE_STATUS)"
    exit 1
fi
if ! grep -Eiq '^cache-control:[[:space:]]*no-store\r?$' "$DB_EXCHANGE_HEADERS" ||
   ! grep -Eiq '^pragma:[[:space:]]*no-cache\r?$' "$DB_EXCHANGE_HEADERS"; then
    echo "ERROR: trusted service login using database policy is missing no-cache headers"
    exit 1
fi
if ! jq -e --arg token_type "$ID_TOKEN_TYPE" '
    (.access_token | type == "string" and length > 0) and
    .issued_token_type == $token_type and
    .token_type == "Bearer" and
    (.expires_in | type == "number" and . > 0 and . <= 900) and
    (has("id_token") | not) and
    (has("refresh_token") | not)
' "$DB_EXCHANGE_RESPONSE" > /dev/null; then
    echo "ERROR: trusted service login using database policy returned an invalid token response"
    exit 1
fi

DB_MINTED_TOKEN_PAYLOAD="$(jq -er '
    .access_token |
    '"$JWT_PAYLOAD_FILTER"'
' "$DB_EXCHANGE_RESPONSE")"
if ! jq -e \
    --arg audience "$DB_TRUST_CLIENT_ID" \
    --arg issuer "$DEX_ISSUER" \
    --arg subject "$DEX_SUBJECT" '
    .sub == "trusted:e2e:ci" and
    .aud == [$audience] and
    .groups == ["e2e:ci"] and
    .upstream_issuer == $issuer and
    .upstream_subject == $subject and
    (.jti | type == "string" and length > 0) and
    (has("sid") | not)
' <<< "$DB_MINTED_TOKEN_PAYLOAD" > /dev/null; then
    jq . <<< "$DB_MINTED_TOKEN_PAYLOAD"
    echo "ERROR: trusted service token produced with database policy contains unexpected claims"
    exit 1
fi
unset DB_MINTED_TOKEN_PAYLOAD
echo "✅ Database policy supplied the expected trusted service token."

echo "==> Mutating the live policy database trust binding and exchanging again..."
$CONTAINER_CMD exec -i "$POSTGRES_CONTAINER_NAME" psql -v ON_ERROR_STOP=1 \
    -v db_trust_binding_id="$DB_TRUST_BINDING_ID" -U postgres -d easy_oidc_e2e >/dev/null <<'SQL'
UPDATE easy_oidc_policy.trust_bindings SET subject='trusted:e2e:changed', groups=ARRAY['e2e:changed'] WHERE binding_id=:'db_trust_binding_id';
SQL
DB_MUTATED_EXCHANGE_RESPONSE="$E2E_TEMP_DIR/db-mutated-exchange-response.json"
DB_MUTATED_EXCHANGE_STATUS="$(curl -sS -o "$DB_MUTATED_EXCHANGE_RESPONSE" -w '%{http_code}' \
    --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
    --data-urlencode "client_id=$DB_TRUST_CLIENT_ID" \
    --data-urlencode "subject_token=$(cat "$DB_DEX_TOKEN_FILE")" \
    --data-urlencode "subject_token_type=$ID_TOKEN_TYPE" \
    --data-urlencode "requested_token_type=$ID_TOKEN_TYPE" "$EASY_OIDC_TOKEN_URL")"
if [ "$DB_MUTATED_EXCHANGE_STATUS" != 200 ] || ! jq -e '
    .access_token |
    '"$JWT_PAYLOAD_FILTER"' |
    .sub == "trusted:e2e:changed" and
    .groups == ["e2e:changed"]
' "$DB_MUTATED_EXCHANGE_RESPONSE" >/dev/null; then
    echo "ERROR: changed database policy trust output was not applied"
    exit 1
fi

echo "==> Testing OIDC login and refresh with database policy..."
printf '\nOpening browser for OIDC authentication...\n'
printf 'Please complete the login in your browser (use Dex mock login)\n\n'

DB_TOKEN_CACHE_DIR="$E2E_TEMP_DIR/db-cache"
DB_FIRST_TOKEN="$E2E_TEMP_DIR/db-first.json"
DB_SECOND_TOKEN="$E2E_TEMP_DIR/db-second.json"
mkdir -p "$DB_TOKEN_CACHE_DIR"
kubelogin_get_token "$DB_INTERACTIVE_CLIENT_ID" "$DB_TOKEN_CACHE_DIR" "$DB_FIRST_TOKEN" interactive

if ! jq -er '
    .status.token |
    '"$JWT_PAYLOAD_FILTER"' |
    .groups == ["admins", "developers"]
' "$DB_FIRST_TOKEN" >/dev/null; then
    echo "ERROR: ID token for a client supplied by database policy did not contain initial groups"
    exit 1
fi

echo "==> Waiting for the initial ID token to expire..."
sleep 6

echo "==> Updating live user groups in the policy database before refresh..."
$CONTAINER_CMD exec -i "$POSTGRES_CONTAINER_NAME" psql -v ON_ERROR_STOP=1 \
    -v db_interactive_client_id="$DB_INTERACTIVE_CLIENT_ID" -U postgres -d easy_oidc_e2e >/dev/null <<'SQL'
UPDATE easy_oidc_policy.users SET groups=ARRAY['current-on-refresh'] WHERE client_id=:'db_interactive_client_id';
SQL

echo "==> Refreshing without opening a browser..."
kubelogin_get_token "$DB_INTERACTIVE_CLIENT_ID" "$DB_TOKEN_CACHE_DIR" "$DB_SECOND_TOKEN" refresh

if [ "$(jq -r '.status.token // empty' "$DB_FIRST_TOKEN")" = "$(jq -r '.status.token // empty' "$DB_SECOND_TOKEN")" ]; then
    echo "ERROR: kubelogin did not return a fresh ID token"
    exit 1
fi
if ! jq -er '
    .status.token |
    '"$JWT_PAYLOAD_FILTER"' |
    .groups == ["current-on-refresh"]
' "$DB_SECOND_TOKEN" >/dev/null; then
    echo "ERROR: refreshed ID token did not contain current database policy groups"
    exit 1
fi
if ! jq -s -e --arg client "$DB_INTERACTIVE_CLIENT_ID" 'any(.[]; .msg == "refresh attempt" and .result == 200 and .client_id == $client)' "$EASY_OIDC_LOG" > /dev/null; then
    cat "$EASY_OIDC_LOG"
    echo "ERROR: no successful kubelogin refresh exchange was logged"
    exit 1
fi

printf '\n✅ ID token received and refreshed by kubelogin without another browser login.\n'
printf '\n✅ E2E Test PASSED!\n'
