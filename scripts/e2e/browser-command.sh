#!/usr/bin/env bash
# Truster <https://truster.dev>
# Copyright The Truster Authors
# SPDX-License-Identifier: Apache-2.0
# Completes kubelogin authentication interactively or through Dex headlessly.

set -euo pipefail

if [ "${E2E_HEADLESS:-false}" = true ]; then
    auth_url="$(curl -fsSL -o /dev/null -w '%{url_effective}' "$1")"
    case "$auth_url" in
        *\?*) separator='&' ;;
        *) separator='?' ;;
    esac
    response="$(mktemp)"
    trap 'rm -f "$response"' EXIT
    status="$(curl -sSL -o "$response" -w '%{http_code} %{url_effective}' "${auth_url}${separator}connector_id=mock")"
    if [ "${status%% *}" -lt 200 ] || [ "${status%% *}" -ge 300 ]; then
        echo "Headless browser flow failed: HTTP $status" >&2
        cat "$response" >&2
        exit 1
    fi
    exit
fi

echo "Open this URL to complete the E2E login:"
echo "$1"
open "$1"
