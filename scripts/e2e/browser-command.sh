#!/usr/bin/env bash
# Easy OIDC <https://easy-oidc.dev>
# Copyright The Easy OIDC Authors
# SPDX-License-Identifier: Apache-2.0
# Completes kubelogin authentication interactively or through Dex headlessly.

set -euo pipefail

if [ "${E2E_HEADLESS:-false}" = true ]; then
    auth_url="$(curl -fsSL -o /dev/null -w '%{url_effective}' "$1")"
    case "$auth_url" in
        *\?*) separator='&' ;;
        *) separator='?' ;;
    esac
    curl -fsSL "${auth_url}${separator}connector_id=mock" > /dev/null
    exit
fi

echo "Open this URL to complete the E2E login:"
echo "$1"
open "$1"
