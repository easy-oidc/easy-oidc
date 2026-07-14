#!/bin/bash
# Easy OIDC <https://easy-oidc.dev>
# Copyright The Easy OIDC Authors
# SPDX-License-Identifier: Apache-2.0

set -e

echo "Generating RSA-3072 private key for RS256 signing..." >&2
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072

echo "" >&2
echo "Key generated! Store this in AWS Secrets Manager, GCP Secret Manager, or Azure Key Vault." >&2
