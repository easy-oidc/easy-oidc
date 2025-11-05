#!/bin/bash
# Copyright 2025 Nadrama Pty Ltd
# SPDX-License-Identifier: Apache-2.0

set -e

echo "Generating Ed25519 private key..."
openssl genpkey -algorithm ed25519

echo ""
echo "Key generated! Store this in AWS Secrets Manager, GCP Secret Manager, or Azure Key Vault."
