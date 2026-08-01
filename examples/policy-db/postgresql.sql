-- Easy OIDC <https://easy-oidc.dev>
-- Copyright The Easy OIDC Authors
-- SPDX-License-Identifier: Apache-2.0

-- Default schema for the PostgreSQL policy database driver.

BEGIN;

CREATE SCHEMA IF NOT EXISTS easy_oidc_policy;

CREATE TABLE IF NOT EXISTS easy_oidc_policy.clients (
    client_id text PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS easy_oidc_policy.users (
    client_id text NOT NULL REFERENCES easy_oidc_policy.clients (client_id) ON DELETE CASCADE,
    subject text NOT NULL CHECK (subject = lower(subject)),
    groups text[] NOT NULL DEFAULT ARRAY[]::text[],
    PRIMARY KEY (client_id, subject)
);

CREATE TABLE IF NOT EXISTS easy_oidc_policy.trust_bindings (
    client_id text NOT NULL REFERENCES easy_oidc_policy.clients (client_id) ON DELETE CASCADE,
    issuer_id text NOT NULL,
    binding_id text NOT NULL,
    subject text NOT NULL CHECK (subject LIKE 'trusted:%'),
    required_claims jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(required_claims) = 'object'),
    policy_claims jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(policy_claims) = 'object'),
    binding_claims jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(binding_claims) = 'object'),
    groups text[] NOT NULL DEFAULT ARRAY[]::text[],
    PRIMARY KEY (client_id, issuer_id, binding_id)
);

COMMIT;
