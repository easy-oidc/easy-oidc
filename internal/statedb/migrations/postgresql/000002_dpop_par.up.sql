-- Easy OIDC <https://easy-oidc.dev>
-- Copyright The Easy OIDC Authors
-- SPDX-License-Identifier: Apache-2.0

BEGIN;
SET search_path TO easy_oidc_state, public;
ALTER TABLE oauth_states ADD COLUMN dpop_jkt text;
ALTER TABLE auth_codes ADD COLUMN dpop_jkt text;
ALTER TABLE oauth_states ADD COLUMN pushed_authorization boolean NOT NULL DEFAULT false;
ALTER TABLE auth_codes ADD COLUMN pushed_authorization boolean NOT NULL DEFAULT false;
CREATE TABLE pushed_requests (
 request_uri text PRIMARY KEY, client_id text NOT NULL, redirect_uri text NOT NULL, response_type text NOT NULL,
 scopes text NOT NULL, oidc_state text NOT NULL, nonce text, code_challenge text NOT NULL,
 code_challenge_method text NOT NULL, prompt text, dpop_jkt text,
 created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL
);
CREATE INDEX idx_pushed_requests_expiry ON pushed_requests(expires_at);
COMMIT;
