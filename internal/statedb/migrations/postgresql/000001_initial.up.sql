-- Truster <https://truster.dev>
-- Copyright The Truster Authors
-- SPDX-License-Identifier: Apache-2.0

BEGIN; -- Initial state database schema.

CREATE SCHEMA IF NOT EXISTS truster_state;
SET search_path TO truster_state, public;

CREATE TABLE oauth_states (
    state_token text PRIMARY KEY,
    client_id text NOT NULL,
    redirect_uri text NOT NULL,
    code_challenge text NOT NULL,
    nonce text,
    oidc_state text NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    connector_id text NOT NULL DEFAULT '',
    scopes text NOT NULL,
    refresh_mode text NOT NULL,
    auth_time timestamptz NOT NULL,
    offline_consent boolean NOT NULL DEFAULT false,
    purpose text NOT NULL DEFAULT 'authorize',
    dpop_jkt text,
    pushed_authorization boolean NOT NULL DEFAULT false
);
CREATE INDEX idx_states_expires_at ON oauth_states(expires_at);
CREATE TABLE auth_codes (
    code text PRIMARY KEY,
    client_id text NOT NULL,
    redirect_uri text NOT NULL,
    code_challenge text NOT NULL,
    email text NOT NULL,
    email_verified boolean NOT NULL,
    nonce text,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    scopes text NOT NULL,
    refresh_mode text NOT NULL,
    auth_time timestamptz NOT NULL,
    connector_id text NOT NULL DEFAULT '',
    upstream_subject text NOT NULL DEFAULT '',
    offline_consent boolean NOT NULL DEFAULT false,
    dpop_jkt text,
    pushed_authorization boolean NOT NULL DEFAULT false
);
CREATE INDEX idx_codes_expires_at ON auth_codes(expires_at);
CREATE TABLE flow_credentials (
    flow_id text PRIMARY KEY, client_id text NOT NULL, connector_id text NOT NULL,
    nonce bytea NOT NULL, ciphertext bytea NOT NULL, expires_at timestamptz NOT NULL
);
CREATE INDEX idx_flow_credentials_expiry ON flow_credentials(expires_at);
CREATE TABLE upstream_credentials (
    connector_id text NOT NULL, subject text NOT NULL, email text NOT NULL,
    verified_at timestamptz NOT NULL, local_verified boolean NOT NULL DEFAULT false,
    PRIMARY KEY(connector_id, subject, email)
);
CREATE TABLE otp_challenges (
    challenge_id text PRIMARY KEY, email text NOT NULL, code_hmac bytea NOT NULL,
    context text NOT NULL, attempts integer NOT NULL DEFAULT 0, sends integer NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL, sent_at timestamptz NOT NULL, expires_at timestamptz NOT NULL
);
CREATE INDEX idx_otp_challenges_expiry ON otp_challenges(expires_at);
CREATE TABLE otp_sends (email text NOT NULL, sent_at timestamptz NOT NULL);
CREATE INDEX idx_otp_sends_email_time ON otp_sends(email,sent_at);
CREATE TABLE refresh_grants (
    sid text PRIMARY KEY, client_id text NOT NULL, email text NOT NULL, email_verified boolean NOT NULL,
    scopes text NOT NULL, connector_id text, upstream_subject text, credential_nonce bytea,
    credential_ciphertext bytea, mode text NOT NULL CHECK(mode IN ('session','offline')),
    auth_time timestamptz NOT NULL, created_at timestamptz NOT NULL, last_used_at timestamptz NOT NULL,
    idle_ttl_ns bigint NOT NULL, idle_expires_at timestamptz NOT NULL, absolute_expires_at timestamptz NOT NULL,
    revoked_at timestamptz, revoke_reason text, upstream_access_expires_at timestamptz,
    upstream_refresh_expires_at timestamptz, upstream_access_nonexpiring boolean NOT NULL DEFAULT false,
    claim_id text, claim_expires_at timestamptz, upstream_refresh_started boolean NOT NULL DEFAULT false,
    dpop_jkt text
);
CREATE INDEX idx_refresh_grants_email ON refresh_grants(email,absolute_expires_at);
CREATE INDEX idx_refresh_grants_expiry ON refresh_grants(absolute_expires_at);
CREATE TABLE refresh_tokens (
    handle_hash bytea PRIMARY KEY, token_hash bytea NOT NULL,
    sid text NOT NULL REFERENCES refresh_grants(sid) ON DELETE CASCADE,
    issued_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
    consumed_at timestamptz, replacement_hash bytea
);
CREATE INDEX idx_refresh_tokens_sid ON refresh_tokens(sid);
CREATE TABLE grant_actions (
    action_hash bytea PRIMARY KEY, email text NOT NULL,
    sid text NOT NULL REFERENCES refresh_grants(sid) ON DELETE CASCADE,
    action text NOT NULL, created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL
);
CREATE INDEX idx_grant_actions_expiry ON grant_actions(expires_at);
CREATE TABLE identity_selections (
    token_hash bytea PRIMARY KEY, state_token text NOT NULL, connector_id text NOT NULL,
    subject text NOT NULL, emails_json text NOT NULL, expires_at timestamptz NOT NULL
);
CREATE INDEX idx_identity_selections_expiry ON identity_selections(expires_at);
CREATE TABLE pushed_requests (
    request_uri text PRIMARY KEY, client_id text NOT NULL, redirect_uri text NOT NULL,
    response_type text NOT NULL, scopes text NOT NULL, oidc_state text NOT NULL,
    nonce text, code_challenge text NOT NULL, code_challenge_method text NOT NULL,
    prompt text, dpop_jkt text, created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL
);
CREATE INDEX idx_pushed_requests_expiry ON pushed_requests(expires_at);

COMMIT;
