-- Easy OIDC <https://easy-oidc.dev>
-- Copyright The Easy OIDC Authors
-- SPDX-License-Identifier: Apache-2.0

BEGIN;
SET search_path TO easy_oidc_state, public;
CREATE TABLE dpop_proofs (
 replay_hash bytea PRIMARY KEY CHECK(octet_length(replay_hash)=32), expires_at timestamptz NOT NULL
);
CREATE INDEX idx_dpop_proofs_expiry ON dpop_proofs(expires_at);
COMMIT;
