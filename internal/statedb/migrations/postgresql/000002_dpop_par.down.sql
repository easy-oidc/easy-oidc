-- Easy OIDC <https://easy-oidc.dev>
-- Copyright The Easy OIDC Authors
-- SPDX-License-Identifier: Apache-2.0

BEGIN;
SET search_path TO easy_oidc_state, public;
DROP TABLE pushed_requests;
ALTER TABLE auth_codes DROP COLUMN pushed_authorization;
ALTER TABLE oauth_states DROP COLUMN pushed_authorization;
ALTER TABLE auth_codes DROP COLUMN dpop_jkt;
ALTER TABLE oauth_states DROP COLUMN dpop_jkt;
COMMIT;
