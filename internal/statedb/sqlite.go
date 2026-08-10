// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package statedb

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

// NewSQLite opens an initialized SQLite state database.
func NewSQLite(dbPath string, logger *slog.Logger) (*Store, error) {
	dsn := dbPath
	if dbPath != ":memory:" {
		dsn = "file:" + url.PathEscape(dbPath)
	}
	separator := "?"
	if strings.Contains(dsn, "?") {
		separator = "&"
	}
	dsn += separator + "_foreign_keys=on&_busy_timeout=5000&_journal_mode=WAL&_synchronous=FULL&_txlock=immediate"
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	db.SetMaxOpenConns(8)

	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to enable WAL mode: %w", err)
	}
	for _, pragma := range []string{"PRAGMA synchronous=FULL", "PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000"} {
		if _, err := db.Exec(pragma); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("failed to configure SQLite durability: %w", err)
		}
	}
	if err := initSQLiteSchema(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	s := &Store{db: &database{raw: db}, logger: logger}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel, s.cleanupCtx, s.done = cancel, ctx, make(chan struct{})
	go s.cleanupExpired(ctx)
	return s, nil
}

// initSQLiteSchema creates the required SQLite tables.
func initSQLiteSchema(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS oauth_states (
		state_token TEXT PRIMARY KEY,
		client_id TEXT NOT NULL,
		redirect_uri TEXT NOT NULL,
		code_challenge TEXT NOT NULL,
		nonce TEXT,
		oidc_state TEXT NOT NULL,
		created_at DATETIME NOT NULL,
		expires_at DATETIME NOT NULL,
		connector_id TEXT NOT NULL DEFAULT '', scopes TEXT NOT NULL, refresh_mode TEXT NOT NULL, auth_time DATETIME NOT NULL, offline_consent INTEGER NOT NULL DEFAULT 0, purpose TEXT NOT NULL DEFAULT 'authorize', dpop_jkt TEXT, pushed_authorization INTEGER NOT NULL DEFAULT 0
	);

	CREATE INDEX IF NOT EXISTS idx_states_expires_at ON oauth_states(expires_at);

	CREATE TABLE IF NOT EXISTS auth_codes (
		code TEXT PRIMARY KEY,
		client_id TEXT NOT NULL,
		redirect_uri TEXT NOT NULL,
		code_challenge TEXT NOT NULL,
		email TEXT NOT NULL,
		email_verified INTEGER NOT NULL,
		nonce TEXT,
		created_at DATETIME NOT NULL,
		expires_at DATETIME NOT NULL,
		scopes TEXT NOT NULL, refresh_mode TEXT NOT NULL, auth_time DATETIME NOT NULL,
		connector_id TEXT NOT NULL DEFAULT '', upstream_subject TEXT NOT NULL DEFAULT '', offline_consent INTEGER NOT NULL DEFAULT 0, dpop_jkt TEXT, pushed_authorization INTEGER NOT NULL DEFAULT 0
	);

	CREATE INDEX IF NOT EXISTS idx_codes_expires_at ON auth_codes(expires_at);
	CREATE TABLE IF NOT EXISTS flow_credentials (
		flow_id TEXT PRIMARY KEY, client_id TEXT NOT NULL, connector_id TEXT NOT NULL,
		nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, expires_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_flow_credentials_expiry ON flow_credentials(expires_at);
	CREATE TABLE IF NOT EXISTS upstream_credentials (
		connector_id TEXT NOT NULL, subject TEXT NOT NULL, email TEXT NOT NULL,
		verified_at DATETIME NOT NULL, local_verified INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(connector_id, subject, email)
	);
	CREATE TABLE IF NOT EXISTS otp_challenges (
		challenge_id TEXT PRIMARY KEY, email TEXT NOT NULL, code_hmac BLOB NOT NULL,
		context TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, sends INTEGER NOT NULL DEFAULT 1,
		created_at DATETIME NOT NULL, sent_at DATETIME NOT NULL, expires_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_otp_challenges_expiry ON otp_challenges(expires_at);
	CREATE TABLE IF NOT EXISTS otp_sends (email TEXT NOT NULL, sent_at DATETIME NOT NULL);
	CREATE INDEX IF NOT EXISTS idx_otp_sends_email_time ON otp_sends(email, sent_at);
	CREATE TABLE IF NOT EXISTS refresh_grants (
		sid TEXT PRIMARY KEY, client_id TEXT NOT NULL, email TEXT NOT NULL, email_verified INTEGER NOT NULL,
		scopes TEXT NOT NULL, connector_id TEXT, upstream_subject TEXT, credential_nonce BLOB, credential_ciphertext BLOB,
		mode TEXT NOT NULL CHECK(mode IN ('session','offline')), auth_time DATETIME NOT NULL, created_at DATETIME NOT NULL,
		last_used_at DATETIME NOT NULL, idle_ttl_ns INTEGER NOT NULL, idle_expires_at DATETIME NOT NULL,
		absolute_expires_at DATETIME NOT NULL, revoked_at DATETIME, revoke_reason TEXT,
		upstream_access_expires_at DATETIME, upstream_refresh_expires_at DATETIME, upstream_access_nonexpiring INTEGER NOT NULL DEFAULT 0,
		claim_id TEXT, claim_expires_at DATETIME, upstream_refresh_started INTEGER NOT NULL DEFAULT 0, dpop_jkt TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_refresh_grants_email ON refresh_grants(email, absolute_expires_at);
	CREATE INDEX IF NOT EXISTS idx_refresh_grants_expiry ON refresh_grants(absolute_expires_at);
	CREATE TABLE IF NOT EXISTS refresh_tokens (
		handle_hash BLOB PRIMARY KEY, token_hash BLOB NOT NULL, sid TEXT NOT NULL REFERENCES refresh_grants(sid) ON DELETE CASCADE,
		issued_at DATETIME NOT NULL, expires_at DATETIME NOT NULL, consumed_at DATETIME, replacement_hash BLOB
	);
	CREATE INDEX IF NOT EXISTS idx_refresh_tokens_sid ON refresh_tokens(sid);
	CREATE TABLE IF NOT EXISTS grant_actions (
		action_hash BLOB PRIMARY KEY, email TEXT NOT NULL, sid TEXT NOT NULL REFERENCES refresh_grants(sid) ON DELETE CASCADE,
		action TEXT NOT NULL, created_at DATETIME NOT NULL, expires_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_grant_actions_expiry ON grant_actions(expires_at);
	CREATE TABLE IF NOT EXISTS identity_selections (
		token_hash BLOB PRIMARY KEY, state_token TEXT NOT NULL, connector_id TEXT NOT NULL,
		subject TEXT NOT NULL, emails_json TEXT NOT NULL, expires_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_identity_selections_expiry ON identity_selections(expires_at);
	CREATE TABLE IF NOT EXISTS pushed_requests (
		request_uri TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, response_type TEXT NOT NULL,
		scopes TEXT NOT NULL, oidc_state TEXT NOT NULL, nonce TEXT, code_challenge TEXT NOT NULL,
		code_challenge_method TEXT NOT NULL, prompt TEXT, dpop_jkt TEXT,
		created_at DATETIME NOT NULL, expires_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_pushed_requests_expiry ON pushed_requests(expires_at);
	CREATE TABLE IF NOT EXISTS dpop_proofs (
		replay_hash BLOB PRIMARY KEY CHECK(length(replay_hash)=32), expires_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_dpop_proofs_expiry ON dpop_proofs(expires_at);
	`

	if _, err := db.Exec(schema); err != nil {
		return err
	}
	for _, migration := range []struct{ table, column, definition string }{
		{"oauth_states", "dpop_jkt", "TEXT"},
		{"auth_codes", "dpop_jkt", "TEXT"},
		{"oauth_states", "pushed_authorization", "INTEGER NOT NULL DEFAULT 0"},
		{"auth_codes", "pushed_authorization", "INTEGER NOT NULL DEFAULT 0"},
		{"refresh_grants", "dpop_jkt", "TEXT"},
	} {
		if _, err := db.Exec("ALTER TABLE " + migration.table + " ADD COLUMN " + migration.column + " " + migration.definition); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
			return err
		}
	}
	return nil
}
