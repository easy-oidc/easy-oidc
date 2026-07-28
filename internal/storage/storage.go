// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Store provides persistent storage for OAuth flows with replay protection.
type Store struct {
	db     *sql.DB
	logger *slog.Logger
}

// OAuthState represents stored OAuth state parameters.
type OAuthState struct {
	StateToken     string
	ClientID       string
	RedirectURI    string
	CodeChallenge  string
	Nonce          string
	OIDCState      string
	CreatedAt      time.Time
	ExpiresAt      time.Time
	ConnectorID    string
	Scopes         string
	RefreshMode    string
	AuthTime       time.Time
	OfflineConsent bool
	Purpose        string
}

// AuthCode represents a stored authorization code.
type AuthCode struct {
	Code            string
	ClientID        string
	RedirectURI     string
	CodeChallenge   string
	Email           string
	EmailVerified   bool
	Nonce           string
	CreatedAt       time.Time
	ExpiresAt       time.Time
	Scopes          string
	RefreshMode     string
	AuthTime        time.Time
	ConnectorID     string
	UpstreamSubject string
	OfflineConsent  bool
}

// New creates a new SQLite-backed storage instance.
// The database file is created at the specified path.
func New(dbPath string, logger *slog.Logger) (*Store, error) {
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

	// Enable WAL mode for better concurrency
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

	// Create tables if they don't exist
	if err := initSchema(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	s := &Store{
		db:     db,
		logger: logger,
	}

	// Start cleanup goroutine
	go s.cleanupExpired()

	return s, nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// initSchema creates the required tables.
func initSchema(db *sql.DB) error {
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
		connector_id TEXT NOT NULL DEFAULT '', scopes TEXT NOT NULL, refresh_mode TEXT NOT NULL, auth_time DATETIME NOT NULL, offline_consent INTEGER NOT NULL DEFAULT 0, purpose TEXT NOT NULL DEFAULT 'authorize'
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
		connector_id TEXT NOT NULL DEFAULT '', upstream_subject TEXT NOT NULL DEFAULT '', offline_consent INTEGER NOT NULL DEFAULT 0
	);

	CREATE INDEX IF NOT EXISTS idx_codes_expires_at ON auth_codes(expires_at);
	CREATE TABLE IF NOT EXISTS flow_credentials (
		flow_id TEXT PRIMARY KEY, client_id TEXT NOT NULL, connector_id TEXT NOT NULL,
		nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, expires_at DATETIME NOT NULL
	);
	CREATE TABLE IF NOT EXISTS upstream_credentials (
		connector_id TEXT NOT NULL, subject TEXT NOT NULL, email TEXT NOT NULL,
		verified_at DATETIME NOT NULL, local_verified INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(connector_id, subject, email)
	);
	CREATE TABLE IF NOT EXISTS otp_challenges (
		challenge_id TEXT PRIMARY KEY, email TEXT NOT NULL, code_hmac BLOB NOT NULL,
		context TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, sends INTEGER NOT NULL DEFAULT 1,
		created_at DATETIME NOT NULL, sent_at DATETIME NOT NULL, expires_at DATETIME NOT NULL
	);
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
	`

	if _, err := db.Exec(schema); err != nil {
		return err
	}
	return nil
}

// GenerateStateToken creates a new cryptographically secure random state token.
func GenerateStateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GenerateAuthCode creates a new cryptographically secure random authorization code.
func GenerateAuthCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random code: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// SaveState stores an OAuth state token.
func (s *Store) SaveState(state *OAuthState) error {
	query := `
		INSERT INTO oauth_states (state_token, client_id, redirect_uri, code_challenge, nonce, oidc_state, created_at, expires_at, connector_id, scopes, refresh_mode, auth_time, offline_consent, purpose)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := s.db.Exec(query,
		state.StateToken,
		state.ClientID,
		state.RedirectURI,
		state.CodeChallenge,
		state.Nonce,
		state.OIDCState,
		state.CreatedAt,
		state.ExpiresAt,
		state.ConnectorID,
		state.Scopes, state.RefreshMode, state.AuthTime, state.OfflineConsent, state.Purpose,
	)
	if err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}
	return nil
}

// GetAndDeleteState retrieves and atomically deletes a state token (single-use enforcement).
func (s *Store) GetAndDeleteState(stateToken string) (*OAuthState, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Retrieve the state
	var state OAuthState
	query := `
		SELECT state_token, client_id, redirect_uri, code_challenge, nonce, oidc_state, created_at, expires_at, connector_id, scopes, refresh_mode, auth_time, offline_consent, purpose
		FROM oauth_states
		WHERE state_token = ?
	`
	err = tx.QueryRow(query, stateToken).Scan(
		&state.StateToken,
		&state.ClientID,
		&state.RedirectURI,
		&state.CodeChallenge,
		&state.Nonce,
		&state.OIDCState,
		&state.CreatedAt,
		&state.ExpiresAt,
		&state.ConnectorID,
		&state.Scopes, &state.RefreshMode, &state.AuthTime, &state.OfflineConsent, &state.Purpose,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("state token not found or already used")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve state: %w", err)
	}

	// Check expiry
	if time.Now().After(state.ExpiresAt) {
		return nil, fmt.Errorf("state token has expired")
	}

	// Delete the state (single-use)
	result, err := tx.Exec("DELETE FROM oauth_states WHERE state_token = ?", stateToken)
	if err != nil {
		return nil, fmt.Errorf("failed to delete state: %w", err)
	}
	if affected, rowsErr := result.RowsAffected(); rowsErr != nil || affected != 1 {
		return nil, fmt.Errorf("state token not found or already used")
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return &state, nil
}

// PeekState retrieves a valid state token without consuming it.
func (s *Store) PeekState(stateToken string) (*OAuthState, error) {
	var state OAuthState
	err := s.db.QueryRow(`SELECT state_token,client_id,redirect_uri,code_challenge,nonce,oidc_state,created_at,expires_at,connector_id,scopes,refresh_mode,auth_time,offline_consent,purpose FROM oauth_states WHERE state_token=?`, stateToken).Scan(
		&state.StateToken, &state.ClientID, &state.RedirectURI, &state.CodeChallenge, &state.Nonce, &state.OIDCState, &state.CreatedAt, &state.ExpiresAt, &state.ConnectorID, &state.Scopes, &state.RefreshMode, &state.AuthTime, &state.OfflineConsent, &state.Purpose)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("state token not found or already used")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve state: %w", err)
	}
	if time.Now().After(state.ExpiresAt) {
		return nil, fmt.Errorf("state token has expired")
	}
	return &state, nil
}

// SaveCredential records a credential only after its email has been accepted.
func (s *Store) SaveCredential(connectorID, subject, email string, local bool, verifiedAt time.Time) error {
	_, err := s.db.Exec(`INSERT INTO upstream_credentials(connector_id,subject,email,verified_at,local_verified) VALUES(?,?,?,?,?)
		ON CONFLICT(connector_id,subject,email) DO UPDATE SET verified_at=excluded.verified_at,local_verified=MAX(local_verified,excluded.local_verified)`, connectorID, subject, email, verifiedAt, local)
	if err != nil {
		return fmt.Errorf("failed to save upstream credential: %w", err)
	}
	return nil
}

// CredentialVerified reports whether this exact connector identity and email was accepted before.
func (s *Store) CredentialVerified(connectorID, subject, email string) (exists, local bool, err error) {
	var value bool
	err = s.db.QueryRow(`SELECT local_verified FROM upstream_credentials WHERE connector_id=? AND subject=? AND email=?`, connectorID, subject, email).Scan(&value)
	if err == sql.ErrNoRows {
		return false, false, nil
	}
	return err == nil, value, err
}

// SaveAuthCode stores an authorization code.
func (s *Store) SaveAuthCode(code *AuthCode) error {
	query := `
		INSERT INTO auth_codes (code, client_id, redirect_uri, code_challenge, email, email_verified, nonce, created_at, expires_at, scopes, refresh_mode, auth_time, connector_id, upstream_subject, offline_consent)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := s.db.Exec(query,
		code.Code,
		code.ClientID,
		code.RedirectURI,
		code.CodeChallenge,
		code.Email,
		code.EmailVerified,
		code.Nonce,
		code.CreatedAt,
		code.ExpiresAt,
		code.Scopes, code.RefreshMode, code.AuthTime, code.ConnectorID, code.UpstreamSubject, code.OfflineConsent,
	)
	if err != nil {
		return fmt.Errorf("failed to save auth code: %w", err)
	}
	return nil
}

// PeekAuthCode retrieves a valid authorization code without consuming it.
func (s *Store) PeekAuthCode(codeStr string, now time.Time) (*AuthCode, error) {
	var code AuthCode
	err := s.db.QueryRow(`SELECT code,client_id,redirect_uri,code_challenge,email,email_verified,nonce,created_at,expires_at,scopes,refresh_mode,auth_time,connector_id,upstream_subject,offline_consent FROM auth_codes WHERE code=?`, codeStr).Scan(
		&code.Code, &code.ClientID, &code.RedirectURI, &code.CodeChallenge, &code.Email, &code.EmailVerified, &code.Nonce, &code.CreatedAt, &code.ExpiresAt, &code.Scopes, &code.RefreshMode, &code.AuthTime, &code.ConnectorID, &code.UpstreamSubject, &code.OfflineConsent)
	if err == sql.ErrNoRows || (err == nil && !now.Before(code.ExpiresAt)) {
		return nil, ErrInvalidGrant
	}
	if err != nil {
		return nil, fmt.Errorf("peek authorization code: %w", err)
	}
	return &code, nil
}

// GetAndDeleteAuthCode retrieves and atomically deletes an authorization code (single-use enforcement).
func (s *Store) GetAndDeleteAuthCode(codeStr string) (*AuthCode, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Retrieve the code
	var code AuthCode
	query := `
		SELECT code, client_id, redirect_uri, code_challenge, email, email_verified, nonce, created_at, expires_at, scopes, refresh_mode, auth_time, connector_id, upstream_subject, offline_consent
		FROM auth_codes
		WHERE code = ?
	`
	err = tx.QueryRow(query, codeStr).Scan(
		&code.Code,
		&code.ClientID,
		&code.RedirectURI,
		&code.CodeChallenge,
		&code.Email,
		&code.EmailVerified,
		&code.Nonce,
		&code.CreatedAt,
		&code.ExpiresAt,
		&code.Scopes, &code.RefreshMode, &code.AuthTime, &code.ConnectorID, &code.UpstreamSubject, &code.OfflineConsent,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("authorization code not found or already used")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve auth code: %w", err)
	}

	// Check expiry
	if time.Now().After(code.ExpiresAt) {
		return nil, fmt.Errorf("authorization code has expired")
	}

	// Delete the code (single-use)
	result, err := tx.Exec("DELETE FROM auth_codes WHERE code = ?", codeStr)
	if err != nil {
		return nil, fmt.Errorf("failed to delete auth code: %w", err)
	}
	if affected, rowsErr := result.RowsAffected(); rowsErr != nil || affected != 1 {
		return nil, fmt.Errorf("authorization code not found or already used")
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return &code, nil
}

// cleanupExpired periodically removes expired state tokens and authorization codes.
func (s *Store) cleanupExpired() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.cleanupExpiredAt(time.Now())
	}
}

// cleanupExpiredAt removes records whose safe retention period has elapsed.
func (s *Store) cleanupExpiredAt(now time.Time) {
	result, err := s.db.Exec("DELETE FROM oauth_states WHERE expires_at < ?", now)
	if err != nil {
		s.logger.Error("failed to clean up expired states", "error", err)
	} else if count, rowsErr := result.RowsAffected(); rowsErr == nil && count > 0 {
		s.logger.Debug("cleaned up expired states", "count", count)
	}

	result, err = s.db.Exec("DELETE FROM auth_codes WHERE expires_at < ?", now)
	if err != nil {
		s.logger.Error("failed to clean up expired auth codes", "error", err)
	} else if count, rowsErr := result.RowsAffected(); rowsErr == nil && count > 0 {
		s.logger.Debug("cleaned up expired auth codes", "count", count)
	}
	_, _ = s.db.Exec("DELETE FROM otp_challenges WHERE expires_at < ?", now)
	_, _ = s.db.Exec("DELETE FROM otp_sends WHERE sent_at < ?", now.Add(-time.Hour))
	_, _ = s.db.Exec("DELETE FROM grant_actions WHERE expires_at <= ?", now)
	_, _ = s.db.Exec("DELETE FROM identity_selections WHERE expires_at <= ?", now)
	_, _ = s.db.Exec("DELETE FROM flow_credentials WHERE expires_at <= ?", now)
	_, _ = s.db.Exec("DELETE FROM refresh_grants WHERE absolute_expires_at <= ?", now)
	if _, err := s.db.Exec("PRAGMA optimize"); err != nil {
		s.logger.Error("failed to optimize database", "error", err)
	}
}
