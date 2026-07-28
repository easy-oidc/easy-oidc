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
	StateToken    string
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	Nonce         string
	OIDCState     string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	ConnectorID   string
}

// AuthCode represents a stored authorization code.
type AuthCode struct {
	Code          string
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	Email         string
	EmailVerified bool
	Nonce         string
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

// New creates a new SQLite-backed storage instance.
// The database file is created at the specified path.
func New(dbPath string, logger *slog.Logger) (*Store, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Enable WAL mode for better concurrency
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to enable WAL mode: %w", err)
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
		expires_at DATETIME NOT NULL
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
		expires_at DATETIME NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_codes_expires_at ON auth_codes(expires_at);
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
	`

	if _, err := db.Exec(schema); err != nil {
		return err
	}
	// Additive migration for databases created before connector-bound state.
	rows, err := db.Query("PRAGMA table_info(oauth_states)")
	if err != nil {
		return err
	}
	has := false
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var def any
		if err := rows.Scan(&cid, &name, &typ, &notnull, &def, &pk); err != nil {
			_ = rows.Close()
			return err
		}
		has = has || name == "connector_id"
	}
	_ = rows.Close()
	if !has {
		_, err = db.Exec("ALTER TABLE oauth_states ADD COLUMN connector_id TEXT NOT NULL DEFAULT ''")
	}
	// Additive credential source migration.
	_, _ = db.Exec("ALTER TABLE upstream_credentials ADD COLUMN local_verified INTEGER NOT NULL DEFAULT 0")
	return err
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
		INSERT INTO oauth_states (state_token, client_id, redirect_uri, code_challenge, nonce, oidc_state, created_at, expires_at, connector_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
		SELECT state_token, client_id, redirect_uri, code_challenge, nonce, oidc_state, created_at, expires_at, connector_id
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
	err := s.db.QueryRow(`SELECT state_token,client_id,redirect_uri,code_challenge,nonce,oidc_state,created_at,expires_at,connector_id FROM oauth_states WHERE state_token=?`, stateToken).Scan(
		&state.StateToken, &state.ClientID, &state.RedirectURI, &state.CodeChallenge, &state.Nonce, &state.OIDCState, &state.CreatedAt, &state.ExpiresAt, &state.ConnectorID)
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
		INSERT INTO auth_codes (code, client_id, redirect_uri, code_challenge, email, email_verified, nonce, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
	)
	if err != nil {
		return fmt.Errorf("failed to save auth code: %w", err)
	}
	return nil
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
		SELECT code, client_id, redirect_uri, code_challenge, email, email_verified, nonce, created_at, expires_at
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
		now := time.Now()

		// Clean up expired states
		result, err := s.db.Exec("DELETE FROM oauth_states WHERE expires_at < ?", now)
		if err != nil {
			s.logger.Error("failed to clean up expired states", "error", err)
		} else {
			if count, err := result.RowsAffected(); err == nil && count > 0 {
				s.logger.Debug("cleaned up expired states", "count", count)
			}
		}

		// Clean up expired auth codes
		result, err = s.db.Exec("DELETE FROM auth_codes WHERE expires_at < ?", now)
		if err != nil {
			s.logger.Error("failed to clean up expired auth codes", "error", err)
		} else {
			if count, err := result.RowsAffected(); err == nil && count > 0 {
				s.logger.Debug("cleaned up expired auth codes", "count", count)
			}
		}
		_, _ = s.db.Exec("DELETE FROM otp_challenges WHERE expires_at < ?", now)
		_, _ = s.db.Exec("DELETE FROM otp_sends WHERE sent_at < ?", now.Add(-time.Hour))

		// Vacuum database periodically (every 10 minutes might be too frequent, but it's a good start)
		// SQLite's auto_vacuum can also be used instead
		if _, err := s.db.Exec("PRAGMA optimize"); err != nil {
			s.logger.Error("failed to optimize database", "error", err)
		}
	}
}
