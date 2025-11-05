// Copyright 2025 Nadrama Pty Ltd
// SPDX-License-Identifier: Apache-2.0

// Package storage provides SQLite-backed storage for OAuth state and authorization codes.
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
}

// AuthCode represents a stored authorization code.
type AuthCode struct {
	Code          string
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	Email         string
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
		nonce TEXT,
		created_at DATETIME NOT NULL,
		expires_at DATETIME NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_codes_expires_at ON auth_codes(expires_at);
	`

	_, err := db.Exec(schema)
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
		INSERT INTO oauth_states (state_token, client_id, redirect_uri, code_challenge, nonce, oidc_state, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
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
		SELECT state_token, client_id, redirect_uri, code_challenge, nonce, oidc_state, created_at, expires_at
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
	_, err = tx.Exec("DELETE FROM oauth_states WHERE state_token = ?", stateToken)
	if err != nil {
		return nil, fmt.Errorf("failed to delete state: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return &state, nil
}

// SaveAuthCode stores an authorization code.
func (s *Store) SaveAuthCode(code *AuthCode) error {
	query := `
		INSERT INTO auth_codes (code, client_id, redirect_uri, code_challenge, email, nonce, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := s.db.Exec(query,
		code.Code,
		code.ClientID,
		code.RedirectURI,
		code.CodeChallenge,
		code.Email,
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
		SELECT code, client_id, redirect_uri, code_challenge, email, nonce, created_at, expires_at
		FROM auth_codes
		WHERE code = ?
	`
	err = tx.QueryRow(query, codeStr).Scan(
		&code.Code,
		&code.ClientID,
		&code.RedirectURI,
		&code.CodeChallenge,
		&code.Email,
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
	_, err = tx.Exec("DELETE FROM auth_codes WHERE code = ?", codeStr)
	if err != nil {
		return nil, fmt.Errorf("failed to delete auth code: %w", err)
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

		// Vacuum database periodically (every 10 minutes might be too frequent, but it's a good start)
		// SQLite's auto_vacuum can also be used instead
		if _, err := s.db.Exec("PRAGMA optimize"); err != nil {
			s.logger.Error("failed to optimize database", "error", err)
		}
	}
}
