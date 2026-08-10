// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package statedb

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/mattn/go-sqlite3"
)

var (
	// ErrDPoPReplay identifies an exact replay reservation conflict.
	ErrDPoPReplay = errors.New("DPoP proof replay")
)

const dpopRetention = 15 * time.Second

// ReserveDPoP durably reserves an exact replay hash.
func (s *Store) ReserveDPoP(replayHash [32]byte, now time.Time) error {
	_, err := s.db.Exec(`INSERT INTO dpop_proofs(replay_hash,expires_at) VALUES(?,?)`, replayHash[:], now.UTC().Add(dpopRetention))
	if isUniqueViolation(err) {
		return ErrDPoPReplay
	}
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to reserve DPoP proof", "error", err)
		}
		return fmt.Errorf("reserve DPoP proof: %w", err)
	}
	return nil
}

// isUniqueViolation recognizes SQLite and PostgreSQL uniqueness errors by driver code.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		return pgError.Code == "23505"
	}
	var sqliteError sqlite3.Error
	if errors.As(err, &sqliteError) {
		return sqliteError.ExtendedCode == sqlite3.ErrConstraintPrimaryKey || sqliteError.ExtendedCode == sqlite3.ErrConstraintUnique
	}
	return false
}

// cleanupDPoP removes a bounded batch and reports whether expired reservations remain.
func (s *Store) cleanupDPoP(now time.Time) (bool, error) {
	const batchSize = 2000
	query := `DELETE FROM dpop_proofs WHERE replay_hash IN (SELECT replay_hash FROM dpop_proofs WHERE expires_at < ? LIMIT 2000)`
	if s.postgresql {
		query = `DELETE FROM dpop_proofs WHERE ctid IN (SELECT ctid FROM dpop_proofs WHERE expires_at < ? LIMIT 2000 FOR UPDATE SKIP LOCKED)`
	}
	result, err := s.db.Exec(query, now.UTC())
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("clean DPoP proofs: %w", err)
	}
	removed, err := result.RowsAffected()
	if err != nil || removed < batchSize {
		return false, err
	}
	var backlogged bool
	if err = s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM dpop_proofs WHERE expires_at < ? LIMIT 1)`, now.UTC()).Scan(&backlogged); err != nil {
		return false, fmt.Errorf("inspect DPoP cleanup backlog: %w", err)
	}
	return backlogged, nil
}
