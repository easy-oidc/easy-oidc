// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package statedb

import (
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/mattn/go-sqlite3"
)

// TestDPoPReplaySurvivesRestart verifies durable exact-hash replay rejection.
func TestDPoPReplaySurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	now := time.Now().UTC()
	hash := [32]byte{1, 2, 3}
	store, err := NewSQLite(path, logger)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.ReserveDPoP(hash, now); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = NewSQLite(path, logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err = store.ReserveDPoP(hash, now.Add(time.Second)); !errors.Is(err, ErrDPoPReplay) {
		t.Fatalf("replay error = %v", err)
	}
}

// TestDPoPBoundedCleanup verifies expired reservations can be removed and reused.
func TestDPoPBoundedCleanup(t *testing.T) {
	store := otpStore(t)
	now := time.Now().UTC()
	hash := [32]byte{9}
	if err := store.ReserveDPoP(hash, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.cleanupDPoP(now.Add(dpopRetention + time.Nanosecond)); err != nil {
		t.Fatal(err)
	}
	if err := store.ReserveDPoP(hash, now.Add(dpopRetention+time.Second)); err != nil {
		t.Fatalf("post-expiry reservation = %v", err)
	}
}

// TestDPoPCleanupReportsBacklog verifies a full batch exposes remaining expired rows.
func TestDPoPCleanupReportsBacklog(t *testing.T) {
	store := otpStore(t)
	tx, err := store.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(-time.Minute)
	for i := uint64(0); i < 2001; i++ {
		hash := make([]byte, 32)
		binary.BigEndian.PutUint64(hash[24:], i)
		if _, err = tx.Exec(`INSERT INTO dpop_proofs(replay_hash,expires_at) VALUES(?,?)`, hash, expires); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	backlogged, err := store.cleanupDPoP(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if !backlogged {
		t.Fatal("cleanup did not report remaining expired rows")
	}
}

// TestDPoPUniqueViolationClassification rejects message-based replay classification.
func TestDPoPUniqueViolationClassification(t *testing.T) {
	if !isUniqueViolation(sqlite3.Error{ExtendedCode: sqlite3.ErrConstraintUnique}) {
		t.Fatal("SQLite uniqueness error was not recognized")
	}
	if !isUniqueViolation(&pgconn.PgError{Code: "23505"}) {
		t.Fatal("PostgreSQL uniqueness error was not recognized")
	}
	if isUniqueViolation(errors.New("duplicate key value violates unique constraint")) {
		t.Fatal("error text was misclassified as a replay")
	}
}
