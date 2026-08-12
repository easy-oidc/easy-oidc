// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package statedb

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

// TestNewSQLiteSecuresStateFiles verifies newly created state directories and SQLite files are private.
func TestNewSQLiteSecuresStateFiles(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	path := filepath.Join(directory, "truster.db")
	store, err := NewSQLite(path, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	for _, name := range []string{directory, path, path + "-wal", path + "-shm"} {
		info, statErr := os.Stat(name)
		if statErr != nil {
			t.Fatalf("stat %s: %v", name, statErr)
		}
		if info.Mode().Perm()&0077 != 0 {
			t.Fatalf("permissions for %s = %04o, want no group or other access", name, info.Mode().Perm())
		}
	}
}

// TestNewSQLiteRejectsUnsafeExistingFiles verifies permissive database files fail closed.
func TestNewSQLiteRejectsUnsafeExistingFiles(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "truster.db")
	if err := os.WriteFile(path, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSQLite(path, slog.Default()); err == nil {
		t.Fatal("unsafe state database was accepted")
	}
}
