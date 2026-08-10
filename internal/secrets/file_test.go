// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestFileProvider verifies safe file secret resolution and reads.
func TestFileProvider(t *testing.T) {
	directory := t.TempDir()
	if err := os.Mkdir(filepath.Join(directory, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "nested", "secret"), []byte("secret-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "empty"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "oversized"), make([]byte, maxFileSecretBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	provider, err := NewFileProvider(directory)
	if err != nil {
		t.Fatal(err)
	}

	value, err := provider.GetSecret(context.Background(), filepath.Join("nested", "secret"))
	if err != nil || value != "secret-value\n" {
		t.Fatalf("GetSecret() = %q, %v", value, err)
	}
	for _, name := range []string{"empty", "oversized", "missing", "../secret", filepath.Join(directory, "nested", "secret")} {
		t.Run(name, func(t *testing.T) {
			if _, err := provider.GetSecret(context.Background(), name); err == nil {
				t.Fatalf("GetSecret(%q) unexpectedly succeeded", name)
			}
		})
	}
}

// TestFileProviderRejectsSymlinkEscape verifies that symlinks cannot escape the root.
func TestFileProviderRejectsSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks may require additional privileges on Windows")
	}
	directory := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(directory, "escape")); err != nil {
		t.Fatal(err)
	}
	provider, err := NewFileProvider(directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.GetSecret(context.Background(), "escape"); err == nil {
		t.Fatal("GetSecret() followed a symlink outside the configured directory")
	}
}

// TestFileProviderRetainsRoot verifies replacing the configured path cannot change its root.
func TestFileProviderRetainsRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("renaming an open directory is not portable on Windows")
	}
	parent := t.TempDir()
	directory := filepath.Join(parent, "secrets")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "key"), []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	provider, err := NewFileProvider(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(directory, filepath.Join(parent, "original")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "key"), []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	value, err := provider.GetSecret(context.Background(), "key")
	if err != nil || value != "original" {
		t.Fatalf("GetSecret() = %q, %v; want original root", value, err)
	}
}
