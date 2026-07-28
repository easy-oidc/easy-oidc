// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestValidateCommandRejectsInvalidTemplates verifies validation loads template overlays.
func TestValidateCommandRejectsInvalidTemplates(t *testing.T) {
	configFile, err := filepath.Abs(filepath.Join("..", "..", "examples", "config", "config-local-dev.jsonc"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err = os.MkdirAll(filepath.Join(dir, "pages"), 0755); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "pages/error.html"), []byte(`{{define "content"}}{{.Missing}}{{end}}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EASYOIDC_TEMPLATES_DIR", dir)
	cmd := newValidateCmd()
	cmd.SetArgs([]string{"--config", configFile})
	if err = cmd.Execute(); err == nil || !strings.Contains(err.Error(), "template validation failed") {
		t.Fatalf("invalid templates were accepted: %v", err)
	}
}
