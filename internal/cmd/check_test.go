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

// TestCheckCommandHierarchy verifies checks are grouped and legacy entry points are absent.
func TestCheckCommandHierarchy(t *testing.T) {
	root := NewRootCmd()
	for _, path := range []string{"check config", "check templates", "check trust"} {
		command, _, err := root.Find(strings.Fields(path))
		if err != nil || command.CommandPath() != "easy-oidc "+path {
			t.Errorf("Find(%q) command = %v, error = %v", path, command, err)
		}
	}
	for _, legacy := range []string{"validate", "trust"} {
		command, _, err := root.Find([]string{legacy})
		if err == nil && command != root {
			t.Errorf("legacy top-level command %q is still registered", legacy)
		}
	}
}

// invalidTemplateConfig configures an invalid template overlay and returns a valid config path.
func invalidTemplateConfig(t *testing.T) string {
	t.Helper()
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
	return configFile
}
