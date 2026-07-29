// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"strings"
	"testing"
)

// TestCheckTemplatesRejectsInvalidTemplates verifies configured overlays are rendered.
func TestCheckTemplatesRejectsInvalidTemplates(t *testing.T) {
	configPath := invalidTemplateConfig(t)
	if err := newCheckTemplatesCmd(&configPath).Execute(); err == nil || !strings.Contains(err.Error(), "template validation failed") {
		t.Fatalf("invalid templates were accepted: %v", err)
	}
}
