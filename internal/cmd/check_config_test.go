// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import "testing"

// TestCheckConfigDoesNotValidateTemplates verifies configuration checking has a distinct scope.
func TestCheckConfigDoesNotValidateTemplates(t *testing.T) {
	configPath := invalidTemplateConfig(t)
	if err := newCheckConfigCmd(&configPath).Execute(); err != nil {
		t.Fatalf("configuration check unexpectedly validated templates: %v", err)
	}
}
