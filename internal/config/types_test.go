// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"
	"time"
)

// TestParseDurationUsesStandardSyntax verifies configuration durations follow time.ParseDuration.
func TestParseDurationUsesStandardSyntax(t *testing.T) {
	for input, expected := range map[string]time.Duration{
		"5m":     5 * time.Minute,
		"1h30m":  90 * time.Minute,
		"720h":   30 * 24 * time.Hour,
		"1500ms": 1500 * time.Millisecond,
	} {
		actual, err := ParseDuration(input)
		if err != nil || actual != expected {
			t.Errorf("ParseDuration(%q) = %v, %v; want %v", input, actual, err, expected)
		}
	}
	for _, input := range []string{"", "0s", "-1s", "30d", "forever"} {
		if _, err := ParseDuration(input); err == nil {
			t.Errorf("ParseDuration(%q) unexpectedly succeeded", input)
		}
	}
}

func TestClientConfig_ShouldRequireGroups(t *testing.T) {
	tests := []struct {
		name        string
		clientVal   *bool
		globalVal   *bool
		expectedVal bool
		description string
	}{
		{
			name:        "client true, global true",
			clientVal:   boolPtr(true),
			globalVal:   boolPtr(true),
			expectedVal: true,
			description: "client setting takes precedence",
		},
		{
			name:        "client false, global true",
			clientVal:   boolPtr(false),
			globalVal:   boolPtr(true),
			expectedVal: false,
			description: "client override allows empty groups",
		},
		{
			name:        "client true, global false",
			clientVal:   boolPtr(true),
			globalVal:   boolPtr(false),
			expectedVal: true,
			description: "client override requires groups",
		},
		{
			name:        "client nil, global true",
			clientVal:   nil,
			globalVal:   boolPtr(true),
			expectedVal: true,
			description: "falls back to global setting",
		},
		{
			name:        "client nil, global false",
			clientVal:   nil,
			globalVal:   boolPtr(false),
			expectedVal: false,
			description: "falls back to global setting",
		},
		{
			name:        "client nil, global nil",
			clientVal:   nil,
			globalVal:   nil,
			expectedVal: true,
			description: "defaults to true when both unset",
		},
		{
			name:        "client false, global nil",
			clientVal:   boolPtr(false),
			globalVal:   nil,
			expectedVal: false,
			description: "client setting takes precedence over default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := ClientConfig{
				RequireGroups: tt.clientVal,
			}

			result := client.ShouldRequireGroups(tt.globalVal)

			if result != tt.expectedVal {
				t.Errorf("ShouldRequireGroups() = %v, want %v (%s)", result, tt.expectedVal, tt.description)
			}
		})
	}
}

func boolPtr(b bool) *bool {
	return &b
}
