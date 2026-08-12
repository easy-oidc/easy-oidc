// Truster <https://truster.dev>
// Copyright The Truster Authors
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

func TestClientConfig_ShouldRequireUserGroupsFromPolicy(t *testing.T) {
	tests := []struct {
		name        string
		clientVal   *bool
		policyVal   *bool
		expectedVal bool
		description string
	}{
		{
			name:        "client true, policy true",
			clientVal:   boolPtr(true),
			policyVal:   boolPtr(true),
			expectedVal: true,
			description: "client setting takes precedence",
		},
		{
			name:        "client false, policy true",
			clientVal:   boolPtr(false),
			policyVal:   boolPtr(true),
			expectedVal: false,
			description: "client override allows empty groups",
		},
		{
			name:        "client true, policy false",
			clientVal:   boolPtr(true),
			policyVal:   boolPtr(false),
			expectedVal: true,
			description: "client override requires groups",
		},
		{
			name:        "client nil, policy true",
			clientVal:   nil,
			policyVal:   boolPtr(true),
			expectedVal: true,
			description: "falls back to policy setting",
		},
		{
			name:        "client nil, policy false",
			clientVal:   nil,
			policyVal:   boolPtr(false),
			expectedVal: false,
			description: "falls back to policy setting",
		},
		{
			name:        "client nil, policy nil",
			clientVal:   nil,
			policyVal:   nil,
			expectedVal: true,
			description: "defaults to true when both unset",
		},
		{
			name:        "client false, policy nil",
			clientVal:   boolPtr(false),
			policyVal:   nil,
			expectedVal: false,
			description: "client setting takes precedence over default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := ClientConfig{RequireUserGroupsFromPolicy: tt.clientVal}

			result := client.ShouldRequireUserGroupsFromPolicy(tt.policyVal)

			if result != tt.expectedVal {
				t.Errorf("ShouldRequireUserGroupsFromPolicy() = %v, want %v (%s)", result, tt.expectedVal, tt.description)
			}
		})
	}
}

func boolPtr(b bool) *bool {
	return &b
}
