// Copyright 2025 Nadrama Pty Ltd
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

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
