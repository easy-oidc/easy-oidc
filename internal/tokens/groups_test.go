// Copyright 2025 Nadrama Pty Ltd
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"reflect"
	"testing"
)

func TestResolveGroups(t *testing.T) {
	overrides := map[string]map[string][]string{
		"prod-groups": {
			"alice@example.com": {"admins", "devs"},
			"bob@example.com":   {"readonly"},
		},
		"dev-groups": {
			"charlie@example.com": {"developers"},
		},
	}

	resolver := NewGroupResolver(overrides)

	tests := []struct {
		name           string
		overrideKey    string
		email          string
		expectedGroups []string
	}{
		{
			name:           "override exists for user",
			overrideKey:    "prod-groups",
			email:          "alice@example.com",
			expectedGroups: []string{"admins", "devs"},
		},
		{
			name:           "override exists but user not found",
			overrideKey:    "prod-groups",
			email:          "unknown@example.com",
			expectedGroups: []string{},
		},
		{
			name:           "no override specified",
			overrideKey:    "",
			email:          "alice@example.com",
			expectedGroups: []string{},
		},
		{
			name:           "override key not found",
			overrideKey:    "nonexistent",
			email:          "alice@example.com",
			expectedGroups: []string{},
		},
		{
			name:           "email normalization",
			overrideKey:    "prod-groups",
			email:          "Alice@Example.Com",
			expectedGroups: []string{"admins", "devs"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			groups := resolver.ResolveGroups(tt.overrideKey, tt.email)
			if !reflect.DeepEqual(groups, tt.expectedGroups) {
				t.Errorf("expected %v, got %v", tt.expectedGroups, groups)
			}
		})
	}
}

func TestNormalizeEmail(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"alice@example.com", "alice@example.com"},
		{"Alice@Example.Com", "alice@example.com"},
		{"  bob@test.com  ", "bob@test.com"},
		{"CHARLIE@TEST.COM", "charlie@test.com"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := NormalizeEmail(tt.input)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestExtractUsername(t *testing.T) {
	tests := []struct {
		email    string
		expected string
	}{
		{"alice@example.com", "alice"},
		{"bob.smith@test.com", "bob.smith"},
		{"charlie", "charlie"},
	}

	for _, tt := range tests {
		t.Run(tt.email, func(t *testing.T) {
			result := ExtractUsername(tt.email)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}
