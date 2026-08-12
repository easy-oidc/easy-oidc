// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import "testing"

// TestVerificationAccepted verifies provider and strict verification modes.
func TestVerificationAccepted(t *testing.T) {
	tests := []struct {
		name             string
		mode             string
		providerVerified bool
		localVerified    bool
		want             bool
	}{
		{"disabled accepts unverified assertion", "disabled", false, false, true},
		{"provider trusts current assertion", "provider", true, false, true},
		{"provider requires OTP without current assertion", "provider", false, false, false},
		{"provider accepts prior local verification", "provider", false, true, true},
		{"strict ignores provider assertion", "strict", true, false, false},
		{"strict accepts prior local verification", "strict", false, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := verificationAccepted(tt.mode, tt.providerVerified, tt.localVerified); got != tt.want {
				t.Fatalf("verificationAccepted() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestNormalizeEmail verifies normalization and rejection of non-bare addresses.
func TestNormalizeEmail(t *testing.T) {
	got, err := normalizeEmail(" User@Example.COM ")
	if err != nil || got != "user@example.com" {
		t.Fatalf("normalizeEmail() = %q, %v", got, err)
	}
	for _, invalid := range []string{"", "   ", "Display <user@example.com>", "not-an-email"} {
		if _, err := normalizeEmail(invalid); err == nil {
			t.Errorf("normalizeEmail(%q) succeeded", invalid)
		}
	}
}
