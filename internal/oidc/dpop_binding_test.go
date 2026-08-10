// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"testing"

	"github.com/easy-oidc/easy-oidc/internal/config"
)

// TestValidateDPoPBinding covers the only supported binding profiles.
func TestValidateDPoPBinding(t *testing.T) {
	tests := []struct {
		mode, jkt string
		want      bool
	}{
		{"disabled", "", true},
		{"disabled", "jkt", false},
		{"required", "", false},
		{"required", "jkt", true},
	}
	for _, test := range tests {
		if got := validateDPoPBinding(config.ClientConfig{DPoP: config.DPoPConfig{Mode: test.mode}}, test.jkt); got != test.want {
			t.Fatalf("validateDPoPBinding(%q, %q) = %v, want %v", test.mode, test.jkt, got, test.want)
		}
	}
}

// TestStateSatisfiesClientPolicyRequiresPARProvenance verifies policy changes reject direct flows.
func TestStateSatisfiesClientPolicyRequiresPARProvenance(t *testing.T) {
	client := config.ClientConfig{RedirectURIs: []string{"https://client.example/callback"}, DPoP: config.DPoPConfig{Mode: "disabled"}, RequirePAR: true}
	state := OAuthState{RedirectURI: "https://client.example/callback"}
	if stateSatisfiesClientPolicy(&state, client) {
		t.Fatal("direct authorization state satisfied require_par policy")
	}
	state.PushedAuthorization = true
	if !stateSatisfiesClientPolicy(&state, client) {
		t.Fatal("pushed authorization state did not satisfy require_par policy")
	}
}
