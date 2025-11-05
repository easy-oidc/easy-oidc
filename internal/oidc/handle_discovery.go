// Copyright 2025 Nadrama Pty Ltd
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"encoding/json"
	"net/http"
)

// HandleDiscovery handles the OIDC discovery endpoint (/.well-known/openid-configuration).
// It returns the OpenID Connect provider metadata.
func (s *Server) HandleDiscovery(w http.ResponseWriter, r *http.Request) {
	discovery := map[string]interface{}{
		"issuer":                                s.config.IssuerURL,
		"authorization_endpoint":                s.config.IssuerURL + "/authorize",
		"token_endpoint":                        s.config.IssuerURL + "/token",
		"userinfo_endpoint":                     s.config.IssuerURL + "/userinfo",
		"jwks_uri":                              s.config.IssuerURL + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"EdDSA"},
		"scopes_supported":                      []string{"openid", "email", "profile", "groups"},
		"claims_supported":                      []string{"sub", "email", "email_verified", "preferred_username", "groups"},
		"code_challenge_methods_supported":      []string{"S256"},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(discovery); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
	}
}
