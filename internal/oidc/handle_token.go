// Copyright 2025 Nadrama Pty Ltd
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"encoding/json"
	"net/http"
)

// HandleToken handles the OAuth2 token endpoint (/token).
// It validates the authorization code, verifies PKCE, and issues an ID token.
func (s *Server) HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form data", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")
	if grantType != "authorization_code" {
		http.Error(w, "unsupported grant_type", http.StatusBadRequest)
		return
	}

	code := r.FormValue("code")
	if code == "" {
		http.Error(w, "code is required", http.StatusBadRequest)
		return
	}

	codeVerifier := r.FormValue("code_verifier")
	if codeVerifier == "" {
		http.Error(w, "code_verifier is required (PKCE)", http.StatusBadRequest)
		return
	}

	payload, err := s.authCodeMgr.ValidateAndExtract(code)
	if err != nil {
		s.logger.Error("failed to validate authorization code", "error", err)
		http.Error(w, "invalid authorization code", http.StatusBadRequest)
		return
	}

	if err := ValidatePKCE(codeVerifier, payload.CodeChallenge); err != nil {
		s.logger.Error("PKCE validation failed", "error", err)
		http.Error(w, "invalid code_verifier", http.StatusBadRequest)
		return
	}

	client, exists := s.config.Clients[payload.ClientID]
	if !exists {
		http.Error(w, "unknown client", http.StatusBadRequest)
		return
	}

	groups := s.groupResolver.ResolveGroups(client.GroupsOverride, payload.Email)

	idToken, err := s.signer.SignIDToken(payload.Email, payload.ClientID, groups, payload.Nonce)
	if err != nil {
		s.logger.Error("failed to sign ID token", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"access_token": idToken,
		"id_token":     idToken,
		"token_type":   "Bearer",
		"expires_in":   s.config.TokenTTLSeconds,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.logger.Error("failed to encode token response", "error", err)
	}
}
