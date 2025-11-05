// Copyright 2025 Nadrama Pty Ltd
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"net/http"

	"golang.org/x/oauth2"
)

// HandleAuthorize handles the OAuth2/OIDC authorization endpoint (/authorize).
// It validates the request parameters, creates an OAuth state token, and redirects to the upstream provider.
func (s *Server) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	clientID := query.Get("client_id")
	if clientID == "" {
		http.Error(w, "client_id is required", http.StatusBadRequest)
		return
	}

	client, exists := s.config.Clients[clientID]
	if !exists {
		http.Error(w, "unknown client_id", http.StatusBadRequest)
		return
	}

	redirectURI := query.Get("redirect_uri")
	if redirectURI == "" {
		http.Error(w, "redirect_uri is required", http.StatusBadRequest)
		return
	}

	if !s.isValidRedirectURI(redirectURI, client) {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}

	codeChallenge := query.Get("code_challenge")
	if codeChallenge == "" {
		http.Error(w, "code_challenge is required (PKCE)", http.StatusBadRequest)
		return
	}

	codeChallengeMethod := query.Get("code_challenge_method")
	if codeChallengeMethod != "S256" {
		http.Error(w, "code_challenge_method must be S256", http.StatusBadRequest)
		return
	}

	oidcState := query.Get("state")
	nonce := query.Get("nonce")

	state := OAuthState{
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		CodeChallenge: codeChallenge,
		Nonce:         nonce,
		OIDCState:     oidcState,
	}

	stateToken, err := s.authCodeMgr.EncodeState(state)
	if err != nil {
		s.logger.Error("failed to encode state", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	authURL := s.connector.AuthCodeURL(stateToken, oauth2.AccessTypeOffline)
	http.Redirect(w, r, authURL, http.StatusFound)
}
