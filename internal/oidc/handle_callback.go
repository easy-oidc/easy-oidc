// Copyright 2025 Nadrama Pty Ltd
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
)

// HandleCallback handles the OAuth2 callback from the upstream provider (/callback).
// It exchanges the code for a token, retrieves user information, generates an authorization code,
// and redirects back to the client's redirect URI.
func (s *Server) HandleCallback(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	errorParam := query.Get("error")
	if errorParam != "" {
		errorDesc := query.Get("error_description")
		s.logger.Warn("upstream OAuth error", "error", errorParam, "description", errorDesc)
		http.Error(w, fmt.Sprintf("OAuth error: %s", errorParam), http.StatusBadRequest)
		return
	}

	code := query.Get("code")
	if code == "" {
		http.Error(w, "code is required", http.StatusBadRequest)
		return
	}

	stateToken := query.Get("state")
	if stateToken == "" {
		http.Error(w, "state is required", http.StatusBadRequest)
		return
	}

	state, err := s.authCodeMgr.DecodeState(stateToken)
	if err != nil {
		s.logger.Error("failed to decode state", "error", err)
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}

	token, err := s.connector.Exchange(r.Context(), code)
	if err != nil {
		s.logger.Error("failed to exchange code", "error", err)
		http.Error(w, "failed to exchange authorization code", http.StatusInternalServerError)
		return
	}

	email, verified, err := s.connector.GetUserEmail(r.Context(), token)
	if err != nil {
		s.logger.Error("failed to get user email", "error", err)
		http.Error(w, "failed to get user email", http.StatusInternalServerError)
		return
	}

	if !verified {
		http.Error(w, "email not verified", http.StatusForbidden)
		return
	}

	client, exists := s.config.Clients[state.ClientID]
	if !exists {
		s.logger.Error("unknown client in state", "client_id", state.ClientID)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	groups := s.groupResolver.ResolveGroups(client.GroupsOverride, email)
	if client.ShouldRequireGroups(s.config.RequireGroups) && len(groups) == 0 {
		s.logger.Warn("authentication rejected: user has no groups", "email", email, "client_id", state.ClientID)
		s.renderErrorPage(w, "Login Failed", "Your account was unable to be authorised.")
		return
	}

	authCode, err := s.authCodeMgr.GenerateCode(AuthCodePayload{
		ClientID:      state.ClientID,
		RedirectURI:   state.RedirectURI,
		CodeChallenge: state.CodeChallenge,
		Email:         email,
		Nonce:         state.Nonce,
	})
	if err != nil {
		s.logger.Error("failed to generate authorization code", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	redirectURL, err := url.Parse(state.RedirectURI)
	if err != nil {
		s.logger.Error("invalid redirect URI", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	q := redirectURL.Query()
	q.Set("code", authCode)
	if state.OIDCState != "" {
		q.Set("state", state.OIDCState)
	}
	redirectURL.RawQuery = q.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

func (s *Server) renderErrorPage(w http.ResponseWriter, title string, message string) {
	tmpl, err := template.New("error").Parse(errorPageTemplate)
	if err != nil {
		s.logger.Error("failed to parse error template", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)

	data := struct {
		Title   string
		Message string
	}{
		Title:   title,
		Message: message,
	}

	if err := tmpl.Execute(w, data); err != nil {
		s.logger.Error("failed to render error template", "error", err)
	}
}
