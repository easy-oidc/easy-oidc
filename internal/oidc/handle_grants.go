// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"errors"
	"net/http"
	"time"

	"github.com/easy-oidc/easy-oidc/internal/statedb"
	"github.com/easy-oidc/easy-oidc/internal/templates"
)

// HandleGrants starts a dedicated authentication flow that cannot issue tokens.
func (s *Server) HandleGrants(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.continueAuthorization(w, r, OAuthState{Purpose: "manage_grants", AuthTime: time.Now().UTC()})
}

// renderGrants renders active grants with fresh one-use action tokens.
func (s *Server) renderGrants(w http.ResponseWriter, email string) {
	now := time.Now().UTC()
	grants, err := s.store.ListActiveGrants(email, now)
	if err != nil {
		http.Error(w, "grant management unavailable", http.StatusServiceUnavailable)
		return
	}
	data := templates.GrantsData{Title: "Active grants", Email: email}
	actions := make([]statedb.GrantAction, 0, len(grants))
	for _, grant := range grants {
		token, e := statedb.GenerateStateToken()
		if e != nil {
			http.Error(w, "grant management unavailable", 500)
			return
		}
		actions = append(actions, statedb.GrantAction{Token: token, SID: grant.SID})
		data.Grants = append(data.Grants, templates.GrantData{SID: grant.SID, ClientID: grant.ClientID, Mode: grant.Mode, ActionToken: token, Email: email, CreatedAt: grant.CreatedAt, LastUsedAt: grant.LastUsedAt, ExpiresAt: grant.ExpiresAt})
	}
	if err = s.store.CreateGrantActions(actions, email, "revoke", now, now.Add(5*time.Minute)); err != nil {
		http.Error(w, "grant management unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err = s.templates.RenderPage(w, "grants", data); err != nil {
		http.Error(w, "internal error", 500)
	}
}

// HandleGrantRevoke atomically consumes a CSRF action and revokes its bound grant.
func (s *Server) HandleGrantRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	email, err := normalizeEmail(r.FormValue("email"))
	if err != nil {
		err = statedb.ErrInvalidGrant
	} else {
		err = s.store.ConsumeGrantActionAndRevoke(r.FormValue("action_token"), email, r.FormValue("sid"), "revoke", time.Now().UTC())
	}
	status, message := http.StatusOK, "The grant was revoked. Existing access tokens may remain valid until they expire."
	if err != nil {
		status = http.StatusBadRequest
		message = "This revocation action is invalid, expired, or already used."
		if !errors.Is(err, statedb.ErrInvalidGrant) {
			status = http.StatusServiceUnavailable
			message = "Grant management is temporarily unavailable."
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = s.templates.RenderPage(w, "grants", templates.GrantsData{Title: "Grant revocation", Message: message})
}
