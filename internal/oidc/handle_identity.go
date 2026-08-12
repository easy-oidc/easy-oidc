// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"net/http"
	"strconv"
	"time"

	"github.com/truster-dev/truster/internal/statedb"
	"github.com/truster-dev/truster/internal/templates"
	"github.com/truster-dev/truster/internal/upstream"
)

// renderIdentitySelection renders all authenticated upstream email candidates.
func (s *Server) renderIdentitySelection(w http.ResponseWriter, stateToken, connectorID string, identity upstream.Identity) {
	token, err := statedb.GenerateStateToken()
	if err == nil {
		err = s.store.CreateIdentitySelection(token, stateToken, connectorID, identity.Subject, identity.Emails, time.Now().Add(5*time.Minute))
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	emails := make([]templates.EmailData, len(identity.Emails))
	for i, email := range identity.Emails {
		emails[i] = templates.EmailData{Address: email.Address, Verified: email.Verified, Primary: email.Primary}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err = s.templates.RenderPage(w, "identity", templates.IdentityData{Title: "Choose an email", Token: token, Emails: emails}); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// HandleIdentitySelect consumes a selection and its original OAuth state exactly once.
func (s *Server) HandleIdentitySelect(w http.ResponseWriter, r *http.Request) {
	if !parseBrowserForm(w, r, "token", "index") {
		return
	}
	stateToken, connectorID, subject, emails, err := s.store.ConsumeIdentitySelection(r.PostForm.Get("token"), time.Now())
	index, indexErr := strconv.Atoi(r.PostForm.Get("index"))
	if err != nil || indexErr != nil || index < 0 || index >= len(emails) {
		http.Error(w, "invalid selection", http.StatusBadRequest)
		return
	}
	state, err := s.authCodeMgr.DecodeState(stateToken)
	if err != nil {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	if state.ConnectorID != connectorID {
		http.Error(w, "connector does not match state", http.StatusBadRequest)
		return
	}
	s.acceptOrChallenge(w, r, *state, connectorID, subject, emails[index])
}
