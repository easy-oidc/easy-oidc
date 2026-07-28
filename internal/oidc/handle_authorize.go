// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"net/http"
)

// HandleAuthorize validates a downstream authorization request and starts connector selection.
func (s *Server) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	client, ok := s.config.Clients[clientID]
	if !ok {
		http.Error(w, "unknown client_id", 400)
		return
	}
	redirect := q.Get("redirect_uri")
	if redirect == "" || !s.isValidRedirectURI(redirect, client) {
		http.Error(w, "invalid redirect_uri", 400)
		return
	}
	challenge := q.Get("code_challenge")
	if challenge == "" || q.Get("code_challenge_method") != "S256" {
		http.Error(w, "PKCE S256 is required", 400)
		return
	}
	state := OAuthState{ClientID: clientID, RedirectURI: redirect, CodeChallenge: challenge, Nonce: q.Get("nonce"), OIDCState: q.Get("state")}
	ids := s.connectorIDs()
	if len(ids) == 1 && s.config.Connectors[ids[0]].Type != "email" {
		s.selectConnector(w, r, ids[0], state)
		return
	}
	s.renderSelector(w, state, ids)
}
