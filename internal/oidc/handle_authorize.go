// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/easy-oidc/easy-oidc/internal/authpolicy"
	"github.com/easy-oidc/easy-oidc/internal/templates"
)

// HandleAuthorize validates a downstream authorization request and starts connector selection.
func (s *Server) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	resolved, err := s.policyResolver.ResolveClient(r.Context(), clientID, false)
	if errors.Is(err, authpolicy.ErrDenied) {
		http.Error(w, "unknown client_id", 400)
		return
	}
	if err != nil {
		http.Error(w, "auth temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	client := resolved.Config
	redirect := q.Get("redirect_uri")
	if redirect == "" || !s.isValidRedirectURI(redirect, client) {
		http.Error(w, "invalid redirect_uri", 400)
		return
	}
	if q.Get("response_type") != "code" {
		redirectAuthorizationError(w, r, redirect, q.Get("state"), "unsupported_response_type")
		return
	}
	requested := strings.Fields(q.Get("scope"))
	allowed := map[string]bool{"openid": true, "email": true, "profile": true, "groups": true}
	hasOpenID, offline := false, false
	for _, scope := range requested {
		hasOpenID = hasOpenID || scope == "openid"
		offline = offline || scope == "offline_access"
		if !allowed[scope] && scope != "offline_access" {
			redirectAuthorizationError(w, r, redirect, q.Get("state"), "invalid_scope")
			return
		}
	}
	if !hasOpenID || (offline && (!client.RefreshTokens.Enabled || !client.RefreshTokens.AllowOfflineAccess)) {
		redirectAuthorizationError(w, r, redirect, q.Get("state"), "invalid_scope")
		return
	}
	if offline && q.Get("prompt") == "none" {
		redirectAuthorizationError(w, r, redirect, q.Get("state"), "consent_required")
		return
	}
	sort.Strings(requested)
	challenge := q.Get("code_challenge")
	if challenge == "" || q.Get("code_challenge_method") != "S256" {
		http.Error(w, "PKCE S256 is required", 400)
		return
	}
	mode := ""
	if client.RefreshTokens.Enabled {
		mode = "session"
	}
	if offline {
		mode = "offline"
	}
	state := OAuthState{ClientID: clientID, RedirectURI: redirect, CodeChallenge: challenge, Nonce: q.Get("nonce"), OIDCState: q.Get("state"), Scopes: strings.Join(requested, " "), RefreshMode: mode, AuthTime: time.Now()}
	if offline {
		token, err := s.authCodeMgr.EncodeState(state)
		if err != nil {
			http.Error(w, "internal error", 500)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = s.templates.RenderPage(w, "consent", templates.ConsentData{Title: "Allow offline access", State: token, ClientID: clientID})
		return
	}
	s.continueAuthorization(w, r, state)
}

// HandleConsent accepts or denies explicit offline-access consent.
func (s *Server) HandleConsent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	state, err := s.authCodeMgr.DecodeState(r.FormValue("state"))
	if err != nil || state.RefreshMode != "offline" {
		http.Error(w, "invalid state", 400)
		return
	}
	if r.FormValue("decision") != "accept" {
		redirectAuthorizationError(w, r, state.RedirectURI, state.OIDCState, "access_denied")
		return
	}
	state.OfflineConsent = true
	s.continueAuthorization(w, r, *state)
}

// continueAuthorization begins connector selection after any required consent.
func (s *Server) continueAuthorization(w http.ResponseWriter, r *http.Request, state OAuthState) {
	ids := s.connectorIDs()
	if len(ids) == 1 && s.config.UserLoginConnectors[ids[0]].Type != "email" {
		s.selectConnector(w, r, ids[0], state)
		return
	}
	s.renderSelector(w, state, ids)
}

// redirectAuthorizationError returns an OAuth authorization error to a validated redirect URI.
func redirectAuthorizationError(w http.ResponseWriter, r *http.Request, redirect, state, code string) {
	u, err := url.Parse(redirect)
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	query := u.Query()
	query.Set("error", code)
	if state != "" {
		query.Set("state", state)
	}
	u.RawQuery = query.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}
