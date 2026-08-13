// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/truster-dev/truster/v2/internal/authpolicy"
	"github.com/truster-dev/truster/v2/internal/statedb"
	"github.com/truster-dev/truster/v2/internal/templates"
)

// HandleAuthorize validates a downstream authorization request and starts connector selection.
func (s *Server) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if requestURIs, present := q["request_uri"]; present {
		if len(q) != 2 || len(q["client_id"]) != 1 || len(requestURIs) != 1 || q.Get("client_id") == "" || requestURIs[0] == "" {
			http.Error(w, "invalid_request", http.StatusBadRequest)
			return
		}
		s.handlePushedAuthorize(w, r, q.Get("client_id"), requestURIs[0])
		return
	}
	clientID := q.Get("client_id")
	if len(q["client_id"]) != 1 || len(q["redirect_uri"]) != 1 {
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}
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
	if client.RequirePAR {
		http.Error(w, "invalid_request: pushed authorization request required", http.StatusBadRequest)
		return
	}
	redirect := q.Get("redirect_uri")
	if redirect == "" || !s.isValidRedirectURI(redirect, client) {
		http.Error(w, "invalid redirect_uri", 400)
		return
	}
	for _, values := range q {
		if len(values) != 1 {
			redirectAuthorizationError(w, r, redirect, q.Get("state"), "invalid_request")
			return
		}
	}
	if len(r.Header.Values("DPoP")) != 0 {
		redirectAuthorizationError(w, r, redirect, q.Get("state"), "invalid_request")
		return
	}
	dpopJKT := q.Get("dpop_jkt")
	if values, present := q["dpop_jkt"]; present && (len(values) != 1 || values[0] == "") {
		redirectAuthorizationError(w, r, redirect, q.Get("state"), "invalid_request")
		return
	}
	dpopJKT, dpopError := selectDPoP(client.DPoP.Mode, dpopJKT, false)
	if dpopError != "" {
		redirectAuthorizationError(w, r, redirect, q.Get("state"), dpopError)
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
	state := OAuthState{ClientID: clientID, RedirectURI: redirect, CodeChallenge: challenge, Nonce: q.Get("nonce"), OIDCState: q.Get("state"), Scopes: strings.Join(requested, " "), RefreshMode: mode, AuthTime: time.Now(), DPoPJKT: dpopJKT}
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

// selectDPoP validates a canonical thumbprint and applies the configured client mode.
func selectDPoP(mode, thumbprint string, proofPresent bool) (string, string) {
	selected := thumbprint != "" || proofPresent
	if mode == "disabled" && selected {
		return "", "invalid_request"
	}
	if mode == "required" && !selected {
		return "", "invalid_request"
	}
	if thumbprint != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(thumbprint)
		if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != thumbprint {
			return "", "invalid_request"
		}
	}
	if !selected {
		return "", ""
	}
	return thumbprint, ""
}

// handlePushedAuthorize consumes a PAR object and continues with opaque browser state.
func (s *Server) handlePushedAuthorize(w http.ResponseWriter, r *http.Request, clientID, requestURI string) {
	resolved, err := s.policyResolver.ResolveClient(r.Context(), clientID, false)
	if err != nil {
		if errors.Is(err, authpolicy.ErrDenied) {
			http.Error(w, "invalid_request", http.StatusBadRequest)
		} else {
			http.Error(w, "temporarily_unavailable", http.StatusServiceUnavailable)
		}
		return
	}
	now := time.Now()
	pushed, err := s.store.ConsumePushedRequest(requestURI, clientID, now)
	if err != nil {
		if errors.Is(err, statedb.ErrInvalidGrant) {
			http.Error(w, "invalid_request", http.StatusBadRequest)
		} else {
			http.Error(w, "temporarily_unavailable", http.StatusServiceUnavailable)
		}
		return
	}
	client := resolved.Config
	if !s.isValidRedirectURI(pushed.RedirectURI, client) {
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}
	if (client.DPoP.Mode == "required") != (pushed.DPoPJKT != "") {
		redirectAuthorizationError(w, r, pushed.RedirectURI, pushed.State, "invalid_request")
		return
	}
	mode := ""
	if client.RefreshTokens.Enabled {
		mode = "session"
	}
	if strings.Contains(" "+pushed.Scopes+" ", " offline_access ") {
		if !client.RefreshTokens.Enabled || !client.RefreshTokens.AllowOfflineAccess {
			redirectAuthorizationError(w, r, pushed.RedirectURI, pushed.State, "invalid_request")
			return
		}
		mode = "offline"
	}
	if strings.Contains(" "+pushed.Scopes+" ", " offline_access ") && pushed.Prompt == "none" {
		redirectAuthorizationError(w, r, pushed.RedirectURI, pushed.State, "consent_required")
		return
	}
	state := OAuthState{ClientID: clientID, RedirectURI: pushed.RedirectURI, CodeChallenge: pushed.CodeChallenge, Nonce: pushed.Nonce, OIDCState: pushed.State, Scopes: pushed.Scopes, RefreshMode: mode, AuthTime: now, Purpose: "authorize", DPoPJKT: pushed.DPoPJKT, PushedAuthorization: true}
	if strings.Contains(" "+state.Scopes+" ", " offline_access ") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		token, encodeErr := s.authCodeMgr.EncodeState(state)
		if encodeErr != nil {
			http.Error(w, "internal error", 500)
			return
		}
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
	if !parseBrowserForm(w, r, "state", "decision") {
		return
	}
	state, err := s.authCodeMgr.DecodeState(r.PostForm.Get("state"))
	if err != nil || state.RefreshMode != "offline" {
		http.Error(w, "invalid state", 400)
		return
	}
	if r.PostForm.Get("decision") != "accept" {
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
