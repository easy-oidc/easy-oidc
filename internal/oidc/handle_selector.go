// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/easy-oidc/easy-oidc/internal/templates"
	"golang.org/x/oauth2"
)

// renderSelector renders configured sign-in methods with opaque authorization state.
func (s *Server) renderSelector(w http.ResponseWriter, state OAuthState, ids []string) {
	token, err := s.authCodeMgr.EncodeState(state)
	if err != nil {
		http.Error(w, "internal error", 500)
		return
	}
	items := make([]templates.ConnectorData, 0, len(ids))
	for _, id := range ids {
		cfg := s.config.UserLoginConnectors[id]
		items = append(items, templates.ConnectorData{ID: id, DisplayName: cfg.DisplayName, URL: "/select/" + url.PathEscape(id) + "?state=" + url.QueryEscape(token), Email: cfg.Type == "email"})
	}
	site := ""
	if s.config.Email != nil && s.config.Email.Turnstile != nil {
		site = s.config.Email.Turnstile.SiteKey
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.templates.RenderPage(w, "selector", templates.SelectorData{Title: "Sign in", State: token, SiteKey: site, Connectors: items}); err != nil {
		s.logger.Error("render selector", "error", err)
	}
}

// connectorIDs returns connector IDs in configured display order.
func (s *Server) connectorIDs() []string {
	ids := make([]string, 0, len(s.config.UserLoginConnectors))
	for id := range s.config.UserLoginConnectors {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := s.config.UserLoginConnectors[ids[i]], s.config.UserLoginConnectors[ids[j]]
		if a.Order != b.Order {
			return a.Order < b.Order
		}
		if a.DisplayName != b.DisplayName {
			return a.DisplayName < b.DisplayName
		}
		return ids[i] < ids[j]
	})
	return ids
}

// HandleSelect binds an upstream connector to authorization state.
func (s *Server) HandleSelect(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("connector")
	state, err := s.authCodeMgr.DecodeState(r.URL.Query().Get("state"))
	if err != nil {
		http.Error(w, "invalid state", 400)
		return
	}
	if state.ConnectorID != "" {
		http.Error(w, "invalid selection state", 400)
		return
	}
	s.selectConnector(w, r, id, *state)
}

// selectConnector redirects an authorization flow to an upstream connector.
func (s *Server) selectConnector(w http.ResponseWriter, r *http.Request, id string, state OAuthState) {
	cfg, ok := s.config.UserLoginConnectors[id]
	if !ok {
		http.Error(w, "unknown connector", 400)
		return
	}
	if cfg.Type == "email" {
		http.Error(w, "email connector must be submitted from the sign-in page", 400)
		return
	}
	state.ConnectorID = id
	token, err := s.authCodeMgr.EncodeState(state)
	if err != nil {
		http.Error(w, "internal error", 500)
		return
	}
	connector, ok := s.connectors[id]
	if !ok {
		http.Error(w, "connector unavailable", 500)
		return
	}
	var options []oauth2.AuthCodeOption
	if state.RefreshMode != "" {
		switch cfg.Type {
		case "google":
			options = append(options, oauth2.AccessTypeOffline, oauth2.ApprovalForce)
		case "generic":
			if cfg.Generic != nil && cfg.Generic.Refresh != nil {
				for key, value := range cfg.Generic.Refresh.AuthorizationParams {
					options = append(options, oauth2.SetAuthURLParam(key, value))
				}
				if len(cfg.Generic.Refresh.Scopes) > 0 {
					normalScopes := cfg.Scopes
					if len(normalScopes) == 0 {
						normalScopes = []string{"openid", "email"}
					}
					options = append(options, oauth2.SetAuthURLParam("scope", strings.Join(mergeScopes(normalScopes, cfg.Generic.Refresh.Scopes), " ")))
				}
			}
		}
	}
	http.Redirect(w, r, connector.AuthCodeURL(token, options...), http.StatusFound)
}

// mergeScopes returns stable de-duplicated configured scopes.
func mergeScopes(left, right []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(left)+len(right))
	for _, scope := range append(append([]string(nil), left...), right...) {
		if !seen[scope] {
			seen[scope] = true
			result = append(result, scope)
		}
	}
	return result
}
