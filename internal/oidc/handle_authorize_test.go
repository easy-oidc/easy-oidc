// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/easy-oidc/easy-oidc/internal/config"
	"github.com/easy-oidc/easy-oidc/internal/storage"
	"github.com/easy-oidc/easy-oidc/internal/templates"
	"github.com/easy-oidc/easy-oidc/internal/tokens"
	"github.com/easy-oidc/easy-oidc/internal/upstream"
	"golang.org/x/oauth2"
)

// captureConnector records the state passed to its authorization URL.
type captureConnector struct {
	state    string
	identity upstream.Identity
}

// AuthCodeURL records state and returns a fixed provider URL.
func (c *captureConnector) AuthCodeURL(state string, _ ...oauth2.AuthCodeOption) string {
	c.state = state
	return "https://provider.example/authorize"
}

// Exchange satisfies upstream.Connector for authorization tests.
func (*captureConnector) Exchange(context.Context, string) (*oauth2.Token, error) {
	return nil, nil
}

// GetIdentity returns the configured test identity.
func (c *captureConnector) GetIdentity(context.Context, *oauth2.Token) (upstream.Identity, error) {
	return c.identity, nil
}

// authorizeServer creates a test server and capture connectors.
func authorizeServer(t *testing.T, connectors map[string]config.ConnectorConfig) (*Server, map[string]*captureConnector) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := storage.New(t.TempDir()+"/test.db", logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	manager, err := templates.Load("")
	if err != nil {
		t.Fatal(err)
	}
	registry := make(map[string]upstream.Connector)
	captures := make(map[string]*captureConnector)
	for id, connector := range connectors {
		if connector.Type != "email" {
			capture := &captureConnector{}
			registry[id] = capture
			captures[id] = capture
		}
	}
	requireGroups := false
	cfg := &config.Config{
		Connectors:    connectors,
		RequireGroups: &requireGroups,
		Clients: map[string]config.ClientConfig{
			"client": {RedirectURIs: []string{"https://client.example/callback"}},
		},
	}
	managerAuth, err := NewAuthCodeManager(store)
	if err != nil {
		t.Fatal(err)
	}
	return NewServer(cfg, registry, managerAuth, nil, tokens.NewGroupResolver(nil), nil, logger, store, manager, nil, nil, nil, []byte("01234567890123456789012345678901")), captures
}

// authorizationRequest creates a valid downstream authorization request.
func authorizationRequest() *http.Request {
	values := url.Values{
		"client_id":             {"client"},
		"redirect_uri":          {"https://client.example/callback"},
		"code_challenge":        {"challenge"},
		"code_challenge_method": {"S256"},
		"state":                 {"downstream-state"},
		"nonce":                 {"nonce"},
	}
	return httptest.NewRequest(http.MethodGet, "/authorize?"+values.Encode(), nil)
}

// TestHandleAuthorizeAutomaticallySelectsSingleConnector verifies single-provider bypass.
func TestHandleAuthorizeAutomaticallySelectsSingleConnector(t *testing.T) {
	server, captures := authorizeServer(t, map[string]config.ConnectorConfig{
		"google-work": {Type: "google", DisplayName: "Google"},
	})
	response := httptest.NewRecorder()
	server.HandleAuthorize(response, authorizationRequest())
	if response.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusFound)
	}
	state, err := server.authCodeMgr.DecodeState(captures["google-work"].state)
	if err != nil {
		t.Fatal(err)
	}
	if state.ConnectorID != "google-work" || state.RedirectURI != "https://client.example/callback" || state.OIDCState != "downstream-state" {
		t.Fatalf("unexpected state: %#v", state)
	}
}
