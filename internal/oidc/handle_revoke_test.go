// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/easy-oidc/easy-oidc/internal/statedb"
	"github.com/easy-oidc/easy-oidc/internal/tokens"
)

// revokeServer creates a revocation handler with a real SQLite store and signer.
func revokeServer(t *testing.T) (*Server, *statedb.Store, *tokens.Signer) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := statedb.NewSQLite(t.TempDir()+"/test.db", logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	signer := tokens.NewSigner(newTestSigningKey(t), "test-kid", "https://issuer.example", time.Hour)
	return &Server{store: store, signer: signer, logger: logger}, store, signer
}

// createRevocableGrant inserts one active refresh family for handler tests.
func createRevocableGrant(t *testing.T, store *statedb.Store, sid, clientID string) statedb.RefreshMaterial {
	t.Helper()
	now := time.Now().UTC()
	material, err := statedb.GenerateRefreshMaterial()
	if err != nil {
		t.Fatal(err)
	}
	grant := statedb.RefreshGrant{SID: sid, ClientID: clientID, Email: "user@example.com", Scopes: "openid", ConnectorID: "email", Mode: "session", AuthTime: now, IdleTTL: time.Hour, AbsoluteExpiry: now.Add(2 * time.Hour)}
	if err = store.CreateRefreshGrant(grant, material, nil, nil, now); err != nil {
		t.Fatal(err)
	}
	return material
}

// revokeRequest sends a canonical revocation form to the handler.
func revokeRequest(server *Server, values url.Values) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.HandleRevoke(response, request)
	return response
}

// TestHandleRevokeRevokesRefreshFamily verifies refresh tokens are client-bound and family-wide.
func TestHandleRevokeRevokesRefreshFamily(t *testing.T) {
	server, store, _ := revokeServer(t)
	material := createRevocableGrant(t, store, "refresh-sid", "client")

	wrongClient := revokeRequest(server, url.Values{"token": {material.Token}, "client_id": {"other-client"}})
	if wrongClient.Code != http.StatusOK || wrongClient.Body.Len() != 0 {
		t.Fatalf("wrong-client response = %d %q, want empty 200", wrongClient.Code, wrongClient.Body.String())
	}
	if _, _, err := store.PrepareRefresh(material, "client", time.Now()); err != nil {
		t.Fatalf("wrong client revoked grant: %v", err)
	}

	response := revokeRequest(server, url.Values{"token": {material.Token}, "client_id": {"client"}})
	if response.Code != http.StatusOK || response.Body.Len() != 0 {
		t.Fatalf("response = %d %q, want empty 200", response.Code, response.Body.String())
	}
	if _, _, err := store.PrepareRefresh(material, "client", time.Now()); err != statedb.ErrInvalidGrant {
		t.Fatalf("grant after revocation = %v, want ErrInvalidGrant", err)
	}
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("missing no-store headers: %v", response.Header())
	}
}

// TestHandleRevokeAcceptsJWTAndHidesUnknownTokens verifies JWT sid revocation and RFC 7009 non-disclosure.
func TestHandleRevokeAcceptsJWTAndHidesUnknownTokens(t *testing.T) {
	server, store, signer := revokeServer(t)
	material := createRevocableGrant(t, store, "jwt-sid", "client")
	_, accessToken, err := signer.SignTokenPair(tokens.TokenContext{Email: "user@example.com", ClientID: "client", SID: "jwt-sid", Scopes: "openid", AuthTime: time.Now(), IDExpiry: time.Now().Add(time.Hour), AccessExpiry: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}

	unknown := revokeRequest(server, url.Values{"token": {"not-a-token"}, "client_id": {"client"}})
	if unknown.Code != http.StatusOK || unknown.Body.Len() != 0 {
		t.Fatalf("unknown-token response = %d %q, want empty 200", unknown.Code, unknown.Body.String())
	}
	response := revokeRequest(server, url.Values{"token": {accessToken}, "client_id": {"client"}})
	if response.Code != http.StatusOK || response.Body.Len() != 0 {
		t.Fatalf("JWT response = %d %q, want empty 200", response.Code, response.Body.String())
	}
	if _, _, err = store.PrepareRefresh(material, "client", time.Now()); err != statedb.ErrInvalidGrant {
		t.Fatalf("grant after JWT revocation = %v, want ErrInvalidGrant", err)
	}
}

// TestHandleRevokeAcceptsIDToken verifies ID tokens revoke their refresh family.
func TestHandleRevokeAcceptsIDToken(t *testing.T) {
	server, store, signer := revokeServer(t)
	material := createRevocableGrant(t, store, "id-token-sid", "client")
	idToken, _, err := signer.SignTokenPair(tokens.TokenContext{Email: "user@example.com", ClientID: "client", SID: "id-token-sid", Scopes: "openid", AuthTime: time.Now(), IDExpiry: time.Now().Add(time.Hour), AccessExpiry: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	response := revokeRequest(server, url.Values{"token": {idToken}, "client_id": {"client"}})
	if response.Code != http.StatusOK || response.Body.Len() != 0 {
		t.Fatalf("ID token response = %d %q, want empty 200", response.Code, response.Body.String())
	}
	if _, _, err = store.PrepareRefresh(material, "client", time.Now()); !errors.Is(err, statedb.ErrInvalidGrant) {
		t.Fatalf("grant after ID token revocation = %v", err)
	}
}

// TestHandleRevokeRejectsMalformedRequests verifies the strict RFC 7009 HTTP boundary.
func TestHandleRevokeRejectsMalformedRequests(t *testing.T) {
	server, _, _ := revokeServer(t)
	tests := []struct {
		name        string
		method      string
		target      string
		contentType string
		body        string
	}{
		{name: "wrong method", method: http.MethodGet, target: "/revoke", contentType: "application/x-www-form-urlencoded", body: "token=x&client_id=client"},
		{name: "query string", method: http.MethodPost, target: "/revoke?token=x", contentType: "application/x-www-form-urlencoded", body: "token=x&client_id=client"},
		{name: "wrong content type", method: http.MethodPost, target: "/revoke", contentType: "application/json", body: `{}`},
		{name: "missing token", method: http.MethodPost, target: "/revoke", contentType: "application/x-www-form-urlencoded", body: "client_id=client"},
		{name: "duplicate client", method: http.MethodPost, target: "/revoke", contentType: "application/x-www-form-urlencoded", body: "token=x&client_id=client&client_id=other"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.target, strings.NewReader(test.body))
			request.Header.Set("Content-Type", test.contentType)
			response := httptest.NewRecorder()
			server.HandleRevoke(response, request)
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"error":"invalid_request"`) {
				t.Fatalf("response = %d %q, want invalid_request", response.Code, response.Body.String())
			}
		})
	}
}
