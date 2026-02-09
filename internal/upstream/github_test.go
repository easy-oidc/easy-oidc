// Copyright 2025 Nadrama Pty Ltd
// SPDX-License-Identifier: Apache-2.0

package upstream

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/easy-oidc/easy-oidc/internal/config"
	"golang.org/x/oauth2"
)

// newTestGitHubServer creates a test HTTP server that mimics the GitHub /user/emails API.
func newTestGitHubServer(t *testing.T, emails []githubEmail) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(emails); err != nil {
			t.Fatalf("failed to encode test emails: %v", err)
		}
	}))
}

// testToken returns a valid, non-expired OAuth2 token for use in tests.
func testToken() *oauth2.Token {
	return &oauth2.Token{
		AccessToken: "test-access-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Hour),
	}
}

// newTestConnector creates a GitHubConnector that uses apiURLOverride to route
// requests to the test server.
func newTestConnector(t *testing.T, ts *httptest.Server) *GitHubConnector {
	t.Helper()
	cfg := config.ConnectorConfig{Type: "github"}
	connector := NewGitHubConnector(cfg, "http://localhost/callback", "client-id", "client-secret")
	connector.apiURLOverride = ts.URL + "/user/emails"
	return connector
}

func TestGetUserEmail_PrimaryVerified(t *testing.T) {
	emails := []githubEmail{
		{Email: "secondary@example.com", Primary: false, Verified: true},
		{Email: "primary@example.com", Primary: true, Verified: true},
		{Email: "unverified@example.com", Primary: false, Verified: false},
	}

	ts := newTestGitHubServer(t, emails)
	defer ts.Close()

	connector := newTestConnector(t, ts)
	email, verified, err := connector.GetUserEmail(t.Context(), testToken())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !verified {
		t.Error("expected verified to be true")
	}
	if email != "primary@example.com" {
		t.Errorf("expected primary@example.com, got %s", email)
	}
}

func TestGetUserEmail_FallbackToVerified(t *testing.T) {
	emails := []githubEmail{
		{Email: "not-primary-but-verified@example.com", Primary: false, Verified: true},
		{Email: "unverified@example.com", Primary: false, Verified: false},
	}

	ts := newTestGitHubServer(t, emails)
	defer ts.Close()

	connector := newTestConnector(t, ts)
	email, verified, err := connector.GetUserEmail(t.Context(), testToken())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !verified {
		t.Error("expected verified to be true")
	}
	if email != "not-primary-but-verified@example.com" {
		t.Errorf("expected not-primary-but-verified@example.com, got %s", email)
	}
}

func TestGetUserEmail_NoVerifiedEmail(t *testing.T) {
	emails := []githubEmail{
		{Email: "unverified1@example.com", Primary: true, Verified: false},
		{Email: "unverified2@example.com", Primary: false, Verified: false},
	}

	ts := newTestGitHubServer(t, emails)
	defer ts.Close()

	connector := newTestConnector(t, ts)
	_, _, err := connector.GetUserEmail(t.Context(), testToken())
	if err == nil {
		t.Fatal("expected error for no verified email, got nil")
	}
	if !strings.Contains(err.Error(), "no verified email found") {
		t.Errorf("expected 'no verified email found' error, got: %v", err)
	}
}

func TestGetUserEmail_EmptyEmailList(t *testing.T) {
	ts := newTestGitHubServer(t, []githubEmail{})
	defer ts.Close()

	connector := newTestConnector(t, ts)
	_, _, err := connector.GetUserEmail(t.Context(), testToken())
	if err == nil {
		t.Fatal("expected error for empty email list, got nil")
	}
}

func TestGetUserEmail_PrivateNoReplyEmail(t *testing.T) {
	// GitHub users with private email get a noreply address as primary.
	// The noreply address is returned since it is primary+verified.
	// Admins must use the noreply address in groups_overrides config.
	emails := []githubEmail{
		{Email: "12345678+alice@users.noreply.github.com", Primary: true, Verified: true},
		{Email: "alice@example.com", Primary: false, Verified: true},
	}

	ts := newTestGitHubServer(t, emails)
	defer ts.Close()

	connector := newTestConnector(t, ts)
	email, verified, err := connector.GetUserEmail(t.Context(), testToken())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !verified {
		t.Error("expected verified to be true")
	}
	if email != "12345678+alice@users.noreply.github.com" {
		t.Errorf("expected noreply address (primary+verified), got %s", email)
	}
}

func TestGetUserEmail_OnlyNoReplyEmail(t *testing.T) {
	emails := []githubEmail{
		{Email: "12345678+alice@users.noreply.github.com", Primary: true, Verified: true},
	}

	ts := newTestGitHubServer(t, emails)
	defer ts.Close()

	connector := newTestConnector(t, ts)
	email, verified, err := connector.GetUserEmail(t.Context(), testToken())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !verified {
		t.Error("expected verified to be true")
	}
	if email != "12345678+alice@users.noreply.github.com" {
		t.Errorf("expected noreply address, got %s", email)
	}
}

func TestGetUserEmail_MultipleVerifiedNoPrimary(t *testing.T) {
	// Multiple verified emails, none primary - returns the first verified one
	emails := []githubEmail{
		{Email: "work@company.com", Primary: false, Verified: true},
		{Email: "personal@gmail.com", Primary: false, Verified: true},
		{Email: "old@legacy.com", Primary: false, Verified: true},
	}

	ts := newTestGitHubServer(t, emails)
	defer ts.Close()

	connector := newTestConnector(t, ts)
	email, verified, err := connector.GetUserEmail(t.Context(), testToken())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !verified {
		t.Error("expected verified to be true")
	}
	if email != "work@company.com" {
		t.Errorf("expected work@company.com (first verified), got %s", email)
	}
}

func TestGetUserEmail_PrimaryNotVerified(t *testing.T) {
	// Primary email is not verified, falls back to verified non-primary
	emails := []githubEmail{
		{Email: "primary-unverified@example.com", Primary: true, Verified: false},
		{Email: "secondary-verified@example.com", Primary: false, Verified: true},
	}

	ts := newTestGitHubServer(t, emails)
	defer ts.Close()

	connector := newTestConnector(t, ts)
	email, verified, err := connector.GetUserEmail(t.Context(), testToken())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !verified {
		t.Error("expected verified to be true")
	}
	if email != "secondary-verified@example.com" {
		t.Errorf("expected secondary-verified@example.com, got %s", email)
	}
}

func TestGetUserEmail_APIError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message": "Bad credentials"}`))
	}))
	defer ts.Close()

	connector := newTestConnector(t, ts)
	_, _, err := connector.GetUserEmail(t.Context(), testToken())
	if err == nil {
		t.Fatal("expected error for API failure, got nil")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("expected error to mention 401 status, got: %v", err)
	}
}

func TestGetUserEmail_InvalidJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`not valid json`))
	}))
	defer ts.Close()

	connector := newTestConnector(t, ts)
	_, _, err := connector.GetUserEmail(t.Context(), testToken())
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestNewGitHubConnector_DefaultScopes(t *testing.T) {
	cfg := config.ConnectorConfig{Type: "github"}
	connector := NewGitHubConnector(cfg, "http://localhost/callback", "client-id", "client-secret")

	if connector.hostname != "github.com" {
		t.Errorf("expected hostname github.com, got %s", connector.hostname)
	}
	if len(connector.config.Scopes) != 1 || connector.config.Scopes[0] != "user:email" {
		t.Errorf("expected default scopes [user:email], got %v", connector.config.Scopes)
	}
}

func TestNewGitHubConnector_CustomScopes(t *testing.T) {
	cfg := config.ConnectorConfig{
		Type:   "github",
		Scopes: []string{"user:email", "read:org"},
	}
	connector := NewGitHubConnector(cfg, "http://localhost/callback", "client-id", "client-secret")

	if len(connector.config.Scopes) != 2 {
		t.Errorf("expected 2 scopes, got %d", len(connector.config.Scopes))
	}
}

func TestNewGitHubConnector_GitHubEnterprise(t *testing.T) {
	cfg := config.ConnectorConfig{
		Type: "github",
		GitHub: &config.GitHubConfig{
			Hostname: "github.enterprise.com",
		},
	}
	connector := NewGitHubConnector(cfg, "http://localhost/callback", "client-id", "client-secret")

	if connector.hostname != "github.enterprise.com" {
		t.Errorf("expected hostname github.enterprise.com, got %s", connector.hostname)
	}
}

func TestNewGitHubConnector_GitHubEnterpriseEndpoints(t *testing.T) {
	cfg := config.ConnectorConfig{
		Type: "github",
		GitHub: &config.GitHubConfig{
			Hostname: "github.enterprise.com",
		},
	}
	connector := NewGitHubConnector(cfg, "http://localhost/callback", "client-id", "client-secret")

	expectedAuthURL := "https://github.enterprise.com/login/oauth/authorize"
	expectedTokenURL := "https://github.enterprise.com/login/oauth/access_token"

	if connector.config.Endpoint.AuthURL != expectedAuthURL {
		t.Errorf("expected GHE auth URL %s, got %s", expectedAuthURL, connector.config.Endpoint.AuthURL)
	}
	if connector.config.Endpoint.TokenURL != expectedTokenURL {
		t.Errorf("expected GHE token URL %s, got %s", expectedTokenURL, connector.config.Endpoint.TokenURL)
	}
}

func TestNewGitHubConnector_GitHubComEndpoints(t *testing.T) {
	cfg := config.ConnectorConfig{Type: "github"}
	connector := NewGitHubConnector(cfg, "http://localhost/callback", "client-id", "client-secret")

	// github.com should use the standard github.Endpoint from the oauth2 package
	if connector.config.Endpoint.AuthURL != "https://github.com/login/oauth/authorize" {
		t.Errorf("expected github.com auth URL, got %s", connector.config.Endpoint.AuthURL)
	}
	if connector.config.Endpoint.TokenURL != "https://github.com/login/oauth/access_token" {
		t.Errorf("expected github.com token URL, got %s", connector.config.Endpoint.TokenURL)
	}
}

func TestGetUserEmail_GitHubEnterpriseAPIPath(t *testing.T) {
	var requestedPath string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]githubEmail{
			{Email: "alice@enterprise.com", Primary: true, Verified: true},
		})
	}))
	defer ts.Close()

	cfg := config.ConnectorConfig{
		Type: "github",
		GitHub: &config.GitHubConfig{
			Hostname: "github.enterprise.com",
		},
	}
	connector := NewGitHubConnector(cfg, "http://localhost/callback", "client-id", "client-secret")
	connector.apiURLOverride = ts.URL + "/api/v3/user/emails"

	email, _, err := connector.GetUserEmail(t.Context(), testToken())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if email != "alice@enterprise.com" {
		t.Errorf("expected alice@enterprise.com, got %s", email)
	}
	if requestedPath != "/api/v3/user/emails" {
		t.Errorf("expected GHE API path /api/v3/user/emails, got %s", requestedPath)
	}
}
