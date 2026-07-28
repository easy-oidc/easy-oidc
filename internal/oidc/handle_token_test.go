// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/easy-oidc/easy-oidc/internal/config"
	"github.com/easy-oidc/easy-oidc/internal/storage"
	"github.com/easy-oidc/easy-oidc/internal/tokens"
	"github.com/easy-oidc/easy-oidc/internal/upstream"
	"github.com/lestrrat-go/jwx/v2/jwa"
)

func TestHandleToken_RequireGroups(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate keys: %v", err)
	}

	signingKey := &tokens.SigningKey{
		Algorithm:  jwa.EdDSA,
		PrivateKey: privKey,
		PublicKey:  pubKey,
	}

	signer := tokens.NewSigner(signingKey, "test-kid", "https://test.example.com", time.Hour)

	tests := []struct {
		name                string
		globalRequireGroups *bool
		clientRequireGroups *bool
		userGroups          []string
		expectSuccess       bool
		expectedError       string
	}{
		{
			name:                "global true, client unset, empty groups - reject",
			globalRequireGroups: boolPtr(true),
			clientRequireGroups: nil,
			userGroups:          []string{},
			expectSuccess:       false,
			expectedError:       "access_denied",
		},
		{
			name:                "global true, client false, empty groups - allow",
			globalRequireGroups: boolPtr(true),
			clientRequireGroups: boolPtr(false),
			userGroups:          []string{},
			expectSuccess:       true,
		},
		{
			name:                "global false, client true, empty groups - reject",
			globalRequireGroups: boolPtr(false),
			clientRequireGroups: boolPtr(true),
			userGroups:          []string{},
			expectSuccess:       false,
			expectedError:       "access_denied",
		},
		{
			name:                "global false, client unset, empty groups - allow",
			globalRequireGroups: boolPtr(false),
			clientRequireGroups: nil,
			userGroups:          []string{},
			expectSuccess:       true,
		},
		{
			name:                "global nil (default true), client unset, empty groups - reject",
			globalRequireGroups: nil,
			clientRequireGroups: nil,
			userGroups:          []string{},
			expectSuccess:       false,
			expectedError:       "access_denied",
		},
		{
			name:                "global true, client unset, with groups - allow",
			globalRequireGroups: boolPtr(true),
			clientRequireGroups: nil,
			userGroups:          []string{"admins"},
			expectSuccess:       true,
		},
		{
			name:                "global false, client false, with groups - allow",
			globalRequireGroups: boolPtr(false),
			clientRequireGroups: boolPtr(false),
			userGroups:          []string{"developers"},
			expectSuccess:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			groupResolver := tokens.NewGroupResolver(map[string]map[string][]string{
				"test-override": {
					"user@example.com": tt.userGroups,
				},
			})

			cfg := &config.Config{
				IssuerURL:      "https://test.example.com",
				RequireGroups:  tt.globalRequireGroups,
				AccessTokenTTL: config.Duration(time.Hour),
				IDTokenTTL:     config.Duration(time.Hour),
				Clients: map[string]config.ClientConfig{
					"test-client": {
						RequireGroups:  tt.clientRequireGroups,
						GroupsOverride: "test-override",
					},
				},
			}

			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
			store, err := storage.New(t.TempDir()+"/test.db", logger)
			if err != nil {
				t.Fatalf("failed to create storage: %v", err)
			}
			defer func() {
				if err := store.Close(); err != nil {
					t.Errorf("failed to close store: %v", err)
				}
			}()

			authCodeMgr, err := NewAuthCodeManager(store)
			if err != nil {
				t.Fatalf("failed to create auth code manager: %v", err)
			}

			srv := NewServer(cfg, nil, authCodeMgr, signer, groupResolver, []byte("{}"), logger, store, nil, nil, nil, nil, nil, nil)

			verifier := "test-verifier-dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
			hash := sha256.Sum256([]byte(verifier))
			challenge := base64.RawURLEncoding.EncodeToString(hash[:])

			authCode, err := authCodeMgr.GenerateCode(AuthCodePayload{
				ClientID:      "test-client",
				Email:         "user@example.com",
				RedirectURI:   "http://localhost/callback",
				CodeChallenge: challenge,
				Nonce:         "test-nonce",
			})
			if err != nil {
				t.Fatalf("failed to generate auth code: %v", err)
			}

			formData := url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {authCode},
				"client_id":     {"test-client"},
				"redirect_uri":  {"http://localhost/callback"},
				"code_verifier": {verifier},
			}

			req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(formData.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			w := httptest.NewRecorder()
			srv.HandleToken(w, req)

			if tt.expectSuccess {
				if w.Code != http.StatusOK {
					t.Errorf("expected status 200, got %d; body: %s", w.Code, w.Body.String())
				}

				var response map[string]interface{}
				if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}

				if _, ok := response["id_token"]; !ok {
					t.Error("expected id_token in response")
				}
			} else {
				if w.Code != http.StatusForbidden {
					t.Errorf("expected status 403, got %d", w.Code)
				}

				var response map[string]interface{}
				if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
					t.Fatalf("failed to decode error response: %v", err)
				}

				if response["error"] != tt.expectedError {
					t.Errorf("expected error %q, got %q", tt.expectedError, response["error"])
				}
			}
		})
	}
}

func boolPtr(b bool) *bool {
	return &b
}

// refreshTokenServer creates a token endpoint configured for one direct-email connector.
func refreshTokenServer(t *testing.T) (*Server, *storage.Store, *AuthCodeManager, []byte) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store, err := storage.New(t.TempDir()+"/test.db", logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	manager, err := NewAuthCodeManager(store)
	if err != nil {
		t.Fatal(err)
	}
	requireGroups := false
	cfg := &config.Config{
		IssuerURL:      "https://issuer.example",
		AccessTokenTTL: config.Duration(15 * time.Minute),
		IDTokenTTL:     config.Duration(10 * time.Minute),
		RequireGroups:  &requireGroups,
		Connectors:     map[string]config.ConnectorConfig{"provider": {Type: "email"}},
		Clients: map[string]config.ClientConfig{
			"client": {RefreshTokens: config.RefreshTokenConfig{Enabled: true, SessionIdleTTL: config.Duration(time.Hour), SessionAbsoluteTTL: config.Duration(4 * time.Hour)}},
		},
	}
	key := []byte("01234567890123456789012345678901")
	signer := tokens.NewSigner(newTestSigningKey(t), "kid", cfg.IssuerURL, time.Hour)
	return NewServer(cfg, nil, manager, signer, tokens.NewGroupResolver(nil), nil, logger, store, nil, nil, nil, nil, nil, key), store, manager, key
}

// exchangeCodeRequest sends a valid authorization-code token request.
func exchangeCodeRequest(server *Server, code, verifier string) *httptest.ResponseRecorder {
	values := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {"client"}, "redirect_uri": {"https://client.example/callback"}, "code_verifier": {verifier}}
	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.HandleToken(response, request)
	return response
}

// exitResponseWriter terminates its process when the token response body is written.
type exitResponseWriter struct{ header http.Header }

// Header returns the response headers accumulated before process termination.
func (w *exitResponseWriter) Header() http.Header { return w.header }

// WriteHeader accepts headers so termination occurs specifically during body delivery.
func (*exitResponseWriter) WriteHeader(int) {}

// Write simulates losing the process and response after refresh rotation commits.
func (*exitResponseWriter) Write([]byte) (int, error) {
	os.Exit(0)
	return 0, nil
}

// responseLossServer opens a token endpoint over an existing direct-email refresh database.
func responseLossServer(t *testing.T, path string) (*Server, *storage.Store) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store, err := storage.New(path, logger)
	if err != nil {
		t.Fatal(err)
	}
	requireGroups := false
	cfg := &config.Config{
		IssuerURL:      "https://issuer.example",
		AccessTokenTTL: config.Duration(15 * time.Minute),
		IDTokenTTL:     config.Duration(10 * time.Minute),
		RequireGroups:  &requireGroups,
		Connectors:     map[string]config.ConnectorConfig{"provider": {Type: "email"}},
		Clients:        map[string]config.ClientConfig{"client": {RefreshTokens: config.RefreshTokenConfig{Enabled: true}}},
	}
	signer := tokens.NewSigner(newTestSigningKey(t), "kid", cfg.IssuerURL, time.Hour)
	return NewServer(cfg, nil, nil, signer, tokens.NewGroupResolver(nil), nil, logger, store, nil, nil, nil, nil, nil, nil), store
}

// TestResponseWriteCrashProcess exits from the production HTTP response writer after commit.
func TestResponseWriteCrashProcess(t *testing.T) {
	path := os.Getenv("EASY_OIDC_RESPONSE_CRASH_DB")
	if path == "" {
		t.Skip("subprocess helper")
	}
	server, _ := responseLossServer(t, path)
	values := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {os.Getenv("EASY_OIDC_RESPONSE_CRASH_TOKEN")}, "client_id": {"client"}}
	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.HandleToken(&exitResponseWriter{header: make(http.Header)}, request)
	t.Fatal("token response body was not written")
}

// TestResponseWriteLossReplaysAndRevokes verifies a lost committed response requires re-login.
func TestResponseWriteLossReplaysAndRevokes(t *testing.T) {
	path := t.TempDir() + "/response-loss.db"
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store, err := storage.New(path, logger)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	material, err := storage.GenerateRefreshMaterial()
	if err != nil {
		t.Fatal(err)
	}
	grant := storage.RefreshGrant{SID: "response-loss", ClientID: "client", Email: "user@example.com", Scopes: "openid", ConnectorID: "provider", Mode: "session", AuthTime: now, IdleTTL: time.Hour, AbsoluteExpiry: now.Add(2 * time.Hour)}
	if err = store.CreateRefreshGrant(grant, material, nil, nil, now); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestResponseWriteCrashProcess$")
	command.Env = append(os.Environ(), "EASY_OIDC_RESPONSE_CRASH_DB="+path, "EASY_OIDC_RESPONSE_CRASH_TOKEN="+material.Token)
	if output, runErr := command.CombinedOutput(); runErr != nil {
		t.Fatalf("response-write crash helper: %v\n%s", runErr, output)
	}
	server, store := responseLossServer(t, path)
	t.Cleanup(func() { _ = store.Close() })
	values := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {material.Token}, "client_id": {"client"}}
	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.HandleToken(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"error":"invalid_grant"`) {
		t.Fatalf("lost response retry = %d %q", response.Code, response.Body.String())
	}
	grants, err := store.ListActiveGrants("user@example.com", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 0 {
		t.Fatalf("replayed family remained active: %#v", grants)
	}
}

// TestHandleTokenIssuesAndRotatesDirectRefresh verifies authorization-code wiring into the refresh domain.
func TestHandleTokenIssuesAndRotatesDirectRefresh(t *testing.T) {
	server, _, manager, _ := refreshTokenServer(t)
	verifier := strings.Repeat("a", 43)
	code, err := manager.GenerateCode(AuthCodePayload{ClientID: "client", RedirectURI: "https://client.example/callback", CodeChallenge: computeChallenge(verifier), Email: "user@example.com", EmailVerified: true, Scopes: "openid email", RefreshMode: "session", AuthTime: time.Now().UTC(), ConnectorID: "provider", UpstreamSubject: "user@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	response := exchangeCodeRequest(server, code, verifier)
	if response.Code != http.StatusOK {
		t.Fatalf("code exchange = %d %q", response.Code, response.Body.String())
	}
	var issued map[string]any
	if err = json.Unmarshal(response.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	refreshToken, ok := issued["refresh_token"].(string)
	if !ok || refreshToken == "" {
		t.Fatalf("missing refresh token: %#v", issued)
	}
	values := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}, "client_id": {"client"}}
	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rotated := httptest.NewRecorder()
	server.HandleToken(rotated, request)
	if rotated.Code != http.StatusOK || strings.Contains(rotated.Body.String(), refreshToken) {
		t.Fatalf("refresh exchange = %d %q", rotated.Code, rotated.Body.String())
	}
}

// TestHandleTokenRejectsCredentialProvenanceDrift verifies provider credentials cannot become local grants.
func TestHandleTokenRejectsCredentialProvenanceDrift(t *testing.T) {
	server, store, manager, key := refreshTokenServer(t)
	verifier := strings.Repeat("a", 43)
	code, err := manager.GenerateCode(AuthCodePayload{ClientID: "client", RedirectURI: "https://client.example/callback", CodeChallenge: computeChallenge(verifier), Email: "user@example.com", EmailVerified: true, Scopes: "openid", RefreshMode: "session", AuthTime: time.Now().UTC(), ConnectorID: "provider", UpstreamSubject: "subject"})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := json.Marshal(upstream.Credential{AccessToken: "access", RefreshToken: "refresh", AccessExpiry: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	nonce, ciphertext, err := storage.EncryptTemporaryCredential(key, code, "client", "provider", credential)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.SaveFlowCredential("", code, "client", "provider", nonce, ciphertext, time.Now().UTC().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	response := exchangeCodeRequest(server, code, verifier)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"error":"invalid_grant"`) || strings.Contains(response.Body.String(), "refresh_token") {
		t.Fatalf("drift response = %d %q", response.Code, response.Body.String())
	}
}

// TestHandleTokenRejectsInvalidProtocolRequests verifies the strict public-client boundary.
func TestHandleTokenRejectsInvalidProtocolRequests(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	server := &Server{logger: logger}
	tests := []struct {
		name, method, target, contentType, body, authorization, wantError string
		wantStatus                                                        int
	}{
		{name: "wrong method", method: http.MethodGet, target: "/token", contentType: "application/x-www-form-urlencoded", wantStatus: http.StatusMethodNotAllowed, wantError: "invalid_request"},
		{name: "query parameters", method: http.MethodPost, target: "/token?grant_type=refresh_token", contentType: "application/x-www-form-urlencoded", wantStatus: http.StatusBadRequest, wantError: "invalid_request"},
		{name: "wrong content type", method: http.MethodPost, target: "/token", contentType: "application/json", body: `{}`, wantStatus: http.StatusBadRequest, wantError: "invalid_request"},
		{name: "missing grant type", method: http.MethodPost, target: "/token", contentType: "application/x-www-form-urlencoded", wantStatus: http.StatusBadRequest, wantError: "invalid_request"},
		{name: "unsupported grant type", method: http.MethodPost, target: "/token", contentType: "application/x-www-form-urlencoded", body: "grant_type=password", wantStatus: http.StatusBadRequest, wantError: "unsupported_grant_type"},
		{name: "duplicate parameter", method: http.MethodPost, target: "/token", contentType: "application/x-www-form-urlencoded", body: "grant_type=refresh_token&grant_type=authorization_code", wantStatus: http.StatusBadRequest, wantError: "invalid_request"},
		{name: "basic authentication", method: http.MethodPost, target: "/token", contentType: "application/x-www-form-urlencoded", body: "grant_type=refresh_token", authorization: "Basic Y2xpZW50OnNlY3JldA==", wantStatus: http.StatusBadRequest, wantError: "invalid_request"},
		{name: "client secret", method: http.MethodPost, target: "/token", contentType: "application/x-www-form-urlencoded", body: "grant_type=refresh_token&client_secret=secret", wantStatus: http.StatusBadRequest, wantError: "invalid_request"},
		{name: "empty client secret", method: http.MethodPost, target: "/token", contentType: "application/x-www-form-urlencoded", body: "grant_type=refresh_token&client_secret=", wantStatus: http.StatusBadRequest, wantError: "invalid_request"},
		{name: "refresh token on code grant", method: http.MethodPost, target: "/token", contentType: "application/x-www-form-urlencoded", body: "grant_type=authorization_code&refresh_token=token", wantStatus: http.StatusBadRequest, wantError: "invalid_request"},
		{name: "code on refresh grant", method: http.MethodPost, target: "/token", contentType: "application/x-www-form-urlencoded", body: "grant_type=refresh_token&code=code", wantStatus: http.StatusBadRequest, wantError: "invalid_request"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.target, strings.NewReader(test.body))
			request.Header.Set("Content-Type", test.contentType)
			request.Header.Set("Authorization", test.authorization)
			response := httptest.NewRecorder()
			server.HandleToken(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body=%q", response.Code, test.wantStatus, response.Body.String())
			}
			var payload map[string]any
			if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
				t.Fatal(err)
			}
			if payload["error"] != test.wantError {
				t.Fatalf("error = %v, want %s", payload["error"], test.wantError)
			}
			if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Pragma") != "no-cache" {
				t.Fatalf("missing no-store headers: %v", response.Header())
			}
		})
	}
}
