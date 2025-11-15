// Copyright 2025 Nadrama Pty Ltd
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
	"strings"
	"testing"
	"time"

	"github.com/easy-oidc/easy-oidc/internal/config"
	"github.com/easy-oidc/easy-oidc/internal/storage"
	"github.com/easy-oidc/easy-oidc/internal/tokens"
)

func TestHandleToken_RequireGroups(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate keys: %v", err)
	}

	keyPair := &tokens.KeyPair{
		PrivateKey: privKey,
		PublicKey:  pubKey,
	}

	signer := tokens.NewSigner(keyPair, "test-kid", "https://test.example.com", time.Hour)

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
				IssuerURL:       "https://test.example.com",
				RequireGroups:   tt.globalRequireGroups,
				TokenTTLSeconds: 3600,
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

			srv := NewServer(cfg, nil, authCodeMgr, signer, groupResolver, []byte("{}"), logger)

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
