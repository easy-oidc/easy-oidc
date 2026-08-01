// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"crypto/ed25519"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/easy-oidc/easy-oidc/internal/authpolicy"
	"github.com/easy-oidc/easy-oidc/internal/config"
	"github.com/easy-oidc/easy-oidc/internal/tokens"
	"github.com/lestrrat-go/jwx/v2/jwa"
)

func TestHandleUserInfoVerifiesToken(t *testing.T) {
	issuer := "https://test.example.com"
	signingKey := newTestSigningKey(t)
	signer := tokens.NewSigner(signingKey, "test-kid", issuer, time.Hour)
	server := &Server{
		signer: signer,
		logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelError,
		})),
	}

	_, validToken, err := signer.SignTokenPair(tokens.TokenContext{Email: "user@example.com", EmailVerified: false, ClientID: "test-client", Groups: []string{"users"}, Scopes: "openid email", AuthTime: time.Now(), IDExpiry: time.Now().Add(time.Hour), AccessExpiry: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatalf("failed to sign valid token: %v", err)
	}
	forgedSigner := tokens.NewSigner(newTestSigningKey(t), "test-kid", issuer, time.Hour)
	forgedToken, err := forgedSigner.SignIDToken("attacker@example.com", true, "test-client", nil, "")
	if err != nil {
		t.Fatalf("failed to sign forged token: %v", err)
	}
	expiredSigner := tokens.NewSigner(signingKey, "test-kid", issuer, -time.Minute)
	expiredToken, err := expiredSigner.SignIDToken("user@example.com", true, "test-client", nil, "")
	if err != nil {
		t.Fatalf("failed to sign expired token: %v", err)
	}
	wrongIssuerSigner := tokens.NewSigner(signingKey, "test-kid", "https://attacker.example.com", time.Hour)
	wrongIssuerToken, err := wrongIssuerSigner.SignIDToken("user@example.com", true, "test-client", nil, "")
	if err != nil {
		t.Fatalf("failed to sign wrong-issuer token: %v", err)
	}

	tests := []struct {
		name       string
		token      string
		wantStatus int
	}{
		{name: "valid token", token: validToken, wantStatus: http.StatusOK},
		{name: "forged token", token: forgedToken, wantStatus: http.StatusUnauthorized},
		{name: "expired token", token: expiredToken, wantStatus: http.StatusUnauthorized},
		{name: "wrong issuer", token: wrongIssuerToken, wantStatus: http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
			req.Header.Set("Authorization", "Bearer "+tt.token)
			response := httptest.NewRecorder()

			server.HandleUserInfo(response, req)

			if response.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", response.Code, tt.wantStatus, response.Body.String())
			}
			if tt.name == "valid token" && !strings.Contains(response.Body.String(), `"email_verified":false`) {
				t.Fatalf("userinfo did not preserve email_verified=false: %s", response.Body.String())
			}
		})
	}
}

func newTestSigningKey(t *testing.T) *tokens.SigningKey {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate signing key: %v", err)
	}
	return &tokens.SigningKey{
		Algorithm:  jwa.EdDSA,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}
}

// TestHandleUserInfoRevalidatesDynamicClient verifies current client auth and failure mapping.
func TestHandleUserInfoRevalidatesDynamicClient(t *testing.T) {
	issuer := "https://test.example.com"
	signer := tokens.NewSigner(newTestSigningKey(t), "kid", issuer, time.Hour)
	_, access, err := signer.SignTokenPair(tokens.TokenContext{Email: "user@example.com", ClientID: "dynamic", Scopes: "openid", AuthTime: time.Now(), IDExpiry: time.Now().Add(time.Hour), AccessExpiry: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		err  error
		want int
	}{{"accepted", nil, http.StatusOK}, {"denied", authpolicy.ErrDenied, http.StatusUnauthorized}, {"indeterminate", &authpolicy.IndeterminateError{Err: context.DeadlineExceeded}, http.StatusServiceUnavailable}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := &fakePolicyResolver{client: authpolicy.ResolvedClient{Config: config.ClientConfig{}}, clientErrors: []error{test.err}}
			server := &Server{config: &config.Config{}, signer: signer, policyResolver: fake, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
			request := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
			request.Header.Set("Authorization", "Bearer "+access)
			response := httptest.NewRecorder()
			server.HandleUserInfo(response, request)
			if response.Code != test.want || fake.resolveClientCalls != 1 {
				t.Fatalf("status=%d calls=%d body=%s", response.Code, fake.resolveClientCalls, response.Body.String())
			}
		})
	}
}
