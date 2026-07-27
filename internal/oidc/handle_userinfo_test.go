// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"crypto/ed25519"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

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

	validToken, err := signer.SignIDToken("user@example.com", "test-client", []string{"users"}, "")
	if err != nil {
		t.Fatalf("failed to sign valid token: %v", err)
	}
	forgedSigner := tokens.NewSigner(newTestSigningKey(t), "test-kid", issuer, time.Hour)
	forgedToken, err := forgedSigner.SignIDToken("attacker@example.com", "test-client", nil, "")
	if err != nil {
		t.Fatalf("failed to sign forged token: %v", err)
	}
	expiredSigner := tokens.NewSigner(signingKey, "test-kid", issuer, -time.Minute)
	expiredToken, err := expiredSigner.SignIDToken("user@example.com", "test-client", nil, "")
	if err != nil {
		t.Fatalf("failed to sign expired token: %v", err)
	}
	wrongIssuerSigner := tokens.NewSigner(signingKey, "test-kid", "https://attacker.example.com", time.Hour)
	wrongIssuerToken, err := wrongIssuerSigner.SignIDToken("user@example.com", "test-client", nil, "")
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
