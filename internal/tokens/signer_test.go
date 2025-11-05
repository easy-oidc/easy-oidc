// Copyright 2025 Nadrama Pty Ltd
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func TestSignAndVerifyIDToken(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	keyPair := &KeyPair{
		PrivateKey: privKey,
		PublicKey:  pubKey,
	}

	signer := NewSigner(keyPair, "test-kid", "https://auth.example.com", time.Hour)

	email := "alice@example.com"
	clientID := "test-client"
	groups := []string{"admins", "developers"}
	nonce := "test-nonce"

	tokenString, err := signer.SignIDToken(email, clientID, groups, nonce)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	if tokenString == "" {
		t.Fatal("token string is empty")
	}

	token, err := jwt.Parse([]byte(tokenString), jwt.WithKey(jwa.EdDSA, pubKey), jwt.WithValidate(true))
	if err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}

	if token.Issuer() != "https://auth.example.com" {
		t.Errorf("expected issuer https://auth.example.com, got %s", token.Issuer())
	}

	if len(token.Audience()) != 1 || token.Audience()[0] != clientID {
		t.Errorf("expected audience %s, got %v", clientID, token.Audience())
	}

	if token.Subject() != "alice@example.com" {
		t.Errorf("expected subject alice@example.com, got %s", token.Subject())
	}

	emailClaim, ok := token.Get("email")
	if !ok || emailClaim != email {
		t.Errorf("expected email %s, got %v", email, emailClaim)
	}

	_, ok = token.Get("groups")
	if !ok {
		t.Fatal("groups claim not found")
	}

	nonceClaim, ok := token.Get("nonce")
	if !ok || nonceClaim != nonce {
		t.Errorf("expected nonce %s, got %v", nonce, nonceClaim)
	}

	usernameClaim, ok := token.Get("preferred_username")
	if !ok || usernameClaim != "alice" {
		t.Errorf("expected preferred_username alice, got %v", usernameClaim)
	}
}

func TestParseEd25519PrivateKey(t *testing.T) {
	validPEM := `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIFYOURxCMy8dPaRvPHtVMr0qH9FeX9QJR5KHLHmYxZI8
-----END PRIVATE KEY-----`

	keyPair, err := ParseEd25519PrivateKey(validPEM)
	if err != nil {
		t.Fatalf("failed to parse valid Ed25519 key: %v", err)
	}

	if keyPair == nil {
		t.Fatal("keyPair is nil")
	}

	if len(keyPair.PublicKey) != ed25519.PublicKeySize {
		t.Errorf("expected public key size %d, got %d", ed25519.PublicKeySize, len(keyPair.PublicKey))
	}

	if len(keyPair.PrivateKey) != ed25519.PrivateKeySize {
		t.Errorf("expected private key size %d, got %d", ed25519.PrivateKeySize, len(keyPair.PrivateKey))
	}

	_, err = ParseEd25519PrivateKey("invalid pem")
	if err == nil {
		t.Error("expected error for invalid PEM")
	}

	invalidTypePEM := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF3H9w9w==
-----END RSA PRIVATE KEY-----`

	_, err = ParseEd25519PrivateKey(invalidTypePEM)
	if err == nil {
		t.Error("expected error for non-Ed25519 key")
	}
}

func TestNormalizeEmailInSigner(t *testing.T) {
	pubKey, privKey, _ := ed25519.GenerateKey(nil)
	keyPair := &KeyPair{
		PrivateKey: privKey,
		PublicKey:  pubKey,
	}

	signer := NewSigner(keyPair, "test-kid", "https://auth.example.com", time.Hour)

	tokenString, err := signer.SignIDToken("Alice@Example.COM", "test-client", []string{}, "")
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	token, err := jwt.Parse([]byte(tokenString), jwt.WithKey(jwa.EdDSA, pubKey))
	if err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}

	if token.Subject() != "alice@example.com" {
		t.Errorf("expected normalized subject alice@example.com, got %s", token.Subject())
	}
}

func TestExtractUsernameFromEmail(t *testing.T) {
	pubKey, privKey, _ := ed25519.GenerateKey(nil)
	keyPair := &KeyPair{
		PrivateKey: privKey,
		PublicKey:  pubKey,
	}

	signer := NewSigner(keyPair, "test-kid", "https://auth.example.com", time.Hour)

	tests := []struct {
		email            string
		expectedUsername string
	}{
		{"alice@example.com", "alice"},
		{"bob.smith@test.com", "bob.smith"},
		{"charlie+tag@example.com", "charlie+tag"},
	}

	for _, tt := range tests {
		t.Run(tt.email, func(t *testing.T) {
			tokenString, err := signer.SignIDToken(tt.email, "test-client", []string{}, "")
			if err != nil {
				t.Fatalf("failed to sign token: %v", err)
			}

			token, err := jwt.Parse([]byte(tokenString), jwt.WithKey(jwa.EdDSA, pubKey))
			if err != nil {
				t.Fatalf("failed to parse token: %v", err)
			}

			username, ok := token.Get("preferred_username")
			if !ok {
				t.Fatal("preferred_username claim not found")
			}

			if username != tt.expectedUsername {
				t.Errorf("expected username %s, got %v", tt.expectedUsername, username)
			}
		})
	}
}
