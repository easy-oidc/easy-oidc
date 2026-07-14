// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func TestSupportedSigningAlgorithms(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p521Key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		algorithm string
		key       any
	}{
		{"RS256", rsaKey}, {"RS384", rsaKey}, {"RS512", rsaKey},
		{"PS256", rsaKey}, {"PS384", rsaKey}, {"PS512", rsaKey},
		{"ES256", p256Key}, {"ES384", p384Key}, {"ES512", p521Key},
		{"EdDSA", ed25519Key},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			signingKey, err := ParsePrivateKey(privateKeyPEM(t, tt.key), tt.algorithm)
			if err != nil {
				t.Fatalf("ParsePrivateKey() error = %v", err)
			}

			signer := NewSigner(signingKey, "test-kid", "https://auth.example.com", time.Hour)
			tokenString, err := signer.SignIDToken(
				"Alice@Example.COM", "test-client", []string{"admins"}, "test-nonce",
			)
			if err != nil {
				t.Fatalf("SignIDToken() error = %v", err)
			}

			token, err := jwt.Parse(
				[]byte(tokenString),
				jwt.WithKey(signingKey.Algorithm, signingKey.PublicKey),
				jwt.WithValidate(true),
			)
			if err != nil {
				t.Fatalf("failed to verify token: %v", err)
			}
			if token.Subject() != "alice@example.com" {
				t.Errorf("subject = %q, want alice@example.com", token.Subject())
			}
			if username, _ := token.Get("preferred_username"); username != "Alice" {
				t.Errorf("preferred_username = %q, want Alice", username)
			}

			jwksData, err := GenerateJWKS(signingKey, "test-kid")
			if err != nil {
				t.Fatalf("GenerateJWKS() error = %v", err)
			}
			set, err := jwk.Parse(jwksData)
			if err != nil {
				t.Fatalf("failed to parse JWKS: %v", err)
			}
			key, ok := set.Key(0)
			if !ok {
				t.Fatal("JWKS does not contain a key")
			}
			if key.Algorithm().String() != tt.algorithm {
				t.Errorf("JWKS alg = %q, want %q", key.Algorithm(), tt.algorithm)
			}
			if key.KeyID() != "test-kid" {
				t.Errorf("JWKS kid = %q, want test-kid", key.KeyID())
			}
		})
	}
}

func TestParsePrivateKeyRejectsInvalidConfiguration(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		pem       string
		algorithm string
	}{
		{"invalid PEM", "invalid", "RS256"},
		{"unsupported algorithm", privateKeyPEM(t, rsaKey), "HS256"},
		{"RSA algorithm with EC key", privateKeyPEM(t, p256Key), "RS256"},
		{"EC algorithm with RSA key", privateKeyPEM(t, rsaKey), "ES256"},
		{"wrong EC curve", privateKeyPEM(t, p256Key), "ES384"},
		{"EdDSA with RSA key", privateKeyPEM(t, rsaKey), "EdDSA"},
		{"RSA algorithm with Ed25519 key", privateKeyPEM(t, ed25519Key), "RS256"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParsePrivateKey(tt.pem, tt.algorithm); err == nil {
				t.Fatal("ParsePrivateKey() unexpectedly succeeded")
			}
		})
	}
}

func TestGenerateKeyIDIsStable(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signingKey, err := ParsePrivateKey(privateKeyPEM(t, key), "RS256")
	if err != nil {
		t.Fatal(err)
	}

	first, err := GenerateKeyID(signingKey)
	if err != nil {
		t.Fatal(err)
	}
	second, err := GenerateKeyID(signingKey)
	if err != nil {
		t.Fatal(err)
	}
	if first == "" || first != second {
		t.Fatalf("unstable key ID: %q != %q", first, second)
	}
}

func TestSigningAlgorithmJSONValues(t *testing.T) {
	for algorithm, want := range signingAlgorithms {
		data, err := json.Marshal(want)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != `"`+algorithm+`"` {
			t.Errorf("algorithm JSON = %s, want %q", data, algorithm)
		}
	}
}

func privateKeyPEM(t *testing.T, privateKey any) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}
