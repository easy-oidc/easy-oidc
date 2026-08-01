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

// TestSignTokenPairIssuesPurposeSpecificClaims verifies refreshed token-pair semantics.
func TestSignTokenPairIssuesPurposeSpecificClaims(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signingKey, err := ParsePrivateKey(privateKeyPEM(t, key), "RS256")
	if err != nil {
		t.Fatal(err)
	}
	signer := NewSigner(signingKey, "test-kid", "https://auth.example.com", time.Hour)
	now := time.Now().Truncate(time.Second)
	context := TokenContext{
		Email:         "Alice@Example.COM",
		EmailVerified: true,
		ClientID:      "test-client",
		Groups:        []string{"admins"},
		Nonce:         "initial-nonce",
		SID:           "session-id",
		Scopes:        "openid email",
		AuthTime:      now.Add(-time.Minute),
		IDExpiry:      now.Add(10 * time.Minute),
		AccessExpiry:  now.Add(5 * time.Minute),
	}

	idRaw, accessRaw, err := signer.SignTokenPair(context)
	if err != nil {
		t.Fatalf("SignTokenPair() error = %v", err)
	}
	if idRaw == accessRaw {
		t.Fatal("ID and access tokens are identical")
	}
	idToken, err := signer.VerifyToken(idRaw)
	if err != nil {
		t.Fatalf("verify ID token: %v", err)
	}
	accessToken, err := signer.VerifyAccessToken(accessRaw, context.ClientID)
	if err != nil {
		t.Fatalf("verify access token: %v", err)
	}

	assertTokenClaim(t, idToken, "sid", context.SID)
	assertTokenClaim(t, idToken, "nonce", context.Nonce)
	assertTokenClaim(t, idToken, "auth_time", float64(context.AuthTime.Unix()))
	assertTokenClaim(t, accessToken, "sid", context.SID)
	assertTokenClaim(t, accessToken, "scope", context.Scopes)
	if _, ok := idToken.Get("scope"); ok {
		t.Fatal("ID token contains access-token scope claim")
	}
	if _, ok := accessToken.Get("nonce"); ok {
		t.Fatal("access token contains nonce")
	}
	if idToken.Subject() != "alice@example.com" || accessToken.Subject() != "alice@example.com" {
		t.Fatalf("subjects = %q, %q", idToken.Subject(), accessToken.Subject())
	}
	if idToken.Expiration().Unix() != context.IDExpiry.Unix() || accessToken.Expiration().Unix() != context.AccessExpiry.Unix() {
		t.Fatalf("expiries = %v, %v", idToken.Expiration(), accessToken.Expiration())
	}
	idJTI, idOK := idToken.Get(jwt.JwtIDKey)
	accessJTI, accessOK := accessToken.Get(jwt.JwtIDKey)
	if !idOK || !accessOK || idJTI == "" || accessJTI == "" || idJTI == accessJTI {
		t.Fatalf("token JTIs are missing or not distinct: %v, %v", idJTI, accessJTI)
	}
	if _, err := signer.VerifyAccessToken(idRaw, context.ClientID); err == nil {
		t.Fatal("VerifyAccessToken() accepted an ID token")
	}
	if _, err := signer.VerifyAccessToken(accessRaw, "other-client"); err == nil {
		t.Fatal("VerifyAccessToken() accepted the wrong audience")
	}
}

// assertTokenClaim checks one parsed JWT claim.
func assertTokenClaim(t *testing.T, token jwt.Token, name string, expected any) {
	t.Helper()
	actual, ok := token.Get(name)
	if !ok || actual != expected {
		t.Errorf("claim %q = %#v, want %#v", name, actual, expected)
	}
}

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
				"Alice@Example.COM", false, "test-client", []string{"admins"}, "test-nonce",
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
			if emailVerified, _ := token.Get("email_verified"); emailVerified != false {
				t.Errorf("email_verified = %v, want false", emailVerified)
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

// TestNormalizeEmail verifies canonical email normalization.
func TestNormalizeEmail(t *testing.T) {
	for input, expected := range map[string]string{
		"alice@example.com": "alice@example.com",
		"Alice@Example.Com": "alice@example.com",
		"  bob@test.com  ":  "bob@test.com",
		"CHARLIE@TEST.COM":  "charlie@test.com",
	} {
		if result := NormalizeEmail(input); result != expected {
			t.Errorf("NormalizeEmail(%q) = %q, want %q", input, result, expected)
		}
	}
}

// TestExtractUsername verifies username extraction from email-like subjects.
func TestExtractUsername(t *testing.T) {
	for email, expected := range map[string]string{
		"alice@example.com":  "alice",
		"bob.smith@test.com": "bob.smith",
		"charlie":            "charlie",
	} {
		if result := ExtractUsername(email); result != expected {
			t.Errorf("ExtractUsername(%q) = %q, want %q", email, result, expected)
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
