// Copyright 2025 Nadrama Pty Ltd
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// Signer signs OpenID Connect ID tokens using Ed25519.
type Signer struct {
	keyPair   *KeyPair
	kid       string
	issuerURL string
	tokenTTL  time.Duration
}

// NewSigner creates a new token signer with the provided key pair, key ID, issuer URL, and token TTL.
func NewSigner(keyPair *KeyPair, kid, issuerURL string, tokenTTL time.Duration) *Signer {
	return &Signer{
		keyPair:   keyPair,
		kid:       kid,
		issuerURL: issuerURL,
		tokenTTL:  tokenTTL,
	}
}

// SignIDToken signs an OpenID Connect ID token with the provided claims.
// The email is normalized and used as the subject (sub) claim.
func (s *Signer) SignIDToken(email, clientID string, groups []string, nonce string) (string, error) {
	now := time.Now()

	sub := NormalizeEmail(email)
	username := ExtractUsername(email)

	token := jwt.New()
	if err := token.Set(jwt.IssuerKey, s.issuerURL); err != nil {
		return "", err
	}
	if err := token.Set(jwt.AudienceKey, clientID); err != nil {
		return "", err
	}
	if err := token.Set(jwt.SubjectKey, sub); err != nil {
		return "", err
	}
	if err := token.Set("email", email); err != nil {
		return "", err
	}
	if err := token.Set("email_verified", true); err != nil {
		return "", err
	}
	if err := token.Set("preferred_username", username); err != nil {
		return "", err
	}
	if err := token.Set("groups", groups); err != nil {
		return "", err
	}
	if err := token.Set(jwt.IssuedAtKey, now); err != nil {
		return "", err
	}
	if err := token.Set(jwt.ExpirationKey, now.Add(s.tokenTTL)); err != nil {
		return "", err
	}
	if nonce != "" {
		if err := token.Set("nonce", nonce); err != nil {
			return "", err
		}
	}

	hdrs := jws.NewHeaders()
	if err := hdrs.Set(jws.KeyIDKey, s.kid); err != nil {
		return "", err
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.EdDSA, s.keyPair.PrivateKey, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return string(signed), nil
}

// NormalizeEmail normalizes an email address to lowercase and trims whitespace.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// ExtractUsername extracts the username (local part) from an email address.
// If the email has no @ symbol, the full email is returned.
func ExtractUsername(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) > 0 {
		return parts[0]
	}
	return email
}
