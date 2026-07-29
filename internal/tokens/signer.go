// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// TokenContext contains claims shared by separately signed ID and access tokens.
type TokenContext struct {
	Email         string
	EmailVerified bool
	ClientID      string
	Groups        []string
	Nonce         string
	SID           string
	Scopes        string
	AuthTime      time.Time
	IDExpiry      time.Time
	AccessExpiry  time.Time
}

// TrustedTokenContext contains claims for a short-lived exchanged identity token.
type TrustedTokenContext struct {
	Subject, ClientID, UpstreamIssuer, UpstreamSubject string
	Groups                                             []string
	Expiry                                             time.Time
}

// SignTrustedIDToken signs an exchanged ID token without session or refresh claims.
func (s *Signer) SignTrustedIDToken(context TrustedTokenContext) (string, error) {
	now := time.Now().UTC()
	token := jwt.New()
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}
	claims := map[string]any{jwt.IssuerKey: s.issuerURL, jwt.SubjectKey: context.Subject, jwt.AudienceKey: context.ClientID, jwt.IssuedAtKey: now, jwt.ExpirationKey: context.Expiry, jwt.JwtIDKey: base64.RawURLEncoding.EncodeToString(jti), "groups": context.Groups, "upstream_issuer": context.UpstreamIssuer, "upstream_subject": context.UpstreamSubject}
	for key, value := range claims {
		if err := token.Set(key, value); err != nil {
			return "", fmt.Errorf("set %s claim: %w", key, err)
		}
	}
	hdrs := jws.NewHeaders()
	if err := hdrs.Set(jws.KeyIDKey, s.kid); err != nil {
		return "", err
	}
	signed, err := jwt.Sign(token, jwt.WithKey(s.signingKey.Algorithm, s.signingKey.PrivateKey, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		return "", fmt.Errorf("sign trusted token: %w", err)
	}
	return string(signed), nil
}

// SignTokenPair issues distinct ID and access JWTs with independent claims and expiries.
func (s *Signer) SignTokenPair(context TokenContext) (string, string, error) {
	id, err := s.signContext(context, true)
	if err != nil {
		return "", "", err
	}
	access, err := s.signContext(context, false)
	if err != nil {
		return "", "", err
	}
	return id, access, nil
}

// signContext signs one token from a grant context.
func (s *Signer) signContext(context TokenContext, identity bool) (string, error) {
	now := time.Now()
	token := jwt.New()
	claims := map[string]any{jwt.IssuerKey: s.issuerURL, jwt.AudienceKey: context.ClientID, jwt.SubjectKey: NormalizeEmail(context.Email), jwt.IssuedAtKey: now}
	expiry := context.AccessExpiry
	if identity {
		expiry = context.IDExpiry
	}
	claims[jwt.ExpirationKey] = expiry
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}
	claims[jwt.JwtIDKey] = base64.RawURLEncoding.EncodeToString(jti)
	if context.SID != "" {
		claims["sid"] = context.SID
	}
	if identity {
		claims["email"], claims["email_verified"], claims["preferred_username"], claims["groups"] = context.Email, context.EmailVerified, ExtractUsername(context.Email), context.Groups
		claims["auth_time"] = context.AuthTime.Unix()
		if context.Nonce != "" {
			claims["nonce"] = context.Nonce
		}
	} else {
		claims["scope"] = context.Scopes
		claims["email"], claims["email_verified"], claims["preferred_username"], claims["groups"] = context.Email, context.EmailVerified, ExtractUsername(context.Email), context.Groups
	}
	for key, value := range claims {
		if err := token.Set(key, value); err != nil {
			return "", fmt.Errorf("set %s claim: %w", key, err)
		}
	}
	hdrs := jws.NewHeaders()
	if err := hdrs.Set(jws.KeyIDKey, s.kid); err != nil {
		return "", err
	}
	signed, err := jwt.Sign(token, jwt.WithKey(s.signingKey.Algorithm, s.signingKey.PrivateKey, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}
	return string(signed), nil
}

// Signer signs OpenID Connect ID tokens.
type Signer struct {
	signingKey *SigningKey
	kid        string
	issuerURL  string
	tokenTTL   time.Duration
}

// NewSigner creates a new token signer with the provided signing key, key ID, issuer URL, and token TTL.
func NewSigner(signingKey *SigningKey, kid, issuerURL string, tokenTTL time.Duration) *Signer {
	return &Signer{
		signingKey: signingKey,
		kid:        kid,
		issuerURL:  issuerURL,
		tokenTTL:   tokenTTL,
	}
}

// SignIDToken signs an OpenID Connect ID token with the provided claims.
// The email is normalized and used as the subject (sub) claim.
func (s *Signer) SignIDToken(email string, emailVerified bool, clientID string, groups []string, nonce string) (string, error) {
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
	if err := token.Set("email_verified", emailVerified); err != nil {
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

	signed, err := jwt.Sign(token, jwt.WithKey(s.signingKey.Algorithm, s.signingKey.PrivateKey, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return string(signed), nil
}

// VerifyToken verifies a token signed by this signer and validates its issuer and expiry.
func (s *Signer) VerifyToken(token string) (jwt.Token, error) {
	verified, err := jwt.Parse(
		[]byte(token),
		jwt.WithKey(s.signingKey.Algorithm, s.signingKey.PublicKey),
		jwt.WithIssuer(s.issuerURL),
		jwt.WithRequiredClaim(jwt.ExpirationKey),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to verify token: %w", err)
	}
	return verified, nil
}

// HasAudience reports whether a verified token has exactly the required audience among its audiences.
func HasAudience(token jwt.Token, required string) bool {
	for _, audience := range token.Audience() {
		if audience == required {
			return true
		}
	}
	return false
}

// VerifyAccessToken verifies signature, issuer, expiry, audience, and access-token purpose.
func (s *Signer) VerifyAccessToken(raw, audience string) (jwt.Token, error) {
	token, err := s.VerifyToken(raw)
	if err != nil {
		return nil, err
	}
	if !HasAudience(token, audience) {
		return nil, fmt.Errorf("required audience is missing")
	}
	if scope, ok := token.Get("scope"); !ok || strings.TrimSpace(fmt.Sprint(scope)) == "" {
		return nil, fmt.Errorf("token is not an access token")
	}
	return token, nil
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
