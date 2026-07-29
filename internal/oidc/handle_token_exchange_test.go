// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/easy-oidc/easy-oidc/internal/config"
	"github.com/easy-oidc/easy-oidc/internal/tokens"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const (
	tokenExchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange"
	idTokenType        = "urn:ietf:params:oauth:token-type:id_token"
)

// tokenExchangeIssuer is a local TLS discovery, JWKS, and signing fixture.
type tokenExchangeIssuer struct {
	t      *testing.T
	server *httptest.Server
	key    *rsa.PrivateKey
	kid    string
}

// newTokenExchangeIssuer starts a local TLS OIDC issuer.
func newTokenExchangeIssuer(t *testing.T) *tokenExchangeIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &tokenExchangeIssuer{t: t, key: key, kid: "upstream-key"}
	fixture.server = httptest.NewTLSServer(http.HandlerFunc(fixture.serveHTTP))
	t.Cleanup(fixture.server.Close)
	return fixture
}

// serveHTTP serves the fixture's discovery document and public key.
func (f *tokenExchangeIssuer) serveHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": f.server.URL, "jwks_uri": f.server.URL + "/jwks"})
	case "/jwks":
		key, err := jwk.FromRaw(&f.key.PublicKey)
		if err != nil {
			f.t.Fatal(err)
		}
		_ = key.Set(jwk.KeyIDKey, f.kid)
		_ = key.Set(jwk.AlgorithmKey, jwa.RS256)
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []jwk.Key{key}})
	default:
		http.NotFound(w, r)
	}
}

// sign creates an upstream ID token with optional claim replacements.
func (f *tokenExchangeIssuer) sign(replacements map[string]any) string {
	f.t.Helper()
	now := time.Now().UTC()
	claims := map[string]any{"iss": f.server.URL, "sub": "upstream-user", "aud": "client", "iat": now, "exp": now.Add(10 * time.Minute), "repository": "acme/project"}
	for name, value := range replacements {
		claims[name] = value
	}
	token := jwt.New()
	for name, value := range claims {
		if err := token.Set(name, value); err != nil {
			f.t.Fatal(err)
		}
	}
	headers := jws.NewHeaders()
	_ = headers.Set(jws.KeyIDKey, f.kid)
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, f.key, jws.WithProtectedHeaders(headers)))
	if err != nil {
		f.t.Fatal(err)
	}
	return string(signed)
}

// tokenExchangeServer constructs NewServer with compiled trust configuration and a real signer.
func tokenExchangeServer(t *testing.T, issuer *tokenExchangeIssuer, policies int) (*Server, *tokens.SigningKey) {
	t.Helper()
	policyConfig := make(map[string]config.TrustPolicyConfig, policies)
	bindings := make([]config.TrustBindingConfig, policies)
	for i := 0; i < policies; i++ {
		name := "policy-" + string(rune('a'+i))
		policyConfig[name] = config.TrustPolicyConfig{Issuer: "local", Subject: "trusted:builder", Groups: []string{"builders", "release"}, Claims: map[string]json.RawMessage{"repository": json.RawMessage(`{"const":"acme/project"}`)}}
		bindings[i] = config.TrustBindingConfig{ID: "binding-" + name, TrustPolicy: name}
	}
	cfg := &config.Config{IssuerURL: "https://downstream.example", HTTPListenAddr: ":8080", DataDir: t.TempDir(), Secrets: config.SecretsConfig{Provider: "env", SigningKeyName: "KEY"}, Connectors: map[string]config.ConnectorConfig{"google": {Type: "google", DisplayName: "Google", CredentialsSecret: "GOOGLE_KEY"}}, DefaultRedirectURIs: []string{"http://localhost/callback"}, GroupsOverrides: map[string]map[string][]string{}, IDTokenTTL: config.Duration(20 * time.Minute), AccessTokenTTL: config.Duration(time.Hour), Clients: map[string]config.ClientConfig{"client": {TrustBindings: bindings}, "other-client": {}}, OIDCTrust: config.OIDCTrustConfig{Issuers: map[string]config.TrustIssuerConfig{"local": {Provider: "oidc", IssuerURL: issuer.server.URL, SigningAlgs: []string{"RS256"}, MaxTokenAge: config.Duration(10 * time.Minute)}}, Policies: policyConfig}}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/config.jsonc"
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	key := newTestSigningKey(t)
	signer := tokens.NewSigner(key, "downstream-key", loaded.IssuerURL, time.Hour)
	originalTransport := http.DefaultTransport
	http.DefaultTransport = issuer.server.Client().Transport
	server := NewServer(loaded, nil, nil, signer, tokens.NewGroupResolver(nil), nil, nil, nil, nil, nil, nil, nil, nil, nil)
	http.DefaultTransport = originalTransport
	return server, key
}

// tokenExchangeRequest submits form values to the production token handler.
func tokenExchangeRequest(server *Server, values url.Values) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.HandleToken(response, request)
	return response
}

// validTokenExchangeForm returns a complete RFC 8693 ID-token exchange form.
func validTokenExchangeForm(raw string) url.Values {
	return url.Values{"grant_type": {tokenExchangeGrant}, "client_id": {"client"}, "subject_token": {raw}, "subject_token_type": {idTokenType}, "requested_token_type": {idTokenType}}
}

// TestTokenExchangeProductionPath verifies the complete HTTP, trust, and downstream signing path.
func TestTokenExchangeProductionPath(t *testing.T) {
	issuer := newTokenExchangeIssuer(t)
	server, signingKey := tokenExchangeServer(t, issuer, 1)
	response := tokenExchangeRequest(server, validTokenExchangeForm(issuer.sign(nil)))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("cache headers=%v", response.Header())
	}
	var body struct {
		AccessToken     string          `json:"access_token"`
		IssuedTokenType string          `json:"issued_token_type"`
		TokenType       string          `json:"token_type"`
		ExpiresIn       int64           `json:"expires_in"`
		IDToken         json.RawMessage `json:"id_token"`
		RefreshToken    json.RawMessage `json:"refresh_token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.AccessToken == "" || body.IssuedTokenType != idTokenType || body.TokenType != "Bearer" || body.ExpiresIn <= 0 || body.ExpiresIn > 900 {
		t.Fatalf("unexpected response: %+v", body)
	}
	if body.IDToken != nil || body.RefreshToken != nil {
		t.Fatalf("exchange returned forbidden token fields: %s", response.Body.String())
	}
	verified, err := jwt.Parse([]byte(body.AccessToken), jwt.WithKey(signingKey.Algorithm, signingKey.PublicKey), jwt.WithValidate(true))
	if err != nil {
		t.Fatalf("verify downstream token: %v", err)
	}
	groups, ok := verified.Get("groups")
	if verified.Subject() != "trusted:builder" || len(verified.Audience()) != 1 || verified.Audience()[0] != "client" || !ok {
		t.Fatalf("unexpected trusted identity claims: %v", verified)
	}
	encodedGroups, _ := json.Marshal(groups)
	if string(encodedGroups) != `["builders","release"]` || verified.JwtID() == "" {
		t.Fatalf("groups=%s jti=%q", encodedGroups, verified.JwtID())
	}
	upstreamIssuer, _ := verified.Get("upstream_issuer")
	upstreamSubject, _ := verified.Get("upstream_subject")
	if upstreamIssuer != issuer.server.URL || upstreamSubject != "upstream-user" {
		t.Fatalf("upstream provenance=%q/%q", upstreamIssuer, upstreamSubject)
	}
	if _, exists := verified.Get("sid"); exists {
		t.Fatal("trusted token unexpectedly contains sid")
	}
}

// TestTokenExchangeDenials verifies RFC 8693 inputs fail closed without reflecting credentials.
func TestTokenExchangeDenials(t *testing.T) {
	issuer := newTokenExchangeIssuer(t)
	ordinary, _ := tokenExchangeServer(t, issuer, 1)
	ambiguous, _ := tokenExchangeServer(t, issuer, 2)
	external := issuer.sign(nil)
	tests := []struct {
		name   string
		server *Server
		form   url.Values
	}{
		{"cross-client audience", ordinary, validTokenExchangeForm(issuer.sign(map[string]any{"aud": "other-client"}))},
		{"ambiguous bindings", ambiguous, validTokenExchangeForm(external)},
		{"unrelated parameter", ordinary, func() url.Values { v := validTokenExchangeForm(external); v.Set("scope", "openid"); return v }()},
		{"duplicate parameter", ordinary, func() url.Values {
			v := validTokenExchangeForm(external)
			v["client_id"] = []string{"client", "client"}
			return v
		}()},
		{"wrong subject token type", ordinary, func() url.Values {
			v := validTokenExchangeForm(external)
			v.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
			return v
		}()},
		{"wrong requested token type", ordinary, func() url.Values {
			v := validTokenExchangeForm(external)
			v.Set("requested_token_type", "urn:ietf:params:oauth:token-type:access_token")
			return v
		}()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := tokenExchangeRequest(test.server, test.form)
			if response.Code == http.StatusOK {
				t.Fatalf("exchange unexpectedly succeeded: %s", response.Body.String())
			}
			if strings.Contains(response.Body.String(), test.form.Get("subject_token")) {
				t.Fatal("OAuth error reflected the external token")
			}
			var body map[string]any
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body["error"] == nil {
				t.Fatalf("invalid OAuth error: %s", response.Body.String())
			}
		})
	}
}
