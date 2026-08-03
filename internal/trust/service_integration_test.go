// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/easy-oidc/easy-oidc/internal/config"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// tlsIssuer is an exact local OIDC discovery, JWKS, and JWT-signing fixture.
type tlsIssuer struct {
	t        *testing.T
	server   *httptest.Server
	key      *rsa.PrivateKey
	kid      string
	outage   bool
	redirect string
}

// newTLSIssuer starts a local TLS issuer with a fresh RSA key.
func newTLSIssuer(t *testing.T) *tlsIssuer {
	t.Helper()
	f := &tlsIssuer{t: t, kid: "current"}
	f.rotate()
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.serveHTTP))
	t.Cleanup(f.server.Close)
	return f
}

// serveHTTP serves only the exact discovery and JWKS resources.
func (f *tlsIssuer) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if f.outage {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if f.redirect != "" && r.URL.Path == "/.well-known/openid-configuration" {
		http.Redirect(w, r, f.redirect, http.StatusFound)
		return
	}
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": f.server.URL, "jwks_uri": f.server.URL + "/jwks"})
	case "/jwks":
		public, err := jwk.FromRaw(&f.key.PublicKey)
		if err != nil {
			f.t.Fatal(err)
		}
		_ = public.Set(jwk.KeyIDKey, f.kid)
		_ = public.Set(jwk.AlgorithmKey, jwa.RS256)
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []jwk.Key{public}})
	default:
		http.NotFound(w, r)
	}
}

// rotate replaces the fixture signing key and key ID.
func (f *tlsIssuer) rotate() {
	f.t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.t.Fatal(err)
	}
	f.key, f.kid = key, "kid-"+time.Now().Format("150405.000000000")
}

// sign signs configurable claims and protected headers.
func (f *tlsIssuer) sign(claims map[string]any, options ...any) string {
	f.t.Helper()
	now := time.Now().UTC()
	defaults := map[string]any{"iss": f.server.URL, "sub": "upstream-user", "aud": "client", "iat": now, "exp": now.Add(time.Hour), "repository": "acme/repo"}
	for k, v := range claims {
		defaults[k] = v
	}
	token := jwt.New()
	for k, v := range defaults {
		if err := token.Set(k, v); err != nil {
			f.t.Fatal(err)
		}
	}
	alg, key, kid := jwa.RS256, any(f.key), f.kid
	for _, option := range options {
		switch value := option.(type) {
		case jwa.SignatureAlgorithm:
			alg = value
		case *rsa.PrivateKey:
			key = value
		case string:
			kid = value
		}
	}
	headers := jws.NewHeaders()
	_ = headers.Set(jws.KeyIDKey, kid)
	signed, err := jwt.Sign(token, jwt.WithKey(alg, key, jws.WithProtectedHeaders(headers)))
	if err != nil {
		f.t.Fatal(err)
	}
	return string(signed)
}

// serviceForIssuer creates a production verifier with compiled policy schemas.
func serviceForIssuer(t *testing.T, issuer *tlsIssuer, policies ...string) *Service {
	t.Helper()
	bindings := make([]config.TrustBindingConfig, len(policies))
	policyMap := make(map[string]config.TrustPolicyConfig, len(policies))
	for i, repository := range policies {
		name := "policy" + string(rune('A'+i))
		policyMap[name] = config.TrustPolicyConfig{Issuer: "local", Subject: "trusted:user", Groups: []string{"builders"}, Claims: map[string]json.RawMessage{"repository": json.RawMessage(`{"const":` + mustJSON(t, repository) + `}`)}}
		bindings[i] = config.TrustBindingConfig{ID: "binding-" + name, TrustPolicy: name}
	}
	cfg := &config.Config{IssuerURL: "https://downstream.example", HTTPListenAddr: ":8080", Secrets: config.SecretsConfig{Provider: "env", SigningKeyName: "KEY"}, Connectors: map[string]config.ConnectorConfig{"google": {Type: "google", DisplayName: "Google", CredentialsSecret: "GOOGLE_KEY"}}, DefaultRedirectURIs: []string{"http://localhost/callback"}, GroupsOverrides: map[string]map[string][]string{}, Clients: map[string]config.ClientConfig{"client": {TrustBindings: bindings}, "other": {}}, OIDCTrust: config.OIDCTrustConfig{Issuers: map[string]config.TrustIssuerConfig{"local": {Provider: "oidc", IssuerURL: issuer.server.URL, SigningAlgs: []string{"RS256"}, MaxTokenAge: config.Duration(10 * time.Minute)}}, Policies: policyMap}}
	// Config.Load's trust compiler is intentionally exercised via JSON round trip.
	data, _ := json.Marshal(cfg)
	path := t.TempDir() + "/config.jsonc"
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(loaded, nil)
	service.client = issuer.server.Client()
	return service
}

// mustJSON marshals a fixture value.
func mustJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestVerifyAndEvaluateProductionPath covers standard claims, signatures, and exactly-one authorization.
func TestVerifyAndEvaluateProductionPath(t *testing.T) {
	issuer := newTLSIssuer(t)
	tests := []struct {
		name        string
		policies    []string
		claims      map[string]any
		options     []any
		want        string
		diagnostics int
	}{
		{"exactly one", []string{"acme/repo", "other/repo"}, nil, nil, "", 2},
		{"zero", []string{"other/a", "other/b"}, nil, nil, "no trust binding matched", 2},
		{"multiple", []string{"acme/repo", "acme/repo"}, nil, nil, "multiple trust bindings matched", 2},
		{"wrong audience", []string{"acme/repo"}, map[string]any{"aud": "other"}, nil, "standard claims are invalid", 0},
		{"multiple audience", []string{"acme/repo"}, map[string]any{"aud": []string{"client", "other"}}, nil, "standard claims are invalid", 0},
		{"azp mismatch", []string{"acme/repo"}, map[string]any{"azp": "other"}, nil, "authorized party is invalid", 0},
		{"empty subject", []string{"acme/repo"}, map[string]any{"sub": ""}, nil, "standard claims are invalid", 0},
		{"expired", []string{"acme/repo"}, map[string]any{"exp": time.Now().Add(-time.Minute)}, nil, "token verification failed", 0},
		{"future nbf", []string{"acme/repo"}, map[string]any{"nbf": time.Now().Add(time.Hour)}, nil, "token verification failed", 0},
		{"stale iat", []string{"acme/repo"}, map[string]any{"iat": time.Now().Add(-time.Hour)}, nil, "standard claims are invalid", 0},
		{"future iat", []string{"acme/repo"}, map[string]any{"iat": time.Now().Add(time.Hour)}, nil, "token verification failed", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := serviceForIssuer(t, issuer, tt.policies...).VerifyAndEvaluate(context.Background(), issuer.sign(tt.claims, tt.options...), "client")
			if tt.want == "" {
				if err != nil || result.Binding == nil {
					t.Fatalf("result=%+v err=%v", result, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("result=%+v err=%v, want %q", result, err, tt.want)
			}
			if result != nil && len(result.Diagnostics) != tt.diagnostics {
				t.Fatalf("diagnostics=%+v", result.Diagnostics)
			}
			if err != nil && result != nil && result.Binding != nil {
				t.Fatal("denial retained binding")
			}
		})
	}
}

// TestVerifyAndEvaluateInfrastructureFailures covers signature, discovery, outage, and key rotation paths.
func TestVerifyAndEvaluateInfrastructureFailures(t *testing.T) {
	issuer := newTLSIssuer(t)
	t.Run("wrong signature", func(t *testing.T) {
		other, _ := rsa.GenerateKey(rand.Reader, 2048)
		_, err := serviceForIssuer(t, issuer, "acme/repo").VerifyAndEvaluate(context.Background(), issuer.sign(nil, other), "client")
		if err == nil {
			t.Fatal("accepted wrong signature")
		}
	})
	t.Run("wrong algorithm", func(t *testing.T) {
		_, err := serviceForIssuer(t, issuer, "acme/repo").VerifyAndEvaluate(context.Background(), issuer.sign(nil, jwa.PS256), "client")
		if err == nil {
			t.Fatal("accepted wrong algorithm")
		}
	})
	t.Run("cross origin redirect", func(t *testing.T) {
		issuer.redirect = "https://example.com/metadata"
		defer func() { issuer.redirect = "" }()
		_, err := serviceForIssuer(t, issuer, "acme/repo").VerifyAndEvaluate(context.Background(), issuer.sign(nil), "client")
		if err == nil {
			t.Fatal("followed cross-origin redirect")
		}
	})
	t.Run("outage", func(t *testing.T) {
		issuer.outage = true
		defer func() { issuer.outage = false }()
		_, err := serviceForIssuer(t, issuer, "acme/repo").VerifyAndEvaluate(context.Background(), issuer.sign(nil), "client")
		if err == nil {
			t.Fatal("ignored outage")
		}
	})
	t.Run("unknown kid rotation", func(t *testing.T) {
		service := serviceForIssuer(t, issuer, "acme/repo")
		old := issuer.sign(nil)
		if _, err := service.VerifyAndEvaluate(context.Background(), old, "client"); err != nil {
			t.Fatal(err)
		}
		issuer.rotate()
		if _, err := service.VerifyAndEvaluate(context.Background(), issuer.sign(nil), "client"); err != nil {
			t.Fatalf("rotation failed: %v", err)
		}
		if _, err := service.VerifyAndEvaluate(context.Background(), issuer.sign(nil, "never-seen"), "client"); err == nil {
			t.Fatal("unknown kid accepted")
		}
	})
}
