// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/truster-dev/truster/internal/config"
)

// TestDiscoveryRequiresExactIssuerAndSecureJWKS verifies metadata using the production HTTP path.
func TestDiscoveryRequiresExactIssuerAndSecureJWKS(t *testing.T) {
	var issuer string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, issuer, serverURL(r)+"jwks")
	}))
	defer server.Close()
	service := &Service{cfg: &config.Config{}, client: server.Client()}
	issuer = server.URL
	if _, err := service.discovery(context.Background(), config.TrustIssuerConfig{IssuerURL: issuer}); err != nil {
		t.Fatalf("valid discovery failed: %v", err)
	}
	issuer = server.URL + "/different"
	if _, err := service.discovery(context.Background(), config.TrustIssuerConfig{IssuerURL: server.URL}); err == nil {
		t.Fatal("accepted mismatched discovery issuer")
	}
}

// TestVerifyAndEvaluateNilSafety ensures optional trust configuration cannot panic request handling.
func TestVerifyAndEvaluateNilSafety(t *testing.T) {
	var service *Service
	if _, err := service.VerifyAndEvaluate(context.Background(), "token", "client"); err == nil {
		t.Fatal("nil service unexpectedly succeeded")
	}
}

// TestDecodePayloadPreservesAdjacentLargeIntegers verifies signed payload numbers are never float-remarshaled.
func TestDecodePayloadPreservesAdjacentLargeIntegers(t *testing.T) {
	left, right := "9007199254740992", "9007199254740993"
	payload := fmt.Sprintf(`{"left":%s,"right":%s}`, left, right)
	claims, err := decodePayload("e30." + rawURL([]byte(payload)) + ".signature")
	if err != nil {
		t.Fatal(err)
	}
	if claims["left"].(json.Number).String() != left || claims["right"].(json.Number).String() != right {
		t.Fatalf("numbers changed: %#v", claims)
	}
}

// TestSelectKeyAcceptsMissingAlgorithmAndRejectsAmbiguity verifies standards-compliant JWK selection.
func TestSelectKeyAcceptsMissingAlgorithmAndRejectsAmbiguity(t *testing.T) {
	key := testPublicJWK(t, "key")
	set := jwk.NewSet()
	if err := set.AddKey(key); err != nil {
		t.Fatal(err)
	}
	if _, err := selectKey(set, "key", "RS256"); err != nil {
		t.Fatalf("missing alg rejected: %v", err)
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.RS512); err != nil {
		t.Fatal(err)
	}
	if _, err := selectKey(set, "key", "RS256"); err == nil {
		t.Fatal("wrong JWK alg accepted")
	}
	_ = key.Remove(jwk.AlgorithmKey)
	if err := set.AddKey(testPublicJWK(t, "key")); err != nil {
		t.Fatal(err)
	}
	if _, err := selectKey(set, "key", "RS256"); err == nil {
		t.Fatal("duplicate kid accepted")
	}
	if _, err := selectKey(set, "unknown", "RS256"); err == nil {
		t.Fatal("unknown kid accepted")
	}
}

// TestIssuerCacheCoalescesAndRefreshes verifies bounded requests, rotation, and random-kid cooldown.
func TestIssuerCacheCoalescesAndRefreshes(t *testing.T) {
	var issuer string
	var mu sync.Mutex
	requests := 0
	current := testPublicJWK(t, "one")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		key := current
		mu.Unlock()
		if r.URL.Path == "/.well-known/openid-configuration" {
			_, _ = fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, issuer, issuer+"/jwks")
			return
		}
		data, _ := json.Marshal(map[string]any{"keys": []jwk.Key{key}})
		_, _ = w.Write(data)
	}))
	defer server.Close()
	issuer = server.URL
	service := &Service{cfg: &config.Config{}, client: server.Client(), cache: make(map[string]cachedIssuer)}
	configuration := config.TrustIssuerConfig{IssuerURL: issuer}
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = service.loadIssuer(context.Background(), configuration, false) }()
	}
	wg.Wait()
	mu.Lock()
	count := requests
	current = testPublicJWK(t, "two")
	mu.Unlock()
	if count != 2 {
		t.Fatalf("concurrent initial load made %d requests, want 2", count)
	}
	set, err := service.loadIssuer(context.Background(), configuration, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := selectKey(set, "two", "RS256"); err != nil {
		t.Fatalf("rotation not loaded: %v", err)
	}
	for range 10 {
		_, _ = service.loadIssuer(context.Background(), configuration, true)
	}
	mu.Lock()
	defer mu.Unlock()
	if requests != 4 {
		t.Fatalf("refresh cooldown made %d requests, want 4", requests)
	}
}

// TestIssuerCacheCoolsDownFailedRefreshes verifies outages cannot amplify random-key requests.
func TestIssuerCacheCoolsDownFailedRefreshes(t *testing.T) {
	var issuer string
	var mu sync.Mutex
	requests := 0
	outage := false
	key := testPublicJWK(t, "one")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		unavailable := outage
		mu.Unlock()
		if unavailable {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path == "/.well-known/openid-configuration" {
			_, _ = fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, issuer, issuer+"/jwks")
			return
		}
		data, _ := json.Marshal(map[string]any{"keys": []jwk.Key{key}})
		_, _ = w.Write(data)
	}))
	defer server.Close()
	issuer = server.URL
	service := &Service{cfg: &config.Config{}, client: server.Client(), cache: make(map[string]cachedIssuer)}
	configuration := config.TrustIssuerConfig{IssuerURL: issuer}
	if _, err := service.loadIssuer(context.Background(), configuration, false); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	outage = true
	mu.Unlock()
	if _, err := service.loadIssuer(context.Background(), configuration, true); err == nil {
		t.Fatal("forced refresh unexpectedly succeeded during outage")
	}
	for range 10 {
		_, _ = service.loadIssuer(context.Background(), configuration, true)
	}
	mu.Lock()
	defer mu.Unlock()
	if requests != 3 {
		t.Fatalf("failed refresh cooldown made %d requests, want 3", requests)
	}
}

// testPublicJWK creates an RSA public JWK without an alg member.
func testPublicJWK(t *testing.T, kid string) jwk.Key {
	t.Helper()
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key, err := jwk.FromRaw(&private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatal(err)
	}
	return key
}

// rawURL returns unpadded base64url.
func rawURL(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }

// serverURL reconstructs the TLS test server origin.
func serverURL(r *http.Request) string { return "https://" + r.Host + "/" }
