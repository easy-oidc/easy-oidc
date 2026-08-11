// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// TestPublicEndpointRateLimitsRunBeforeHandlers verifies floods do no handler work.
func TestPublicEndpointRateLimitsRunBeforeHandlers(t *testing.T) {
	server := &Server{publicEndpointLimits: map[string]*rate.Limiter{}}
	for _, path := range []string{"/par", "/token", "/revoke"} {
		t.Run(path, func(t *testing.T) {
			server.publicEndpointLimits[path] = rate.NewLimiter(0, publicEndpointBurst)
			called := 0
			handler := server.LimitPublicEndpoints(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				called++
				w.WriteHeader(http.StatusNoContent)
			}))
			for range publicEndpointBurst {
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, nil))
				if response.Code != http.StatusNoContent {
					t.Fatalf("allowed status = %d", response.Code)
				}
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, nil))
			if response.Code != http.StatusTooManyRequests || called != publicEndpointBurst || response.Header().Get("Retry-After") != "1" {
				t.Fatalf("limited status=%d called=%d retry=%q", response.Code, called, response.Header().Get("Retry-After"))
			}
		})
	}
}

// TestEndpointLimiterRefillsAtConfiguredRate verifies deterministic token-bucket refill.
func TestEndpointLimiterRefillsAtConfiguredRate(t *testing.T) {
	now := time.Unix(100, 0)
	limiter := rate.NewLimiter(publicEndpointRate, 1)
	if !limiter.AllowN(now, 1) {
		t.Fatal("initial token was not available")
	}
	if !limiter.AllowN(now.Add(time.Second/100), 1) {
		t.Fatal("one token was not restored at the configured rate")
	}
	if limiter.AllowN(now.Add(time.Second/100), 1) {
		t.Fatal("refill admitted more than the configured rate")
	}
}
