// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"net/http"

	"golang.org/x/time/rate"
)

const (
	publicEndpointRate  = rate.Limit(100)
	publicEndpointBurst = 200
)

// LimitPublicEndpoints rate-limits expensive public endpoints before handler work.
func (s *Server) LimitPublicEndpoints(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limiter := s.publicEndpointLimits[r.URL.Path]
		if limiter != nil && !limiter.Allow() {
			w.Header().Set("Retry-After", "1")
			writeOAuthJSON(w, http.StatusTooManyRequests, "temporarily_unavailable")
			return
		}
		next.ServeHTTP(w, r)
	})
}
