// Copyright 2025 Nadrama Pty Ltd
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"net/http"
)

// HandleJWKS handles the JWKS endpoint (/jwks).
// It returns the JSON Web Key Set containing the public keys for token verification.
func (s *Server) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(s.jwksData); err != nil {
		s.logger.Error("failed to write JWKS response", "error", err)
	}
}
