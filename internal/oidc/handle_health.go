// Copyright 2025 Nadrama Pty Ltd
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"net/http"
)

// HandleHealth handles the health check endpoint (/healthz).
// It returns HTTP 200 OK to indicate the server is running.
func (s *Server) HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("OK")); err != nil {
		s.logger.Error("failed to write health response", "error", err)
	}
}
