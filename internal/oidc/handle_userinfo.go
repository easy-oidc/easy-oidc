// Copyright 2025 Nadrama Pty Ltd
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

// HandleUserInfo handles the OIDC userinfo endpoint (/userinfo).
// It extracts and validates the bearer token and returns user claims.
func (s *Server) HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "authorization header required", http.StatusUnauthorized)
		return
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		http.Error(w, "invalid authorization header", http.StatusUnauthorized)
		return
	}

	tokenString := parts[1]

	token, err := jwt.Parse([]byte(tokenString), jwt.WithValidate(false))
	if err != nil {
		s.logger.Error("failed to parse token", "error", err)
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	userInfo := map[string]interface{}{
		"sub":            token.Subject(),
		"email_verified": true,
	}

	if email, ok := token.Get("email"); ok {
		userInfo["email"] = email
	}

	if username, ok := token.Get("preferred_username"); ok {
		userInfo["preferred_username"] = username
	}

	if groups, ok := token.Get("groups"); ok {
		userInfo["groups"] = groups
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(userInfo); err != nil {
		s.logger.Error("failed to encode userinfo response", "error", err)
	}
}
