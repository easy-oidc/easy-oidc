// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/easy-oidc/easy-oidc/internal/authpolicy"
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

	token, err := s.signer.VerifyToken(tokenString)
	if err == nil {
		if scope, ok := token.Get("scope"); !ok || strings.TrimSpace(fmt.Sprint(scope)) == "" {
			err = fmt.Errorf("not an access token")
		}
		if len(token.Audience()) != 1 {
			err = fmt.Errorf("invalid audience")
		}
		if err == nil && s.config != nil {
			_, resolveErr := s.policyResolver.ResolveClient(r.Context(), token.Audience()[0], false)
			if resolveErr != nil {
				if !errors.Is(resolveErr, authpolicy.ErrDenied) {
					http.Error(w, "auth temporarily unavailable", http.StatusServiceUnavailable)
					return
				}
				err = fmt.Errorf("invalid audience")
			}
		}
	}
	if err != nil {
		s.logger.Error("failed to verify token", "error", err)
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	userInfo := map[string]interface{}{
		"sub": token.Subject(),
	}

	if email, ok := token.Get("email"); ok {
		userInfo["email"] = email
	}
	if emailVerified, ok := token.Get("email_verified"); ok {
		userInfo["email_verified"] = emailVerified
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
