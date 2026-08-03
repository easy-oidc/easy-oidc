// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/easy-oidc/easy-oidc/internal/statedb"
	"github.com/easy-oidc/easy-oidc/internal/tokens"
)

// HandleRevoke implements RFC 7009 family revocation for refresh tokens.
func (s *Server) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	setOAuthNoStore(w)
	if r.Method != http.MethodPost || r.URL.RawQuery != "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "form POST is required")
		return
	}
	if media := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])); media != "application/x-www-form-urlencoded" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "form content type is required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTokenFormBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		oauthError(w, 400, "invalid_request", "invalid form")
		return
	}
	r.Body = io.NopCloser(strings.NewReader(string(body)))
	if err := r.ParseForm(); err != nil || len(r.PostForm["token"]) != 1 || len(r.PostForm["client_id"]) != 1 || r.PostForm.Get("token") == "" || r.PostForm.Get("client_id") == "" {
		oauthError(w, 400, "invalid_request", "token and client_id are required exactly once")
		return
	}
	material, err := statedb.ParseRefreshToken(r.PostForm.Get("token"))
	if err == nil {
		if err := s.store.RevokeRefreshToken(material, r.PostForm.Get("client_id"), "application", time.Now().UTC()); err != nil {
			oauthError(w, 503, "temporarily_unavailable", "storage unavailable")
			return
		}
		s.logger.Info("refresh grant revoked", "client_id", r.PostForm.Get("client_id"))
	} else if token, verifyErr := s.signer.VerifyToken(r.PostForm.Get("token")); verifyErr == nil && tokens.HasAudience(token, r.PostForm.Get("client_id")) {
		if sid, ok := token.Get("sid"); ok {
			if err := s.store.RevokeGrant(fmt.Sprint(sid), r.PostForm.Get("client_id"), "application", time.Now().UTC()); err != nil {
				oauthError(w, 503, "temporarily_unavailable", "storage unavailable")
				return
			}
		}
	}
	w.WriteHeader(http.StatusOK)
}
