// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/easy-oidc/easy-oidc/internal/templates"
	"github.com/easy-oidc/easy-oidc/internal/upstream"
)

// selectionPayload authenticates all identity-selection browser state.
type selectionPayload struct {
	State, ConnectorID, Subject string
	Emails                      []upstream.Email
	ExpiresAt                   time.Time
}

// selectionAEAD creates an AES-GCM cipher that owns random nonce generation.
// The selection key must not encrypt more than 2^32 tokens across all processes.
func (s *Server) selectionAEAD() (cipher.AEAD, error) {
	block, err := aes.NewCipher(s.selectionKey)
	if err != nil {
		return nil, fmt.Errorf("create selection cipher: %w", err)
	}
	return cipher.NewGCMWithRandomNonce(block)
}

// encryptSelection encrypts and authenticates an identity-selection payload.
func (s *Server) encryptSelection(payload selectionPayload) (string, error) {
	aead, err := s.selectionAEAD()
	if err != nil {
		return "", err
	}
	plain, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encode selection: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(aead.Seal(nil, nil, plain, nil)), nil
}

// decryptSelection decrypts and authenticates an identity-selection payload.
func (s *Server) decryptSelection(token string) (selectionPayload, error) {
	var payload selectionPayload
	aead, err := s.selectionAEAD()
	if err != nil {
		return payload, err
	}
	sealed, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return payload, fmt.Errorf("invalid selection token")
	}
	plain, err := aead.Open(nil, nil, sealed, nil)
	if err != nil {
		return payload, fmt.Errorf("invalid selection token")
	}
	if err = json.Unmarshal(plain, &payload); err != nil || time.Now().After(payload.ExpiresAt) {
		return payload, fmt.Errorf("invalid or expired selection token")
	}
	return payload, nil
}

// renderIdentitySelection renders all authenticated upstream email candidates.
func (s *Server) renderIdentitySelection(w http.ResponseWriter, stateToken, connectorID string, identity upstream.Identity) {
	token, err := s.encryptSelection(selectionPayload{State: stateToken, ConnectorID: connectorID, Subject: identity.Subject, Emails: identity.Emails, ExpiresAt: time.Now().Add(5 * time.Minute)})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	emails := make([]templates.EmailData, len(identity.Emails))
	for i, email := range identity.Emails {
		emails[i] = templates.EmailData{Address: email.Address, Verified: email.Verified, Primary: email.Primary}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err = s.templates.RenderPage(w, "identity", templates.IdentityData{Title: "Choose an email", Token: token, Emails: emails}); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// HandleIdentitySelect consumes a selection and its original OAuth state exactly once.
func (s *Server) HandleIdentitySelect(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid selection", http.StatusBadRequest)
		return
	}
	payload, err := s.decryptSelection(r.FormValue("token"))
	index, indexErr := strconv.Atoi(r.FormValue("index"))
	if err != nil || indexErr != nil || index < 0 || index >= len(payload.Emails) {
		http.Error(w, "invalid selection", http.StatusBadRequest)
		return
	}
	state, err := s.authCodeMgr.DecodeState(payload.State)
	if err != nil {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	if state.ConnectorID != payload.ConnectorID {
		http.Error(w, "connector does not match state", http.StatusBadRequest)
		return
	}
	s.acceptOrChallenge(w, r, *state, payload.ConnectorID, payload.Subject, payload.Emails[index])
}
