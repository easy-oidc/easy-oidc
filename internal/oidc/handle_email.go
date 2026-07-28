// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/easy-oidc/easy-oidc/internal/storage"
	"github.com/easy-oidc/easy-oidc/internal/templates"
)

// otpCode generates an eight-digit cryptographically random code.
func otpCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(100000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%08d", n.Int64()), nil
}

// normalizeEmail validates and lowercases a bare email address.
func normalizeEmail(value string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	address, err := mail.ParseAddress(normalized)
	if err != nil || address.Address != normalized {
		return "", fmt.Errorf("invalid email address")
	}
	return normalized, nil
}

// HandleEmailStart validates an email sign-in request and begins OTP verification.
func (s *Server) HandleEmailStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	state, err := s.authCodeMgr.DecodeState(r.FormValue("state"))
	if err != nil || state.ConnectorID != "" {
		http.Error(w, "invalid state", 400)
		return
	}
	connectorID := r.FormValue("connector")
	connector, ok := s.config.Connectors[connectorID]
	if !ok || connector.Type != "email" {
		http.Error(w, "invalid connector", 400)
		return
	}
	state.ConnectorID = connectorID
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if err = s.challenge.Verify(r.Context(), r.FormValue("cf-turnstile-response"), host); err != nil {
		http.Error(w, "request rejected", 400)
		return
	}
	email, err := normalizeEmail(r.FormValue("email"))
	if err != nil {
		http.Error(w, "invalid email", 400)
		return
	}
	s.beginOTP(w, r, *state, connectorID, email, email)
}

// beginOTP creates, sends, and renders a new OTP challenge.
func (s *Server) beginOTP(w http.ResponseWriter, r *http.Request, state OAuthState, id, subject, email string) {
	challenge, err := storage.GenerateStateToken()
	if err != nil {
		http.Error(w, "internal error", 500)
		return
	}
	code, err := otpCode()
	if err != nil {
		http.Error(w, "internal error", 500)
		return
	}
	flow := storage.OTPFlow{ConnectorID: id, Subject: subject, Email: email, ClientID: state.ClientID, RedirectURI: state.RedirectURI, CodeChallenge: state.CodeChallenge, Nonce: state.Nonce, OIDCState: state.OIDCState}
	otpTTL := time.Duration(s.config.Email.OTPTTLSeconds) * time.Second
	expiresAt, err := s.store.CreateOTP(challenge, email, code, flow, s.otpSecret, time.Now(), otpTTL)
	if err != nil {
		http.Error(w, "unable to send code", http.StatusTooManyRequests)
		return
	}
	if err = s.mailer.SendOTP(r.Context(), email, code, expiresAt); err != nil {
		s.logger.Error("send OTP", "error", err)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = s.templates.RenderPage(w, "otp", templates.OTPData{Title: "Verify email", ChallengeID: challenge, Message: "A code was sent."})
}

// HandleEmailVerify consumes an OTP and completes authorization.
func (s *Server) HandleEmailVerify(w http.ResponseWriter, r *http.Request) {
	if s.config.Email == nil || s.mailer == nil || len(s.otpSecret) == 0 {
		http.Error(w, "email verification unavailable", http.StatusNotFound)
		return
	}
	flow, err := s.store.ConsumeOTP(r.FormValue("challenge"), r.FormValue("code"), s.otpSecret, time.Now())
	if err != nil {
		http.Error(w, "invalid code", 400)
		return
	}
	if err = s.store.SaveCredential(flow.ConnectorID, flow.Subject, flow.Email, true, time.Now()); err != nil {
		http.Error(w, "internal error", 500)
		return
	}
	s.complete(w, r, OAuthState{ConnectorID: flow.ConnectorID, ClientID: flow.ClientID, RedirectURI: flow.RedirectURI, CodeChallenge: flow.CodeChallenge, Nonce: flow.Nonce, OIDCState: flow.OIDCState}, flow.Email, true)
}

// HandleEmailResend replaces and sends the code for an active challenge.
func (s *Server) HandleEmailResend(w http.ResponseWriter, r *http.Request) {
	if s.config.Email == nil || s.mailer == nil || len(s.otpSecret) == 0 {
		http.Error(w, "email verification unavailable", http.StatusNotFound)
		return
	}
	id := r.FormValue("challenge")
	code, err := otpCode()
	var flow storage.OTPFlow
	var expiresAt time.Time
	if err == nil {
		otpTTL := time.Duration(s.config.Email.OTPTTLSeconds) * time.Second
		flow, expiresAt, err = s.store.ResendOTP(id, code, s.otpSecret, time.Now(), otpTTL)
	}
	if err == nil {
		err = s.mailer.SendOTP(r.Context(), flow.Email, code, expiresAt)
	}
	if err != nil {
		s.logger.Warn("resend OTP", "error", err)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = s.templates.RenderPage(w, "otp", templates.OTPData{Title: "Verify email", ChallengeID: id, Message: "A new code was sent."})
}
