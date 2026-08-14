// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/truster-dev/truster/v2/internal/challenge"
	"github.com/truster-dev/truster/v2/internal/config"
	"github.com/truster-dev/truster/v2/internal/statedb"
	"github.com/truster-dev/truster/v2/internal/templates"
)

// fakeMailer returns a configured delivery result.
type fakeMailer struct{ err error }

// SendOTP returns the configured error without sending mail.
func (m fakeMailer) SendOTP(context.Context, string, string, time.Time) error { return m.err }

// TestBeginOTPDoesNotExposeSMTPFailure verifies delivery outcomes are indistinguishable.
func TestBeginOTPDoesNotExposeSMTPFailure(t *testing.T) {
	responses := make([]string, 0, 2)
	statuses := make([]int, 0, 2)
	for i, mailErr := range []error{nil, errors.New("recipient rejected")} {
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		store, err := statedb.NewSQLite(t.TempDir()+"/test.db", logger)
		if err != nil {
			t.Fatal(err)
		}
		manager, err := templates.Load("")
		if err != nil {
			t.Fatal(err)
		}
		server := &Server{config: &config.Config{Email: &config.EmailConfig{OTPTTL: config.Duration(5 * time.Minute)}}, store: store, templates: manager, mailer: fakeMailer{mailErr}, otpSecret: []byte("01234567890123456789012345678901"), logger: logger}
		response := httptest.NewRecorder()
		request := httptest.NewRequest("POST", "/email/start", nil)
		server.beginOTP(response, request, OAuthState{ClientID: "client", RedirectURI: "https://client.example/callback", CodeChallenge: "challenge"}, "email", "user@example.com", "user@example.com")
		_ = store.Close()
		statuses = append(statuses, response.Code)
		responses = append(responses, response.Body.String())
		if !strings.Contains(responses[i], "user@example.com") || !strings.Contains(responses[i], "5 minutes") {
			t.Fatalf("response %d exposed delivery outcome: %s", i, responses[i])
		}
	}
	if statuses[0] != statuses[1] {
		t.Fatalf("SMTP outcomes returned different statuses: %v", statuses)
	}
}

// TestHandleEmailResendReturnsRetryState verifies cooldown rejections reach HTTP clients and templates.
func TestHandleEmailResendReturnsRetryState(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := statedb.NewSQLite(t.TempDir()+"/test.db", logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	manager, err := templates.Load("")
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("01234567890123456789012345678901")
	flow := statedb.OTPFlow{Email: "user@example.com"}
	if _, err = store.CreateOTP("challenge", flow.Email, "11111111", flow, secret, time.Now(), 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	server := &Server{config: &config.Config{Email: &config.EmailConfig{OTPTTL: config.Duration(5 * time.Minute)}}, store: store, templates: manager, mailer: fakeMailer{}, otpSecret: secret, logger: logger}
	form := url.Values{"challenge": {"challenge"}}
	request := httptest.NewRequest(http.MethodPost, "/email/resend", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.HandleEmailResend(response, request)
	retryAfter, retryErr := strconv.Atoi(response.Header().Get("Retry-After"))
	if response.Code != http.StatusTooManyRequests || retryErr != nil || retryAfter < 59 || retryAfter > 60 {
		t.Fatalf("resend status = %d, retry = %q", response.Code, response.Header().Get("Retry-After"))
	}
	body := response.Body.String()
	if !strings.Contains(body, "A new code could not be sent.") || !strings.Contains(body, fmt.Sprintf("Try again in %d seconds.", retryAfter)) {
		t.Fatalf("resend error state missing from template: %s", body)
	}
}

// TestHandleEmailResendExposesExpiry verifies successful resends provide their absolute expiry to page templates.
func TestHandleEmailResendExposesExpiry(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := statedb.NewSQLite(t.TempDir()+"/test.db", logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	templateDir := t.TempDir()
	if err = os.MkdirAll(filepath.Join(templateDir, "pages"), 0755); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(templateDir, "pages/otp.html"), []byte(`{{define "content"}}expiry={{.ExpiresAt.Unix}}{{end}}`), 0600); err != nil {
		t.Fatal(err)
	}
	manager, err := templates.Load(templateDir)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("01234567890123456789012345678901")
	flow := statedb.OTPFlow{Email: "user@example.com"}
	if _, err = store.CreateOTP("challenge", flow.Email, "11111111", flow, secret, time.Now().Add(-2*time.Minute), 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	server := &Server{config: &config.Config{Email: &config.EmailConfig{OTPTTL: config.Duration(5 * time.Minute)}}, store: store, templates: manager, mailer: fakeMailer{}, otpSecret: secret, logger: logger}
	form := url.Values{"challenge": {"challenge"}}
	request := httptest.NewRequest(http.MethodPost, "/email/resend", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	wantExpiry := time.Now().Add(5 * time.Minute)
	server.HandleEmailResend(response, request)
	match := regexp.MustCompile(`expiry=(-?\d+)`).FindStringSubmatch(response.Body.String())
	if response.Code != http.StatusOK || len(match) != 2 {
		t.Fatalf("resend response = %d %s", response.Code, response.Body.String())
	}
	gotExpiry, err := strconv.ParseInt(match[1], 10, 64)
	if err != nil || gotExpiry < wantExpiry.Add(-time.Second).Unix() || gotExpiry > wantExpiry.Add(time.Second).Unix() {
		t.Fatalf("resend expiry = %q, want approximately %v", match[1], wantExpiry)
	}
}

// TestHandleEmailStartUsesConnectorFromSelector verifies selector state binds the email connector.
func TestHandleEmailStartUsesConnectorFromSelector(t *testing.T) {
	server, _ := authorizeServer(t, map[string]config.ConnectorConfig{
		"google":       {Type: "google", DisplayName: "Google"},
		"email-direct": {Type: "email", DisplayName: "Email"},
	})
	server.challenge = challenge.Noop{}
	server.mailer = fakeMailer{}
	server.otpSecret = []byte("01234567890123456789012345678901")
	server.config.Email = &config.EmailConfig{OTPTTL: config.Duration(5 * time.Minute)}

	selector := httptest.NewRecorder()
	server.HandleAuthorize(selector, authorizationRequest())
	match := regexp.MustCompile(`name="state" value="([^"]+)"`).FindStringSubmatch(selector.Body.String())
	if len(match) != 2 {
		t.Fatalf("selector state not found: %s", selector.Body.String())
	}
	form := url.Values{"state": {match[1]}, "connector": {"email-direct"}, "email": {"user@example.com"}}
	request := httptest.NewRequest(http.MethodPost, "/email/start", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.HandleEmailStart(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "user@example.com") || !strings.Contains(response.Body.String(), "5 minutes") {
		t.Fatalf("unexpected email start response: %d %s", response.Code, response.Body.String())
	}
}

// TestEmailVerificationEndpointsRejectUnavailableVerification verifies disabled mode cannot panic on OTP routes.
func TestEmailVerificationEndpointsRejectUnavailableVerification(t *testing.T) {
	server := &Server{config: &config.Config{}}
	for _, path := range []string{"/email/verify", "/email/resend"} {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, path, nil)
		if path == "/email/verify" {
			server.HandleEmailVerify(response, request)
		} else {
			server.HandleEmailResend(response, request)
		}
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d, want %d", path, response.Code, http.StatusNotFound)
		}
	}
}
