// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package email

import (
	"bytes"
	"context"
	"time"

	"github.com/easy-oidc/easy-oidc/internal/templates"
)

// OTPMailer renders and sends one-time verification code messages.
type OTPMailer struct {
	mailer    *SMTPMailer
	templates *templates.Manager
	ttl       time.Duration
}

// NewOTPMailer creates an SMTP-backed one-time code mailer.
func NewOTPMailer(mailer *SMTPMailer, templates *templates.Manager, ttl time.Duration) *OTPMailer {
	return &OTPMailer{mailer: mailer, templates: templates, ttl: ttl}
}

// SendOTP renders and sends an OTP message with its exact expiry to an email address.
func (m *OTPMailer) SendOTP(ctx context.Context, to, code string, expiresAt time.Time) error {
	var textBody, htmlBody bytes.Buffer
	templateData := templates.OTPEmailData{Code: code, ExpiresAt: expiresAt.UTC(), ExpiresIn: m.ttl}
	if err := m.templates.RenderEmail(&textBody, "text", templateData); err != nil {
		return err
	}
	if err := m.templates.RenderEmail(&htmlBody, "html", templateData); err != nil {
		return err
	}
	return m.mailer.send(ctx, to, "Easy OIDC verification code", textBody.String(), htmlBody.String())
}
