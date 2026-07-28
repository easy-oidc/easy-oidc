// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"io"
	"log/slog"
	"testing"
	"time"
)

// otpStore creates a temporary store for an OTP test.
func otpStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(t.TempDir()+"/test.db", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestOTPLifecycle verifies attempt handling and single-use consumption.
func TestOTPLifecycle(t *testing.T) {
	s := otpStore(t)
	now := time.Now()
	secret := []byte("01234567890123456789012345678901")
	flow := OTPFlow{ConnectorID: "google", Subject: "123", Email: "user@example.com", ClientID: "client"}
	expiresAt, err := s.CreateOTP("challenge", flow.Email, "12345678", flow, secret, now, 7*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !expiresAt.Equal(now.Add(7 * time.Minute)) {
		t.Fatalf("expiry = %v", expiresAt)
	}
	for range 4 {
		if _, err := s.ConsumeOTP("challenge", "wrong", secret, now); err == nil {
			t.Fatal("wrong code accepted")
		}
	}
	got, err := s.ConsumeOTP("challenge", "12345678", secret, now)
	if err != nil || got != flow {
		t.Fatalf("consume: %#v %v", got, err)
	}
	if _, err = s.ConsumeOTP("challenge", "12345678", secret, now); err == nil {
		t.Fatal("OTP reused")
	}
}

// TestOTPAttemptLockExpiryResendAndLimits verifies OTP abuse controls.
func TestOTPAttemptLockExpiryResendAndLimits(t *testing.T) {
	s := otpStore(t)
	now := time.Now()
	secret := []byte("01234567890123456789012345678901")
	flow := OTPFlow{Email: "user@example.com"}
	if _, err := s.CreateOTP("lock", flow.Email, "11111111", flow, secret, now, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		_, _ = s.ConsumeOTP("lock", "wrong", secret, now)
	}
	if _, err := s.ConsumeOTP("lock", "11111111", secret, now); err == nil {
		t.Fatal("locked OTP accepted")
	}
	if _, err := s.CreateOTP("expired", flow.Email, "11111111", flow, secret, now.Add(-10*time.Minute), 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeOTP("expired", "11111111", secret, now); err == nil {
		t.Fatal("expired OTP accepted")
	}
	if _, err := s.CreateOTP("resend", "other@example.com", "11111111", flow, secret, now, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	_, resendExpiresAt, err := s.ResendOTP("resend", "22222222", secret, now.Add(time.Minute), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !resendExpiresAt.Equal(now.Add(6 * time.Minute)) {
		t.Fatalf("resend expiry = %v", resendExpiresAt)
	}
	if _, err := s.ConsumeOTP("resend", "11111111", secret, now.Add(time.Minute)); err == nil {
		t.Fatal("old resend code accepted")
	}
	for i := 0; i < 5; i++ {
		id := string(rune('a' + i))
		if _, err := s.CreateOTP(id, "quota@example.com", "11111111", flow, secret, now.Add(time.Duration(i)*time.Minute), 5*time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.CreateOTP("sixth", "quota@example.com", "11111111", flow, secret, now.Add(6*time.Minute), 5*time.Minute); err == nil {
		t.Fatal("hourly quota not enforced")
	}
}

// TestOTPResendCannotReviveChallenge verifies resends cannot restore dead challenges.
func TestOTPResendCannotReviveChallenge(t *testing.T) {
	s := otpStore(t)
	now := time.Now()
	secret := []byte("01234567890123456789012345678901")
	flow := OTPFlow{Email: "user@example.com"}
	if _, err := s.CreateOTP("consumed", flow.Email, "11111111", flow, secret, now, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeOTP("consumed", "11111111", secret, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ResendOTP("consumed", "22222222", secret, now.Add(time.Minute), 5*time.Minute); err == nil {
		t.Fatal("resend revived consumed challenge")
	}
	if _, err := s.CreateOTP("expired-resend", flow.Email, "11111111", flow, secret, now.Add(-10*time.Minute), 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ResendOTP("expired-resend", "22222222", secret, now, 5*time.Minute); err == nil {
		t.Fatal("resend revived expired challenge")
	}
}

// TestCredentialVerificationTracksEachEmail verifies identity email choices do not overwrite each other.
func TestCredentialVerificationTracksEachEmail(t *testing.T) {
	s := otpStore(t)
	now := time.Now()
	if err := s.SaveCredential("github", "123", "first@example.com", true, now); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveCredential("github", "123", "second@example.com", false, now); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveCredential("github", "123", "first@example.com", false, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	firstExists, firstLocal, err := s.CredentialVerified("github", "123", "first@example.com")
	if err != nil {
		t.Fatal(err)
	}
	secondExists, secondLocal, err := s.CredentialVerified("github", "123", "second@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !firstExists || !firstLocal || !secondExists || secondLocal {
		t.Fatalf("credential states = first(%v,%v), second(%v,%v)", firstExists, firstLocal, secondExists, secondLocal)
	}
}
