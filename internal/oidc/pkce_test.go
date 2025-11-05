// Copyright 2025 Nadrama Pty Ltd
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestValidatePKCE(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	tests := []struct {
		name        string
		verifier    string
		challenge   string
		expectError bool
	}{
		{
			name:        "valid PKCE with standard verifier",
			verifier:    verifier,
			challenge:   challenge,
			expectError: false,
		},
		{
			name:        "invalid verifier",
			verifier:    "wrong-verifier",
			challenge:   challenge,
			expectError: true,
		},
		{
			name:        "empty verifier",
			verifier:    "",
			challenge:   challenge,
			expectError: true,
		},
		{
			name:        "empty challenge",
			verifier:    verifier,
			challenge:   "",
			expectError: true,
		},
		{
			name:        "both empty",
			verifier:    "",
			challenge:   "",
			expectError: true,
		},
		{
			name:        "challenge with wrong encoding (standard base64)",
			verifier:    verifier,
			challenge:   base64.StdEncoding.EncodeToString(hash[:]),
			expectError: true,
		},
		{
			name:        "challenge with padding (should fail)",
			verifier:    verifier,
			challenge:   base64.URLEncoding.EncodeToString(hash[:]),
			expectError: true,
		},
		{
			name:     "very long verifier (128 chars)",
			verifier: strings.Repeat("a", 128),
			challenge: func() string {
				h := sha256.Sum256([]byte(strings.Repeat("a", 128)))
				return base64.RawURLEncoding.EncodeToString(h[:])
			}(),
			expectError: false,
		},
		{
			name:     "short verifier (43 chars - minimum per RFC 7636)",
			verifier: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
			challenge: func() string {
				h := sha256.Sum256([]byte("abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"))
				return base64.RawURLEncoding.EncodeToString(h[:])
			}(),
			expectError: false,
		},
		{
			name:     "verifier with special characters",
			verifier: "abc-._~123",
			challenge: func() string {
				h := sha256.Sum256([]byte("abc-._~123"))
				return base64.RawURLEncoding.EncodeToString(h[:])
			}(),
			expectError: false,
		},
		{
			name:        "challenge is just random string",
			verifier:    verifier,
			challenge:   "random-invalid-challenge",
			expectError: true,
		},
		{
			name:        "swapped verifier and challenge",
			verifier:    challenge,
			challenge:   verifier,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePKCE(tt.verifier, tt.challenge)
			if (err != nil) != tt.expectError {
				t.Errorf("expected error: %v, got: %v (error: %v)", tt.expectError, err != nil, err)
			}
		})
	}
}

func TestValidatePKCE_RealWorldScenarios(t *testing.T) {
	t.Run("kubelogin-generated PKCE flow", func(t *testing.T) {
		verifier := generateRandomVerifier(64)
		challenge := computeChallenge(verifier)

		err := ValidatePKCE(verifier, challenge)
		if err != nil {
			t.Errorf("valid PKCE flow failed: %v", err)
		}
	})

	t.Run("multiple different verifiers", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			verifier := generateRandomVerifier(64)
			challenge := computeChallenge(verifier)

			err := ValidatePKCE(verifier, challenge)
			if err != nil {
				t.Errorf("iteration %d: valid PKCE flow failed: %v", i, err)
			}
		}
	})

	t.Run("verifier reuse with different challenge (attack scenario)", func(t *testing.T) {
		verifier := generateRandomVerifier(64)
		challenge1 := computeChallenge(verifier)
		challenge2 := computeChallenge(verifier + "different")

		if err := ValidatePKCE(verifier, challenge1); err != nil {
			t.Errorf("legitimate flow failed: %v", err)
		}

		err := ValidatePKCE(verifier, challenge2)
		if err == nil {
			t.Error("attack scenario should fail: verifier with wrong challenge succeeded")
		}
	})
}

func TestValidatePKCE_ErrorMessages(t *testing.T) {
	tests := []struct {
		name            string
		verifier        string
		challenge       string
		expectedErrText string
	}{
		{
			name:            "empty verifier error message",
			verifier:        "",
			challenge:       "some-challenge",
			expectedErrText: "code_verifier is required",
		},
		{
			name:            "empty challenge error message",
			verifier:        "some-verifier",
			challenge:       "",
			expectedErrText: "code_challenge is required",
		},
		{
			name:            "mismatch error message",
			verifier:        "wrong",
			challenge:       computeChallenge("correct"),
			expectedErrText: "does not match",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePKCE(tt.verifier, tt.challenge)
			if err == nil {
				t.Error("expected error but got nil")
				return
			}
			if !strings.Contains(err.Error(), tt.expectedErrText) {
				t.Errorf("expected error to contain %q, got: %v", tt.expectedErrText, err)
			}
		})
	}
}

func TestValidatePKCE_SpecCompliance(t *testing.T) {
	t.Run("RFC 7636 example A.2", func(t *testing.T) {
		verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		expectedChallenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

		hash := sha256.Sum256([]byte(verifier))
		challenge := base64.RawURLEncoding.EncodeToString(hash[:])

		if challenge != expectedChallenge {
			t.Errorf("RFC 7636 example challenge mismatch: expected %s, got %s", expectedChallenge, challenge)
		}

		err := ValidatePKCE(verifier, challenge)
		if err != nil {
			t.Errorf("RFC 7636 compliant PKCE failed: %v", err)
		}
	})

	t.Run("verifier length boundaries", func(t *testing.T) {
		minLength := 43
		maxLength := 128

		minVerifier := strings.Repeat("a", minLength)
		minChallenge := computeChallenge(minVerifier)
		if err := ValidatePKCE(minVerifier, minChallenge); err != nil {
			t.Errorf("minimum length verifier (%d chars) failed: %v", minLength, err)
		}

		maxVerifier := strings.Repeat("a", maxLength)
		maxChallenge := computeChallenge(maxVerifier)
		if err := ValidatePKCE(maxVerifier, maxChallenge); err != nil {
			t.Errorf("maximum length verifier (%d chars) failed: %v", maxLength, err)
		}
	})

	t.Run("allowed character set", func(t *testing.T) {
		allowedChars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
		verifier := allowedChars[:64]
		challenge := computeChallenge(verifier)

		err := ValidatePKCE(verifier, challenge)
		if err != nil {
			t.Errorf("RFC 7636 allowed characters failed: %v", err)
		}
	})
}

func generateRandomVerifier(length int) string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b)
}

func computeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}
