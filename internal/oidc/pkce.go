// Copyright 2025 Nadrama Pty Ltd
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// ValidatePKCE validates a PKCE code_verifier against the provided code_challenge using S256 method.
// It returns an error if the verifier or challenge is empty, or if the computed challenge does not match.
func ValidatePKCE(codeVerifier, codeChallenge string) error {
	if codeVerifier == "" {
		return fmt.Errorf("code_verifier is required")
	}

	if codeChallenge == "" {
		return fmt.Errorf("code_challenge is required")
	}

	hash := sha256.Sum256([]byte(codeVerifier))
	computed := base64.RawURLEncoding.EncodeToString(hash[:])

	if computed != codeChallenge {
		return fmt.Errorf("code_verifier does not match code_challenge")
	}

	return nil
}
