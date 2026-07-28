// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
)

// ValidatePKCE validates a PKCE code_verifier against the provided code_challenge using S256 method.
// It returns an error if the verifier or challenge is empty, or if the computed challenge does not match.
func ValidatePKCE(codeVerifier, codeChallenge string) error {
	computed, err := pkceChallenge(codeVerifier)
	if err != nil {
		return err
	}
	if codeChallenge == "" {
		return fmt.Errorf("code_challenge is required")
	}
	if subtle.ConstantTimeCompare([]byte(computed), []byte(codeChallenge)) != 1 {
		return fmt.Errorf("code_verifier does not match code_challenge")
	}
	return nil
}

// pkceChallenge validates a verifier and returns its canonical S256 challenge.
func pkceChallenge(codeVerifier string) (string, error) {
	if len(codeVerifier) < 43 || len(codeVerifier) > 128 {
		return "", fmt.Errorf("code_verifier must contain 43 to 128 characters")
	}
	for _, character := range codeVerifier {
		switch {
		case character >= 'a' && character <= 'z':
		case character >= 'A' && character <= 'Z':
		case character >= '0' && character <= '9':
		case character == '-' || character == '.' || character == '_' || character == '~':
		default:
			return "", fmt.Errorf("code_verifier contains an invalid character")
		}
	}
	hash := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}
