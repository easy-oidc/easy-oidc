// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

// GenerateKeyID generates a key ID from the public key fingerprint.
// It uses the SHA-256 hash of the public key, base64-encoded (URL-safe, no padding).
// This creates a stable, unique identifier for the key.
func GenerateKeyID(signingKey *SigningKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(signingKey.PublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}
	hash := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(hash[:16]), nil
}
