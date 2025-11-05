// Copyright 2025 Nadrama Pty Ltd
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"crypto/sha256"
	"encoding/base64"
)

// GenerateKeyID generates a key ID from the public key fingerprint.
// It uses the SHA-256 hash of the public key, base64-encoded (URL-safe, no padding).
// This creates a stable, unique identifier for the key.
func GenerateKeyID(keyPair *KeyPair) string {
	hash := sha256.Sum256(keyPair.PublicKey)
	return base64.RawURLEncoding.EncodeToString(hash[:16])
}
