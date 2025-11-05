// Copyright 2025 Nadrama Pty Ltd
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// KeyPair holds an Ed25519 private and public key pair for token signing.
type KeyPair struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

// ParseEd25519PrivateKey parses a PEM-encoded Ed25519 private key.
// The key must be in PKCS8 format.
func ParseEd25519PrivateKey(pemData string) (*KeyPair, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS8 private key: %w", err)
	}

	ed25519Key, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not an Ed25519 private key")
	}

	publicKey := ed25519Key.Public().(ed25519.PublicKey)

	return &KeyPair{
		PrivateKey: ed25519Key,
		PublicKey:  publicKey,
	}, nil
}

// Signer returns the crypto.Signer interface for the private key.
func (kp *KeyPair) Signer() crypto.Signer {
	return kp.PrivateKey
}
