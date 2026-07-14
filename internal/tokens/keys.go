// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwa"
)

var signingAlgorithms = map[string]jwa.SignatureAlgorithm{
	"RS256": jwa.RS256, "RS384": jwa.RS384, "RS512": jwa.RS512,
	"ES256": jwa.ES256, "ES384": jwa.ES384, "ES512": jwa.ES512,
	"PS256": jwa.PS256, "PS384": jwa.PS384, "PS512": jwa.PS512,
	"EdDSA": jwa.EdDSA,
}

// SigningKey holds a validated private key and its signing algorithm.
type SigningKey struct {
	Algorithm  jwa.SignatureAlgorithm
	PrivateKey crypto.Signer
	PublicKey  crypto.PublicKey
}

// ParsePrivateKey parses a PKCS8 PEM private key and validates that its type matches algorithm.
func ParsePrivateKey(pemData, algorithm string) (*SigningKey, error) {
	block, rest := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("signing key must be a PKCS8 PRIVATE KEY PEM block")
	}
	if len(block.Headers) != 0 || strings.TrimSpace(string(rest)) != "" {
		return nil, fmt.Errorf("signing key PEM must contain exactly one unencrypted private key")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS8 private key: %w", err)
	}

	alg, ok := signingAlgorithms[algorithm]
	if !ok {
		return nil, fmt.Errorf("unsupported signing algorithm %q", algorithm)
	}

	switch {
	case strings.HasPrefix(algorithm, "RS"), strings.HasPrefix(algorithm, "PS"):
		privateKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("signing algorithm %s requires an RSA private key", algorithm)
		}
		if privateKey.N.BitLen() < 2048 {
			return nil, fmt.Errorf("RSA signing key must be at least 2048 bits")
		}
		if err := privateKey.Validate(); err != nil {
			return nil, fmt.Errorf("invalid RSA private key: %w", err)
		}
		return &SigningKey{Algorithm: alg, PrivateKey: privateKey, PublicKey: &privateKey.PublicKey}, nil
	case strings.HasPrefix(algorithm, "ES"):
		privateKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("signing algorithm %s requires an ECDSA private key", algorithm)
		}
		expectedCurve := map[string]elliptic.Curve{
			"ES256": elliptic.P256(),
			"ES384": elliptic.P384(),
			"ES512": elliptic.P521(),
		}[algorithm]
		if privateKey.Curve != expectedCurve {
			return nil, fmt.Errorf("signing algorithm %s requires curve %s", algorithm, expectedCurve.Params().Name)
		}
		return &SigningKey{Algorithm: alg, PrivateKey: privateKey, PublicKey: &privateKey.PublicKey}, nil
	case algorithm == "EdDSA":
		privateKey, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("signing algorithm EdDSA requires an Ed25519 private key")
		}
		return &SigningKey{Algorithm: alg, PrivateKey: privateKey, PublicKey: privateKey.Public()}, nil
	default:
		return nil, fmt.Errorf("unsupported signing algorithm %q", algorithm)
	}
}
