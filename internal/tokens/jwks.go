// Copyright 2025 Nadrama Pty Ltd
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"encoding/json"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

// GenerateJWKS generates a JSON Web Key Set from a key pair and key ID.
// The resulting JWKS can be served at the /jwks endpoint for token verification.
func GenerateJWKS(keyPair *KeyPair, kid string) ([]byte, error) {
	key, err := jwk.FromRaw(keyPair.PublicKey)
	if err != nil {
		return nil, err
	}

	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, err
	}

	if err := key.Set(jwk.AlgorithmKey, "EdDSA"); err != nil {
		return nil, err
	}

	if err := key.Set(jwk.KeyUsageKey, "sig"); err != nil {
		return nil, err
	}

	set := jwk.NewSet()
	if err := set.AddKey(key); err != nil {
		return nil, err
	}

	return json.Marshal(set)
}
