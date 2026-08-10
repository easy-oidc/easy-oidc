// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"hash"
	"testing"
	"time"
)

// endpointProofKey holds an endpoint-test DPoP key and canonical thumbprint.
type endpointProofKey struct {
	key       *ecdsa.PrivateKey
	algorithm string
	curveName string
	size      int
	newHash   func() hash.Hash
	jkt       string
}

// endpointProofOptions controls every request-dependent DPoP proof claim.
type endpointProofOptions struct {
	Method, URL, ATH, JTI string
	IAT                   time.Time
}

// newEndpointProofKey creates a proof key for one supported signing profile.
func newEndpointProofKey(t *testing.T, algorithm string) endpointProofKey {
	t.Helper()
	var curve elliptic.Curve
	var curveName string
	var size int
	var newHash func() hash.Hash
	switch algorithm {
	case "ES256":
		curve, curveName, size, newHash = elliptic.P256(), "P-256", 32, sha256.New
	case "ES384":
		curve, curveName, size, newHash = elliptic.P384(), "P-384", 48, sha512.New384
	case "ES512":
		curve, curveName, size, newHash = elliptic.P521(), "P-521", 66, sha512.New
	default:
		t.Fatalf("unsupported proof algorithm %q", algorithm)
	}
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x := base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, size)))
	y := base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, size)))
	canonical := `{"crv":"` + curveName + `","kty":"EC","x":"` + x + `","y":"` + y + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return endpointProofKey{key: key, algorithm: algorithm, curveName: curveName, size: size, newHash: newHash, jkt: base64.RawURLEncoding.EncodeToString(sum[:])}
}

// proof signs a DPoP proof with explicitly controlled endpoint claims.
func (k endpointProofKey) proof(t *testing.T, options endpointProofOptions) string {
	t.Helper()
	x := base64.RawURLEncoding.EncodeToString(k.key.X.FillBytes(make([]byte, k.size)))
	y := base64.RawURLEncoding.EncodeToString(k.key.Y.FillBytes(make([]byte, k.size)))
	header, _ := json.Marshal(map[string]any{"typ": "dpop+jwt", "alg": k.algorithm, "jwk": map[string]any{"kty": "EC", "crv": k.curveName, "x": x, "y": y}})
	claims := map[string]any{"jti": options.JTI, "htm": options.Method, "htu": options.URL, "iat": options.IAT.Unix()}
	if options.ATH != "" {
		claims["ath"] = options.ATH
	}
	payload, _ := json.Marshal(claims)
	h, p := base64.RawURLEncoding.EncodeToString(header), base64.RawURLEncoding.EncodeToString(payload)
	digest := k.newHash()
	_, _ = digest.Write([]byte(h + "." + p))
	r, s, err := ecdsa.Sign(rand.Reader, k.key, digest.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}
	signature := append(r.FillBytes(make([]byte, k.size)), s.FillBytes(make([]byte, k.size))...)
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(signature)
}
