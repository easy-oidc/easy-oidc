// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package dpop

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

const maxProofSize = 8 * 1024

// Proof is a verified DPoP proof and its replay inputs.
type Proof struct {
	Algorithm  string
	Thumbprint string
	JTI        string
	Method     string
	Target     string
	ATH        string
}

// signingProfile constrains one accepted DPoP algorithm to its required curve.
type signingProfile struct {
	algorithm jwa.SignatureAlgorithm
	curve     elliptic.Curve
	curveName string
}

// profile returns the supported cryptographic profile for an algorithm.
func profile(algorithm string) (signingProfile, bool) {
	switch algorithm {
	case jwa.ES256.String():
		return signingProfile{algorithm: jwa.ES256, curve: elliptic.P256(), curveName: "P-256"}, true
	case jwa.ES512.String():
		return signingProfile{algorithm: jwa.ES512, curve: elliptic.P521(), curveName: "P-521"}, true
	default:
		return signingProfile{}, false
	}
}

// ParseAndVerify parses and verifies a proof under one configured algorithm.
func ParseAndVerify(compact, expectedAlgorithm, method, expectedURL string, now time.Time) (*Proof, error) {
	if _, ok := profile(expectedAlgorithm); !ok {
		return nil, errors.New("unsupported expected algorithm")
	}
	return parseAndVerify(compact, expectedAlgorithm, method, expectedURL, now)
}

// ParseAndVerifyBound verifies any supported profile before a separate JKT binding check.
func ParseAndVerifyBound(compact, method, expectedURL string, now time.Time) (*Proof, error) {
	return parseAndVerify(compact, "", method, expectedURL, now)
}

// parseAndVerify verifies a supported proof, optionally requiring one exact algorithm.
func parseAndVerify(compact, expectedAlgorithm, method, expectedURL string, now time.Time) (*Proof, error) {
	if len(compact) > maxProofSize {
		return nil, errors.New("proof exceeds 8 KiB")
	}
	parts := strings.Split(compact, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, errors.New("compact JWS must have three nonempty segments")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("invalid protected header")
	}
	var header map[string]json.RawMessage
	if err = json.Unmarshal(headerJSON, &header); err != nil {
		return nil, errors.New("invalid protected header")
	}
	if stringValue(header["typ"]) != "dpop+jwt" {
		return nil, errors.New("invalid typ")
	}
	algorithm := stringValue(header["alg"])
	proofProfile, ok := profile(algorithm)
	if !ok || expectedAlgorithm != "" && algorithm != expectedAlgorithm {
		return nil, errors.New("algorithm is not allowed")
	}
	for _, name := range []string{"crit", "b64", "jku", "x5u", "x5c", "kid"} {
		if _, exists := header[name]; exists {
			return nil, fmt.Errorf("forbidden protected header %s", name)
		}
	}
	keyJSON, exists := header["jwk"]
	if !exists {
		return nil, errors.New("jwk is required")
	}
	publicKey, thumbprint, err := parsePublicKey(keyJSON, proofProfile)
	if err != nil {
		return nil, err
	}
	payload, err := jws.Verify([]byte(compact), jws.WithKey(proofProfile.algorithm, publicKey), jws.WithCompact())
	if err != nil {
		return nil, errors.New("verification failed")
	}
	if !utf8.Valid(payload) {
		return nil, errors.New("invalid claims")
	}
	claims := map[string]any{}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err = decoder.Decode(&claims); err != nil {
		return nil, errors.New("invalid claims")
	}
	if err = decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("invalid claims")
	}
	jti, ok := requiredString(claims, "jti")
	if !ok || len(jti) > 128 {
		return nil, errors.New("invalid jti")
	}
	htm, ok := requiredString(claims, "htm")
	if !ok {
		return nil, errors.New("invalid htm")
	}
	htu, ok := requiredString(claims, "htu")
	if !ok {
		return nil, errors.New("invalid htu")
	}
	if err = validateExpectedURL(expectedURL); err != nil {
		return nil, errors.New("invalid expected URL")
	}
	if htm != method {
		return nil, errors.New("method mismatch")
	}
	if htu != expectedURL {
		return nil, errors.New("target mismatch")
	}
	iatNumber, ok := claims["iat"].(json.Number)
	if !ok {
		return nil, errors.New("iat must be numeric")
	}
	iat, err := iatNumber.Float64()
	if err != nil || math.IsInf(iat, 0) || iat < float64(now.UnixNano())/float64(time.Second)-10 || iat > float64(now.UnixNano())/float64(time.Second)+5 {
		return nil, errors.New("iat outside acceptance window")
	}
	ath := ""
	if value, present := claims["ath"]; present {
		ath, ok = value.(string)
		if !ok {
			return nil, errors.New("ath must be a string")
		}
	}
	return &Proof{Algorithm: algorithm, Thumbprint: thumbprint, JTI: jti, Method: htm, Target: htu, ATH: ath}, nil
}

// parsePublicKey constrains and exports an embedded public JWK for one profile.
func parsePublicKey(data []byte, profile signingProfile) (*ecdsa.PublicKey, string, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil {
		return nil, "", errors.New("invalid JWK")
	}
	for _, name := range []string{"d", "k", "p", "q", "dp", "dq", "qi", "oth"} {
		if _, exists := members[name]; exists {
			return nil, "", errors.New("private or symmetric key material")
		}
	}
	if stringValue(members["kty"]) != "EC" || stringValue(members["crv"]) != profile.curveName {
		return nil, "", errors.New("JWK curve does not match algorithm")
	}
	if alg, exists := members["alg"]; exists && stringValue(alg) != profile.algorithm.String() {
		return nil, "", errors.New("JWK algorithm mismatch")
	}
	key, err := jwk.ParseKey(data)
	if err != nil {
		return nil, "", errors.New("invalid JWK")
	}
	var publicKey ecdsa.PublicKey
	if err = key.Raw(&publicKey); err != nil {
		return nil, "", errors.New("invalid EC point")
	}
	point, err := publicKey.Bytes()
	if err != nil {
		return nil, "", errors.New("invalid EC point")
	}
	validatedKey, err := ecdsa.ParseUncompressedPublicKey(profile.curve, point)
	if err != nil {
		return nil, "", errors.New("invalid EC point")
	}
	thumb, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, "", errors.New("JWK thumbprint failed")
	}
	return validatedKey, base64.RawURLEncoding.EncodeToString(thumb), nil
}

// stringValue obtains a JSON string or returns empty for another type.
func stringValue(raw json.RawMessage) string {
	var value string
	_ = json.Unmarshal(raw, &value)
	return value
}

// requiredString obtains a required, nonempty string claim.
func requiredString(claims map[string]any, name string) (string, bool) {
	value, ok := claims[name].(string)
	return value, ok && value != ""
}

// validateExpectedURL checks the trusted DPoP target URL shape.
func validateExpectedURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("invalid absolute HTTP(S) URL")
	}
	return nil
}

// VerifyAccessTokenHash requires and constant-time verifies a proof's ath.
func VerifyAccessTokenHash(proof *Proof, token string) error {
	for i := range len(token) {
		if token[i] > 0x7f {
			return errors.New("token is not ASCII")
		}
	}
	sum := sha256.Sum256([]byte(token))
	expected := base64.RawURLEncoding.EncodeToString(sum[:])
	if proof.ATH == "" || subtle.ConstantTimeCompare([]byte(proof.ATH), []byte(expected)) != 1 {
		return errors.New("ath mismatch")
	}
	return nil
}

// VerifyThumbprint constant-time verifies a proof's binding against a stored jkt.
func VerifyThumbprint(proof *Proof, expected string) error {
	if subtle.ConstantTimeCompare([]byte(proof.Thumbprint), []byte(expected)) != 1 {
		return errors.New("thumbprint mismatch")
	}
	return nil
}

// ReplayHash computes the versioned, length-delimited replay-storage key.
func ReplayHash(thumbprint, jti, method, target string) [32]byte {
	var b bytes.Buffer
	b.WriteByte(1)
	for _, value := range []string{thumbprint, jti, method, target} {
		_ = binary.Write(&b, binary.BigEndian, uint32(len(value)))
		b.WriteString(value)
	}
	return sha256.Sum256(b.Bytes())
}
