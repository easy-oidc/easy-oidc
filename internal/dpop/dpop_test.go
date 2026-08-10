// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

// conformanceFixture is the public-only, interoperable fixture schema. Proof may
// be compact or split into its three public compact-JWS segments.
type conformanceFixture struct {
	Schema        string            `json:"schema"`
	Algorithm     string            `json:"algorithm"`
	Proof         string            `json:"proof"`
	Thumbprint    string            `json:"thumbprint"`
	Method        string            `json:"method"`
	URL           string            `json:"url"`
	AccessToken   string            `json:"access_token"`
	ATH           string            `json:"ath"`
	ReplayHash    string            `json:"replay_hash"`
	UnixTime      int64             `json:"unix_time"`
	ProofSegments []string          `json:"proof_segments"`
	PublicJWK     map[string]string `json:"public_jwk"`
}

// TestPublicConformanceFixtures cryptographically checks externally reusable ES fixtures.
func TestPublicConformanceFixtures(t *testing.T) {
	for _, algorithm := range []string{"ES256", "ES512"} {
		t.Run(algorithm, func(t *testing.T) {
			raw, err := os.ReadFile("testdata/" + algorithm + ".json")
			if err != nil {
				t.Fatal(err)
			}
			var fixture conformanceFixture
			if err = json.Unmarshal(raw, &fixture); err != nil {
				t.Fatal(err)
			}
			if fixture.Schema != "easy-oidc-dpop-conformance-v1" || fixture.Algorithm != algorithm {
				t.Fatal("invalid fixture schema/profile")
			}
			proof := fixture.Proof
			if proof == "" {
				proof = strings.Join(fixture.ProofSegments, ".")
			}
			headerBytes, err := base64.RawURLEncoding.DecodeString(strings.Split(proof, ".")[0])
			if err != nil {
				t.Fatal(err)
			}
			var header struct {
				JWK map[string]string `json:"jwk"`
			}
			if err = json.Unmarshal(headerBytes, &header); err != nil || !reflect.DeepEqual(header.JWK, fixture.PublicJWK) {
				t.Fatal("fixture public_jwk does not match proof header")
			}
			verified, err := ParseAndVerify(proof, algorithm, fixture.Method, fixture.URL, time.Unix(fixture.UnixTime, 0))
			if err != nil {
				t.Fatalf("verify fixture: %v", err)
			}
			if verified.Thumbprint != fixture.Thumbprint || VerifyThumbprint(verified, fixture.Thumbprint) != nil {
				t.Fatal("fixture thumbprint mismatch")
			}
			if VerifyAccessTokenHash(verified, fixture.AccessToken) != nil || verified.ATH != fixture.ATH {
				t.Fatal("fixture ath mismatch")
			}
			wantReplay, err := hex.DecodeString(fixture.ReplayHash)
			if err != nil {
				t.Fatal(err)
			}
			gotReplay := ReplayHash(verified.Thumbprint, verified.JTI, verified.Method, verified.Target)
			if !strings.EqualFold(hex.EncodeToString(gotReplay[:]), hex.EncodeToString(wantReplay)) {
				t.Fatal("fixture replay hash mismatch")
			}
			if _, err = ParseAndVerify(proof, algorithm, "GET", fixture.URL, time.Unix(fixture.UnixTime, 0)); err == nil {
				t.Fatal("accepted wrong method")
			}
			if _, err = ParseAndVerify(proof, algorithm, fixture.Method, fixture.URL+"/other", time.Unix(fixture.UnixTime, 0)); err == nil {
				t.Fatal("accepted wrong URL")
			}
			if _, err = ParseAndVerify(proof, algorithm, fixture.Method, fixture.URL, time.Unix(fixture.UnixTime+60, 0)); err == nil {
				t.Fatal("accepted stale proof")
			}
			if VerifyAccessTokenHash(verified, fixture.AccessToken+"-wrong") == nil || VerifyThumbprint(verified, fixture.Thumbprint+"-wrong") == nil {
				t.Fatal("accepted wrong binding")
			}
		})
	}
}

// testProof signs claims with an embedded public JWK and optional header changes.
func testProof(t *testing.T, claims string, changes map[string]any) string {
	return testProofAlgorithm(t, "ES256", claims, changes)
}

// testProofAlgorithm signs claims under one supported profile.
func testProofAlgorithm(t *testing.T, algorithm, claims string, changes map[string]any) string {
	t.Helper()
	curve, signatureAlgorithm := elliptic.P256(), jwa.ES256
	if algorithm == "ES512" {
		curve, signatureAlgorithm = elliptic.P521(), jwa.ES512
	}
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicJWK, err := jwk.FromRaw(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	header := jws.NewHeaders()
	if err = header.Set("typ", "dpop+jwt"); err != nil {
		t.Fatal(err)
	}
	if err = header.Set("alg", signatureAlgorithm); err != nil {
		t.Fatal(err)
	}
	if err = header.Set("jwk", publicJWK); err != nil {
		t.Fatal(err)
	}
	for name, value := range changes {
		if err = header.Set(name, value); err != nil {
			t.Fatal(err)
		}
	}
	proof, err := jws.Sign([]byte(claims), jws.WithKey(signatureAlgorithm, privateKey, jws.WithProtectedHeaders(header)))
	if err != nil {
		t.Fatal(err)
	}
	return string(proof)
}

// verifyTestProof verifies a test proof at the standard request inputs.
func verifyTestProof(proof string) (*Proof, error) {
	return ParseAndVerify(proof, "ES256", "POST", "https://example.com/token", time.Unix(100, 0))
}

// mutateHeader changes the protected header without resigning the proof.
func mutateHeader(t *testing.T, proof, name string, value any) string {
	t.Helper()
	parts := strings.Split(proof, ".")
	encoded, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var header map[string]any
	if err = json.Unmarshal(encoded, &header); err != nil {
		t.Fatal(err)
	}
	header[name] = value
	encoded, err = json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	parts[0] = base64.RawURLEncoding.EncodeToString(encoded)
	return strings.Join(parts, ".")
}

// TestValidProfiles verifies each constrained profile and jwx thumbprint.
func TestValidProfiles(t *testing.T) {
	sum := sha256.Sum256([]byte("token"))
	ath := base64.RawURLEncoding.EncodeToString(sum[:])
	for _, algorithm := range []string{"ES256", "ES512"} {
		t.Run(algorithm, func(t *testing.T) {
			compact := testProofAlgorithm(t, algorithm, fmt.Sprintf(`{"jti":"id","htm":"POST","htu":"https://example.com/token","iat":100,"ath":%q}`, ath), nil)
			proof, err := ParseAndVerify(compact, algorithm, "POST", "https://example.com/token", time.Unix(100, 0))
			if err != nil {
				t.Fatal(err)
			}
			if proof.Algorithm != algorithm || VerifyAccessTokenHash(proof, "token") != nil || VerifyThumbprint(proof, proof.Thumbprint) != nil {
				t.Fatalf("invalid verified proof: %+v", proof)
			}
			if _, err = ParseAndVerifyBound(compact, "POST", "https://example.com/token", time.Unix(100, 0)); err != nil {
				t.Fatalf("bound verification: %v", err)
			}
		})
	}
}

// TestMalformedCompact rejects size and compact framing violations.
func TestMalformedCompact(t *testing.T) {
	for _, proof := range []string{"a.b", "a..b", "a.b.c.d", strings.Repeat("a", maxProofSize+1)} {
		if _, err := verifyTestProof(proof); err == nil {
			t.Errorf("accepted malformed proof")
		}
	}
}

// TestProfileAndHeaderRejections rejects forbidden algorithms and key sources.
func TestProfileAndHeaderRejections(t *testing.T) {
	claims := `{"jti":"id","htm":"POST","htu":"https://example.com/token","iat":100}`
	valid := testProof(t, claims, nil)
	for name, value := range map[string]any{
		"typ":  "JWT",
		"alg":  "ES384",
		"jku":  "https://example.com/keys",
		"x5u":  "https://example.com/cert",
		"x5c":  []any{"Y2VydA=="},
		"crit": []string{"exp"},
		"b64":  true,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := verifyTestProof(mutateHeader(t, valid, name, value)); err == nil {
				t.Fatal("accepted forbidden header")
			}
		})
	}
}

// TestJWKRejections rejects private, wrong-curve, and invalid point material.
func TestJWKRejections(t *testing.T) {
	es256, _ := profile("ES256")
	zero := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for name, raw := range map[string]string{
		"private":   `{"kty":"EC","crv":"P-256","x":"x","y":"y","d":"secret"}`,
		"curve":     `{"kty":"EC","crv":"P-384","x":"x","y":"y"}`,
		"off-curve": fmt.Sprintf(`{"kty":"EC","crv":"P-256","x":%q,"y":%q}`, zero, zero),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parsePublicKey([]byte(raw), es256); err == nil {
				t.Fatal("accepted invalid JWK")
			}
		})
	}
}

// TestSignatureRejections delegates raw ES256 signature checks to jwx.
func TestSignatureRejections(t *testing.T) {
	proof := testProof(t, `{"jti":"id","htm":"POST","htu":"https://example.com/token","iat":100}`, nil)
	parts := strings.Split(proof, ".")
	for _, signature := range [][]byte{make([]byte, 63), make([]byte, 64)} {
		parts[2] = base64.RawURLEncoding.EncodeToString(signature)
		if _, err := verifyTestProof(strings.Join(parts, ".")); err == nil {
			t.Fatal("accepted invalid signature")
		}
	}
}

// TestClaimsFreshnessAndRequestBinding verifies typed claims and exact boundaries.
func TestClaimsFreshnessAndRequestBinding(t *testing.T) {
	for _, iat := range []string{"90", "105", "100.5"} {
		claims := fmt.Sprintf(`{"jti":"id","htm":"POST","htu":"https://example.com/token","iat":%s}`, iat)
		if _, err := verifyTestProof(testProof(t, claims, nil)); err != nil {
			t.Errorf("iat %s: %v", iat, err)
		}
	}
	for _, claims := range []string{
		`{"jti":1,"htm":"POST","htu":"https://example.com/token","iat":100}`,
		`{"jti":"","htm":"POST","htu":"https://example.com/token","iat":100}`,
		`{"jti":"id","htm":1,"htu":"https://example.com/token","iat":100}`,
		`{"jti":"id","htm":"POST","htu":1,"iat":100}`,
		`{"jti":"id","htm":"POST","htu":"https://example.com/token","iat":"100"}`,
		`{"jti":"id","htm":"POST","htu":"https://example.com/token","iat":89.999}`,
		`{"jti":"id","htm":"POST","htu":"https://example.com/token","iat":105.001}`,
		`{"jti":"id","htm":"POST","htu":"https://example.com/token","iat":100}{}`,
		`{"jti":"id","htm":"POST","htu":"https://example.com/token","iat":100}` + string([]byte{0xff}),
	} {
		if _, err := verifyTestProof(testProof(t, claims, nil)); err == nil {
			t.Errorf("accepted claims %s", claims)
		}
	}
	valid := testProof(t, `{"jti":"id","htm":"POST","htu":"https://example.com/token","iat":100}`, nil)
	for _, request := range [][2]string{{"GET", "https://example.com/token"}, {"POST", "https://EXAMPLE.com/token"}, {"POST", "/token"}, {"POST", "https://example.com/token?q=1"}} {
		if _, err := ParseAndVerify(valid, "ES256", request[0], request[1], time.Unix(100, 0)); err == nil {
			t.Errorf("accepted request %v", request)
		}
	}
}

// TestATHReplayAndBinding verifies token hashing and deterministic replay encoding.
func TestATHReplayAndBinding(t *testing.T) {
	sum := sha256.Sum256([]byte("token"))
	hash := base64.RawURLEncoding.EncodeToString(sum[:])
	proof := &Proof{ATH: hash, Thumbprint: "jkt"}
	if VerifyAccessTokenHash(proof, "token") != nil || VerifyAccessTokenHash(proof, "wrong") == nil || VerifyThumbprint(proof, "wrong") == nil {
		t.Fatal("binding verification failed")
	}
	if err := VerifyAccessTokenHash(proof, "é"); err == nil {
		t.Fatal("accepted non-ASCII token")
	}
	first := ReplayHash("a", "bc", "d", "e")
	second := ReplayHash("a", "bc", "d", "e")
	if first == ReplayHash("ab", "c", "d", "e") || first != second {
		t.Fatal("replay hash is ambiguous or nondeterministic")
	}
}
