// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

// Command dpop-client exercises DPoP resource and revocation behavior that the
// generic oauth2c interoperability client does not cover.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	dpop "github.com/AxisCommunications/go-dpop"
	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

const clientID = "static-dpop-par-e2e"

var b64 = base64.RawURLEncoding

// tokenResponse contains the OAuth fields asserted by this helper.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
}

// main dispatches the key-generation and post-flow exercise commands.
func main() {
	var err error
	switch {
	case len(os.Args) == 3 && os.Args[1] == "key":
		var thumbprint string
		thumbprint, err = writeKey(os.Args[2])
		if err == nil {
			fmt.Println(thumbprint)
		}
	case len(os.Args) == 6 && os.Args[1] == "exercise":
		err = exercise(strings.TrimSuffix(os.Args[2], "/"), os.Args[3], os.Args[4], os.Args[5])
	default:
		fmt.Fprintln(os.Stderr, "usage: dpop-client key KEY_FILE")
		fmt.Fprintln(os.Stderr, "       dpop-client exercise ISSUER KEY_FILE TOKENS_FILE REFRESHED_TOKENS_FILE")
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "DPoP E2E helper failed: %v\n", err)
		os.Exit(1)
	}
}

// writeKey creates a private P-256 JWKS and returns its RFC 7638 thumbprint.
func writeKey(path string) (string, error) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate key: %w", err)
	}
	jwk := jose.JSONWebKey{Key: private, Use: "sig", Algorithm: "ES256"}
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("thumbprint key: %w", err)
	}
	data, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	if err != nil {
		return "", fmt.Errorf("marshal key: %w", err)
	}
	if err = os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return "", fmt.Errorf("write key: %w", err)
	}
	return b64.EncodeToString(thumbprint), nil
}

// readKey parses the generated private JWKS and returns its RFC 7638 thumbprint.
func readKey(path string) (*ecdsa.PrivateKey, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("read key: %w", err)
	}
	var jwks jose.JSONWebKeySet
	if err = json.Unmarshal(data, &jwks); err != nil {
		return nil, "", fmt.Errorf("parse key: %w", err)
	}
	if len(jwks.Keys) != 1 {
		return nil, "", errors.New("key file must contain one key")
	}
	jwk := jwks.Keys[0]
	private, ok := jwk.Key.(*ecdsa.PrivateKey)
	if !ok || jwk.IsPublic() || !jwk.Valid() {
		return nil, "", errors.New("invalid private key")
	}
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, "", fmt.Errorf("thumbprint key: %w", err)
	}
	return private, b64.EncodeToString(thumbprint), nil
}

// readTokens reads and validates an oauth2c token response.
func readTokens(path string) (tokenResponse, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return tokenResponse{}, fmt.Errorf("read tokens: %w", err)
	}
	var tokens tokenResponse
	if err = json.Unmarshal(data, &tokens); err != nil {
		return tokens, fmt.Errorf("parse tokens: %w", err)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" || tokens.TokenType != "DPoP" {
		return tokens, errors.New("token response did not contain DPoP access and refresh tokens")
	}
	return tokens, nil
}

// exercise checks DPoP binding and protected endpoint behavior after oauth2c completes the OAuth flow.
func exercise(issuer, keyPath, tokensPath, refreshedPath string) error {
	key, thumbprint, err := readKey(keyPath)
	if err != nil {
		return err
	}
	tokens, err := readTokens(tokensPath)
	if err != nil {
		return fmt.Errorf("authorization-code response: %w", err)
	}
	refreshed, err := readTokens(refreshedPath)
	if err != nil {
		return fmt.Errorf("refresh response: %w", err)
	}
	if refreshed.RefreshToken == tokens.RefreshToken {
		return errors.New("refresh token was not rotated")
	}
	for name, accessToken := range map[string]string{"authorization-code": tokens.AccessToken, "refreshed": refreshed.AccessToken} {
		got, err := tokenThumbprint(accessToken)
		if err != nil || got != thumbprint {
			return fmt.Errorf("%s access token cnf.jkt does not match oauth2c key", name)
		}
	}

	client := &http.Client{Timeout: 10 * time.Second}
	userinfo := issuer + "/userinfo"
	proof, err := createProof(key, http.MethodGet, userinfo, tokens.AccessToken)
	if err != nil {
		return err
	}
	_, status, err := request(client, http.MethodGet, userinfo, nil, proof, tokens.AccessToken, false)
	if err != nil {
		return fmt.Errorf("userinfo: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("userinfo: HTTP %d", status)
	}
	_, status, err = request(client, http.MethodGet, userinfo, nil, proof, tokens.AccessToken, false)
	if err != nil {
		return fmt.Errorf("cross-replica replay: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("cross-replica request: HTTP %d", status)
	}
	_, status, err = request(client, http.MethodGet, userinfo, nil, proof, tokens.AccessToken, false)
	if err != nil {
		return fmt.Errorf("same-replica replay: %w", err)
	}
	if status != http.StatusUnauthorized {
		return fmt.Errorf("same-replica replay accepted: HTTP %d", status)
	}
	_, status, err = request(client, http.MethodGet, userinfo, nil, "", tokens.AccessToken, true)
	if err != nil {
		return fmt.Errorf("bearer downgrade: %w", err)
	}
	if status != http.StatusUnauthorized {
		return fmt.Errorf("bearer downgrade accepted: HTTP %d", status)
	}

	revoke := issuer + "/revoke"
	proof, err = createProof(key, http.MethodPost, revoke, "")
	if err != nil {
		return err
	}
	form := url.Values{"token": {refreshed.RefreshToken}, "token_type_hint": {"refresh_token"}, "client_id": {clientID}}
	_, status, err = request(client, http.MethodPost, revoke, form, proof, "", false)
	if err != nil {
		return fmt.Errorf("revoke: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("revoke: HTTP %d", status)
	}

	token := issuer + "/token"
	proof, err = createProof(key, http.MethodPost, token, "")
	if err != nil {
		return err
	}
	form = url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshed.RefreshToken}, "client_id": {clientID}}
	body, status, err := request(client, http.MethodPost, token, form, proof, "", false)
	if err != nil {
		return fmt.Errorf("post-revocation refresh: %w", err)
	}
	var oauthError struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &oauthError) != nil || status != http.StatusBadRequest || oauthError.Error != "invalid_grant" {
		return fmt.Errorf("revoked refresh token accepted: HTTP %d", status)
	}

	fmt.Println("DPoP resource, replay, downgrade, and revocation checks passed")
	return nil
}

// createProof creates an independently implemented DPoP proof with go-dpop.
func createProof(key *ecdsa.PrivateKey, method, target, accessToken string) (string, error) {
	claims := dpop.ProofTokenClaims{
		RegisteredClaims: &jwt.RegisteredClaims{
			ID:       rand.Text(),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
		Method: dpop.HTTPVerb(method),
		URL:    target,
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		claims.AccessTokenHash = b64.EncodeToString(sum[:])
	}
	proof, err := dpop.Create(jwt.SigningMethodES256, claims, key)
	if err != nil {
		return "", fmt.Errorf("create DPoP proof: %w", err)
	}
	return proof, nil
}

// request sends one bounded HTTP request with the requested authorization scheme.
func request(client *http.Client, method, target string, form url.Values, proof, accessToken string, bearer bool) ([]byte, int, error) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		return nil, 0, fmt.Errorf("create request: %w", err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}
	if accessToken != "" {
		scheme := "DPoP"
		if bearer {
			scheme = "Bearer"
		}
		req.Header.Set("Authorization", scheme+" "+accessToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	result, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read response: %w", err)
	}
	return result, resp.StatusCode, nil
}

// tokenThumbprint decodes the untrusted cnf.jkt claim solely for an E2E assertion.
func tokenThumbprint(token string) (string, error) {
	if len(token) > 16<<10 {
		return "", fmt.Errorf("token exceeds 16 KiB")
	}
	var claims struct {
		jwt.RegisteredClaims
		Confirmation struct {
			Thumbprint string `json:"jkt"`
		} `json:"cnf"`
	}
	if _, _, err := jwt.NewParser().ParseUnverified(token, &claims); err != nil {
		return "", fmt.Errorf("parse access token: %w", err)
	}
	return claims.Confirmation.Thumbprint, nil
}
