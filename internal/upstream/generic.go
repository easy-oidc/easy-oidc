// Copyright 2025 Nadrama Pty Ltd
// SPDX-License-Identifier: Apache-2.0

package upstream

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/easy-oidc/easy-oidc/internal/config"
	"golang.org/x/oauth2"
)

// GenericConnector implements OAuth2 authentication with generic OAuth2/OIDC providers.
type GenericConnector struct {
	config        *oauth2.Config
	userinfoURL   string
	emailField    string
	verifiedField string
}

// NewGenericConnector creates a new generic OAuth2 connector with the provided configuration.
func NewGenericConnector(cfg config.ConnectorConfig, redirectURL, clientID, clientSecret string) *GenericConnector {
	if cfg.Generic == nil {
		panic("GenericConfig is required for generic connector")
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email"}
	}

	// Note: clientSecret is intentionally not set for public clients (PKCE-only)
	oauth2Config := &oauth2.Config{
		ClientID:    clientID,
		RedirectURL: redirectURL,
		Scopes:      scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  cfg.Generic.AuthorizationURL,
			TokenURL: cfg.Generic.TokenURL,
		},
	}

	emailField := cfg.Generic.EmailField
	if emailField == "" {
		emailField = "email"
	}

	verifiedField := cfg.Generic.EmailVerifiedField
	if verifiedField == "" {
		verifiedField = "email_verified"
	}

	return &GenericConnector{
		config:        oauth2Config,
		userinfoURL:   cfg.Generic.UserinfoURL,
		emailField:    emailField,
		verifiedField: verifiedField,
	}
}

// AuthCodeURL returns the URL to redirect users to for OAuth2 authentication.
func (c *GenericConnector) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	return c.config.AuthCodeURL(state, opts...)
}

// Exchange exchanges an authorization code for an access token.
func (c *GenericConnector) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	return c.config.Exchange(ctx, code)
}

// GetUserEmail retrieves the user's email address and verification status from the userinfo endpoint.
func (c *GenericConnector) GetUserEmail(ctx context.Context, token *oauth2.Token) (string, bool, error) {
	client := c.config.Client(ctx, token)
	resp, err := client.Get(c.userinfoURL)
	if err != nil {
		return "", false, fmt.Errorf("failed to get user info: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			return
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", false, fmt.Errorf("userinfo request failed with status %d: %s", resp.StatusCode, body)
	}

	var userInfo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return "", false, fmt.Errorf("failed to decode user info: %w", err)
	}

	emailValue, ok := userInfo[c.emailField]
	if !ok {
		return "", false, fmt.Errorf("email field '%s' not found in userinfo response", c.emailField)
	}

	email, ok := emailValue.(string)
	if !ok {
		return "", false, fmt.Errorf("email field '%s' is not a string", c.emailField)
	}

	if email == "" {
		return "", false, fmt.Errorf("email not provided by provider")
	}

	verified := false
	if verifiedValue, ok := userInfo[c.verifiedField]; ok {
		if verifiedBool, ok := verifiedValue.(bool); ok {
			verified = verifiedBool
		}
	}

	return email, verified, nil
}
