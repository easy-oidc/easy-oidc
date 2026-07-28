// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
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
	subjectField  string
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

	oauth2Config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
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
	subjectField := cfg.Generic.SubjectField
	if subjectField == "" {
		subjectField = "sub"
	}

	return &GenericConnector{
		config:        oauth2Config,
		userinfoURL:   cfg.Generic.UserinfoURL,
		emailField:    emailField,
		verifiedField: verifiedField,
		subjectField:  subjectField,
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

// GetIdentity retrieves the stable subject and email assertions from the userinfo endpoint.
func (c *GenericConnector) GetIdentity(ctx context.Context, token *oauth2.Token) (Identity, error) {
	client := c.config.Client(ctx, token)
	resp, err := client.Get(c.userinfoURL)
	if err != nil {
		return Identity{}, fmt.Errorf("failed to get user info: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			return
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return Identity{}, fmt.Errorf("userinfo request failed with status %d: %s", resp.StatusCode, body)
	}

	var userInfo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return Identity{}, fmt.Errorf("failed to decode user info: %w", err)
	}

	emailValue, ok := userInfo[c.emailField]
	if !ok {
		return Identity{}, fmt.Errorf("email field '%s' not found in userinfo response", c.emailField)
	}

	email, ok := emailValue.(string)
	if !ok {
		return Identity{}, fmt.Errorf("email field '%s' is not a string", c.emailField)
	}

	if email == "" {
		return Identity{}, fmt.Errorf("email not provided by provider")
	}

	verified := false
	if verifiedValue, ok := userInfo[c.verifiedField]; ok {
		if verifiedBool, ok := verifiedValue.(bool); ok {
			verified = verifiedBool
		}
	}

	subject, ok := userInfo[c.subjectField].(string)
	if !ok || subject == "" {
		return Identity{}, fmt.Errorf("subject field '%s' is missing or not a nonempty string", c.subjectField)
	}
	return Identity{Subject: subject, Emails: []Email{{Address: email, Verified: verified}}}, nil
}
