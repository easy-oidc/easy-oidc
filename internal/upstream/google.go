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
	"golang.org/x/oauth2/google"
)

// GoogleConnector implements OAuth2 authentication with Google.
type GoogleConnector struct {
	config       *oauth2.Config
	hostedDomain string
}

type googleUserInfo struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

// NewGoogleConnector creates a new Google OAuth2 connector with the provided configuration.
func NewGoogleConnector(cfg config.ConnectorConfig, redirectURL, clientID, clientSecret string) *GoogleConnector {
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}

	oauth2Config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
		Endpoint:     google.Endpoint,
	}

	hostedDomain := ""
	if cfg.Google != nil {
		hostedDomain = cfg.Google.HostedDomain
	}

	return &GoogleConnector{
		config:       oauth2Config,
		hostedDomain: hostedDomain,
	}
}

// AuthCodeURL returns the URL to redirect users to for Google OAuth2 authentication.
// If a hosted domain is configured, it adds the hd parameter to restrict authentication.
func (c *GoogleConnector) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	if c.hostedDomain != "" {
		opts = append(opts, oauth2.SetAuthURLParam("hd", c.hostedDomain))
	}
	return c.config.AuthCodeURL(state, opts...)
}

// Exchange exchanges an authorization code for an access token from Google.
func (c *GoogleConnector) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	return c.config.Exchange(ctx, code)
}

// GetUserEmail retrieves the user's email address and verification status from Google's userinfo endpoint.
func (c *GoogleConnector) GetUserEmail(ctx context.Context, token *oauth2.Token) (string, bool, error) {
	client := c.config.Client(ctx, token)
	resp, err := client.Get("https://openidconnect.googleapis.com/v1/userinfo")
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

	var userInfo googleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return "", false, fmt.Errorf("failed to decode user info: %w", err)
	}

	if userInfo.Email == "" {
		return "", false, fmt.Errorf("email not provided by Google")
	}

	return userInfo.Email, userInfo.EmailVerified, nil
}
