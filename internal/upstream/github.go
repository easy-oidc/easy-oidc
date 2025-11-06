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
	"golang.org/x/oauth2/github"
)

// GitHubConnector implements OAuth2 authentication with GitHub.
type GitHubConnector struct {
	config   *oauth2.Config
	hostname string
}

type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

// NewGitHubConnector creates a new GitHub OAuth2 connector with the provided configuration.
// It supports both github.com and GitHub Enterprise instances.
func NewGitHubConnector(cfg config.ConnectorConfig, redirectURL, clientID, clientSecret string) *GitHubConnector {
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"user:email"}
	}

	oauth2Config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
		Endpoint:     github.Endpoint,
	}

	hostname := "github.com"
	if cfg.GitHub != nil && cfg.GitHub.Hostname != "" {
		hostname = cfg.GitHub.Hostname
	}

	return &GitHubConnector{
		config:   oauth2Config,
		hostname: hostname,
	}
}

// AuthCodeURL returns the URL to redirect users to for GitHub OAuth2 authentication.
func (c *GitHubConnector) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	return c.config.AuthCodeURL(state, opts...)
}

// Exchange exchanges an authorization code for an access token from GitHub.
func (c *GitHubConnector) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	return c.config.Exchange(ctx, code)
}

// GetUserEmail retrieves the user's primary verified email address from GitHub's user emails API.
// It prefers the primary verified email, but falls back to any verified email.
func (c *GitHubConnector) GetUserEmail(ctx context.Context, token *oauth2.Token) (string, bool, error) {
	client := c.config.Client(ctx, token)

	apiURL := fmt.Sprintf("https://api.%s/user/emails", c.hostname)
	if c.hostname != "github.com" {
		apiURL = fmt.Sprintf("https://%s/api/v3/user/emails", c.hostname)
	}

	resp, err := client.Get(apiURL)
	if err != nil {
		return "", false, fmt.Errorf("failed to get user emails: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			return
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", false, fmt.Errorf("user emails request failed with status %d: %s", resp.StatusCode, body)
	}

	var emails []githubEmail
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", false, fmt.Errorf("failed to decode emails: %w", err)
	}

	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, true, nil
		}
	}

	for _, e := range emails {
		if e.Verified {
			return e.Email, true, nil
		}
	}

	return "", false, fmt.Errorf("no verified email found")
}
