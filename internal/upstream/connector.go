// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package upstream

import (
	"context"
	"fmt"

	"github.com/easy-oidc/easy-oidc/internal/config"
	"golang.org/x/oauth2"
)

// Connector is the interface for upstream OAuth2/OIDC providers.
// It handles the OAuth2 flow and retrieves user information.
type Connector interface {
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
	Exchange(ctx context.Context, code string) (*oauth2.Token, error)
	GetIdentity(ctx context.Context, token *oauth2.Token) (Identity, error)
}

// Email is an email assertion returned by an upstream provider.
type Email struct {
	Address  string
	Verified bool
	Primary  bool
}

// Identity is a stable upstream subject and all of its email assertions.
type Identity struct {
	Subject string
	Emails  []Email
}

// NewConnector creates a new upstream connector based on the configuration.
// Supported types are "google", "github", and "generic".
// The redirect URL is automatically constructed as {issuerURL}/callback/{type}.
func NewConnector(cfg config.ConnectorConfig, redirectURL, clientID, clientSecret string) (Connector, error) {
	switch cfg.Type {
	case "google":
		return NewGoogleConnector(cfg, redirectURL, clientID, clientSecret), nil
	case "github":
		return NewGitHubConnector(cfg, redirectURL, clientID, clientSecret), nil
	case "generic":
		return NewGenericConnector(cfg, redirectURL, clientID, clientSecret), nil
	default:
		return nil, fmt.Errorf("unsupported connector type: %s", cfg.Type)
	}
}
