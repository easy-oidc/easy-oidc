// Copyright 2025 Nadrama Pty Ltd
// SPDX-License-Identifier: Apache-2.0

// Package upstream provides connectors for authenticating users with upstream OAuth2/OIDC providers.
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
	GetUserEmail(ctx context.Context, token *oauth2.Token) (email string, verified bool, err error)
}

// NewConnector creates a new upstream connector based on the configuration.
// Supported types are "google", "github", and "generic".
func NewConnector(cfg config.ConnectorConfig, clientSecret string) (Connector, error) {
	switch cfg.Type {
	case "google":
		return NewGoogleConnector(cfg, clientSecret), nil
	case "github":
		return NewGitHubConnector(cfg, clientSecret), nil
	case "generic":
		return NewGenericConnector(cfg, clientSecret), nil
	default:
		return nil, fmt.Errorf("unsupported connector type: %s", cfg.Type)
	}
}
