// Copyright 2025 Nadrama Pty Ltd
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"context"
	"fmt"
	"os"

	"github.com/easy-oidc/easy-oidc/internal/config"
)

// EnvProvider reads secrets from environment variables.
type EnvProvider struct {
	signingKeyEnvName        string
	oauthClientIDEnvName     string
	oauthClientSecretEnvName string
}

// NewEnvProvider creates a new environment-based secrets provider.
// It reads the environment variable names from the config and will fetch values at runtime.
func NewEnvProvider(cfg config.SecretsConfig) *EnvProvider {
	return &EnvProvider{
		signingKeyEnvName:        cfg.EnvSigningKey,
		oauthClientIDEnvName:     cfg.EnvOAuthClientID,
		oauthClientSecretEnvName: cfg.EnvOAuthClientSecret,
	}
}

// GetSecret retrieves a secret by name from environment variables.
// Supported names: "signing_key" and "oauth_credentials".
func (p *EnvProvider) GetSecret(ctx context.Context, name string) (string, error) {
	switch name {
	case "signing_key":
		if p.signingKeyEnvName == "" {
			return "", fmt.Errorf("env_signing_key not configured")
		}
		value := os.Getenv(p.signingKeyEnvName)
		if value == "" {
			return "", fmt.Errorf("environment variable %s is not set or empty", p.signingKeyEnvName)
		}
		return value, nil
	case "oauth_credentials":
		if p.oauthClientIDEnvName == "" || p.oauthClientSecretEnvName == "" {
			return "", fmt.Errorf("env_oauth_client_id and env_oauth_client_secret must be configured")
		}
		clientID := os.Getenv(p.oauthClientIDEnvName)
		if clientID == "" {
			return "", fmt.Errorf("environment variable %s is not set or empty", p.oauthClientIDEnvName)
		}
		clientSecret := os.Getenv(p.oauthClientSecretEnvName)
		if clientSecret == "" {
			return "", fmt.Errorf("environment variable %s is not set or empty", p.oauthClientSecretEnvName)
		}
		return fmt.Sprintf(`{"client_id":"%s","client_secret":"%s"}`, clientID, clientSecret), nil
	default:
		return "", fmt.Errorf("unknown secret: %s", name)
	}
}
