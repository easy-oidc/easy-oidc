// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
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
}

// NewEnvProvider creates a new environment-based secrets provider.
// Configured secret names are resolved when GetSecret is called.
func NewEnvProvider(cfg config.SecretsConfig) *EnvProvider {
	return &EnvProvider{}
}

// GetSecret retrieves a secret by name from environment variables.
func (p *EnvProvider) GetSecret(ctx context.Context, name string) (string, error) {
	value := os.Getenv(name)
	if value == "" {
		return "", fmt.Errorf("environment variable %s is not set or empty", name)
	}
	return value, nil
}
