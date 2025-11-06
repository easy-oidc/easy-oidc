// Copyright 2025 Nadrama Pty Ltd
// SPDX-License-Identifier: Apache-2.0

// Package secrets provides interfaces and implementations for retrieving secrets from various providers.
package secrets

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/easy-oidc/easy-oidc/internal/config"
)

// Provider is the interface for retrieving secrets from a secret management service.
type Provider interface {
	GetSecret(ctx context.Context, name string) (string, error)
}

// OAuthCredentials represents OAuth client credentials stored as JSON in secrets.
type OAuthCredentials struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// NewProvider creates a new secrets provider based on the configuration.
// It supports AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, and environment variables.
func NewProvider(ctx context.Context, cfg config.SecretsConfig) (Provider, error) {
	switch cfg.Provider {
	case "aws":
		return NewAWSProvider(ctx, cfg.AWSRegion)
	case "gcp":
		return NewGCPProvider(ctx)
	case "azure":
		return NewAzureProvider(ctx, cfg.AzureKeyVaultURL)
	case "env":
		return NewEnvProvider(cfg), nil
	default:
		return nil, fmt.Errorf("unsupported secrets provider: %s", cfg.Provider)
	}
}

// ParseOAuthCredentials parses a JSON secret value into OAuth credentials.
// It validates that both client_id and client_secret are present.
func ParseOAuthCredentials(secretValue string) (*OAuthCredentials, error) {
	var creds OAuthCredentials
	if err := json.Unmarshal([]byte(secretValue), &creds); err != nil {
		return nil, fmt.Errorf("failed to parse OAuth credentials JSON: %w", err)
	}

	if creds.ClientID == "" {
		return nil, fmt.Errorf("client_id is required in OAuth credentials")
	}
	if creds.ClientSecret == "" {
		return nil, fmt.Errorf("client_secret is required in OAuth credentials")
	}

	return &creds, nil
}
