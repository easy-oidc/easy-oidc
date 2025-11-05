// Copyright 2025 Nadrama Pty Ltd
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

// AzureProvider retrieves secrets from Azure Key Vault.
type AzureProvider struct {
	client *azsecrets.Client
}

// NewAzureProvider creates a new Azure Key Vault provider using default Azure credentials.
// The vaultURL should be in the format: https://<vault-name>.vault.azure.net/.
func NewAzureProvider(ctx context.Context, vaultURL string) (*AzureProvider, error) {
	if vaultURL == "" {
		return nil, fmt.Errorf("vault URL is required for Azure Key Vault")
	}

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure credential: %w", err)
	}

	client, err := azsecrets.NewClient(vaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure Key Vault client: %w", err)
	}

	return &AzureProvider{
		client: client,
	}, nil
}

// GetSecret retrieves a secret from Azure Key Vault by name.
func (p *AzureProvider) GetSecret(ctx context.Context, name string) (string, error) {
	result, err := p.client.GetSecret(ctx, name, "", nil)
	if err != nil {
		return "", fmt.Errorf("failed to get secret %q from Azure Key Vault: %w", name, err)
	}

	if result.Value == nil {
		return "", fmt.Errorf("secret %q has no value", name)
	}

	return *result.Value, nil
}
