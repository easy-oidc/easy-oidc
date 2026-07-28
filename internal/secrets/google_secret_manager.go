// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"context"
	"fmt"

	"cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
)

// GoogleSecretManagerProvider retrieves secrets from Google Secret Manager.
type GoogleSecretManagerProvider struct {
	client *secretmanager.Client
}

// NewGoogleSecretManagerProvider creates a Google Secret Manager provider using default credentials.
func NewGoogleSecretManagerProvider(ctx context.Context) (*GoogleSecretManagerProvider, error) {
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create Google Secret Manager client: %w", err)
	}

	return &GoogleSecretManagerProvider{
		client: client,
	}, nil
}

// GetSecret retrieves a secret version from Google Secret Manager.
// The name should be in the format: projects/*/secrets/*/versions/*.
func (p *GoogleSecretManagerProvider) GetSecret(ctx context.Context, name string) (string, error) {
	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: name,
	}

	result, err := p.client.AccessSecretVersion(ctx, req)
	if err != nil {
		return "", fmt.Errorf("failed to access secret %q: %w", name, err)
	}

	return string(result.Payload.Data), nil
}
