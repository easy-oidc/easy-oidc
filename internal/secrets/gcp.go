// Copyright 2025 Nadrama Pty Ltd
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"context"
	"fmt"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
)

// GCPProvider retrieves secrets from Google Cloud Secret Manager.
type GCPProvider struct {
	client *secretmanager.Client
}

// NewGCPProvider creates a new GCP Secret Manager provider using default credentials.
func NewGCPProvider(ctx context.Context) (*GCPProvider, error) {
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCP Secret Manager client: %w", err)
	}

	return &GCPProvider{
		client: client,
	}, nil
}

// GetSecret retrieves a secret version from GCP Secret Manager.
// The name should be in the format: projects/*/secrets/*/versions/*.
func (p *GCPProvider) GetSecret(ctx context.Context, name string) (string, error) {
	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: name,
	}

	result, err := p.client.AccessSecretVersion(ctx, req)
	if err != nil {
		return "", fmt.Errorf("failed to access secret %q: %w", name, err)
	}

	return string(result.Payload.Data), nil
}
