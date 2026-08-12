// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// AWSSecretsManagerProvider retrieves secrets from AWS Secrets Manager.
type AWSSecretsManagerProvider struct {
	client *secretsmanager.Client
}

// NewAWSSecretsManagerProvider creates a new AWS Secrets Manager provider.
// If region is provided, it will use that region; otherwise uses default AWS configuration.
func NewAWSSecretsManagerProvider(ctx context.Context, region string) (*AWSSecretsManagerProvider, error) {
	cfg, err := loadAWSConfig(ctx, region)
	if err != nil {
		return nil, err
	}

	return &AWSSecretsManagerProvider{
		client: secretsmanager.NewFromConfig(cfg),
	}, nil
}

// GetSecret retrieves a secret value from AWS Secrets Manager by name.
func (p *AWSSecretsManagerProvider) GetSecret(ctx context.Context, name string) (string, error) {
	result, err := p.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: &name,
	})
	if err != nil {
		return "", fmt.Errorf("failed to get secret %q: %w", name, err)
	}

	if result.SecretString == nil {
		return "", fmt.Errorf("secret %q has no string value", name)
	}

	return *result.SecretString, nil
}
