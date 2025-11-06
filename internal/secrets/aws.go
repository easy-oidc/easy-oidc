// Copyright 2025 Nadrama Pty Ltd
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// AWSProvider retrieves secrets from AWS Secrets Manager.
type AWSProvider struct {
	client *secretsmanager.Client
}

// NewAWSProvider creates a new AWS Secrets Manager provider.
// If region is provided, it will use that region; otherwise uses default AWS configuration.
func NewAWSProvider(ctx context.Context, region string) (*AWSProvider, error) {
	var cfg aws.Config
	var err error

	if region != "" {
		cfg, err = config.LoadDefaultConfig(ctx, config.WithRegion(region))
	} else {
		cfg, err = config.LoadDefaultConfig(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return &AWSProvider{
		client: secretsmanager.NewFromConfig(cfg),
	}, nil
}

// GetSecret retrieves a secret value from AWS Secrets Manager by name.
func (p *AWSProvider) GetSecret(ctx context.Context, name string) (string, error) {
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
