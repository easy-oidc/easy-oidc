// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// AWSParameterStoreProvider retrieves secrets from AWS Systems Manager Parameter Store.
type AWSParameterStoreProvider struct {
	client *ssm.Client
}

// NewAWSParameterStoreProvider creates an AWS Systems Manager Parameter Store provider.
// If region is provided, it will use that region; otherwise it uses the default AWS configuration.
func NewAWSParameterStoreProvider(ctx context.Context, region string) (*AWSParameterStoreProvider, error) {
	cfg, err := loadAWSConfig(ctx, region)
	if err != nil {
		return nil, err
	}

	return &AWSParameterStoreProvider{
		client: ssm.NewFromConfig(cfg),
	}, nil
}

// GetSecret retrieves and decrypts a parameter value by name.
func (p *AWSParameterStoreProvider) GetSecret(ctx context.Context, name string) (string, error) {
	result, err := p.client.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(name),
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		return "", fmt.Errorf("failed to get parameter %q: %w", name, err)
	}

	if result.Parameter == nil || result.Parameter.Value == nil {
		return "", fmt.Errorf("parameter %q has no string value", name)
	}

	return *result.Parameter.Value, nil
}
