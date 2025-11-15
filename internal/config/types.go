// Copyright 2025 Nadrama Pty Ltd
// SPDX-License-Identifier: Apache-2.0

// Package config provides configuration loading and validation for easy-oidc.
// It supports JSONC configuration files with comprehensive validation.
package config

// Config represents the top-level configuration structure for easy-oidc.
type Config struct {
	IssuerURL           string                         `json:"issuer_url"`
	HTTPListenAddr      string                         `json:"http_listen_addr"`
	DataDir             string                         `json:"data_dir"`
	JWKSKID             string                         `json:"jwks_kid,omitempty"`
	TokenTTLSeconds     int                            `json:"token_ttl_seconds,omitempty"`
	RequireGroups       *bool                          `json:"require_groups,omitempty"`
	Secrets             SecretsConfig                  `json:"secrets"`
	Connector           ConnectorConfig                `json:"connector"`
	DefaultRedirectURIs []string                       `json:"default_redirect_uris"`
	GroupsOverrides     map[string]map[string][]string `json:"groups_overrides"`
	Clients             map[string]ClientConfig        `json:"clients"`
}

// SecretsConfig defines the secrets provider configuration.
// Supports AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, and env-based secrets.
type SecretsConfig struct {
	Provider             string `json:"provider"`
	SigningKeyName       string `json:"signing_key_name"`
	ConnectorSecretName  string `json:"connector_secret_name"`
	AWSRegion            string `json:"aws_region,omitempty"`
	AzureKeyVaultURL     string `json:"azure_keyvault_url"`
	EnvSigningKey        string `json:"env_signing_key"`
	EnvOAuthClientID     string `json:"env_oauth_client_id"`
	EnvOAuthClientSecret string `json:"env_oauth_client_secret"`
}

// ConnectorConfig defines the upstream OAuth provider configuration.
// Supports Google, GitHub, and generic OAuth2/OIDC providers.
type ConnectorConfig struct {
	Type    string         `json:"type"`
	Scopes  []string       `json:"scopes"`
	Google  *GoogleConfig  `json:"google,omitempty"`
	GitHub  *GitHubConfig  `json:"github,omitempty"`
	Generic *GenericConfig `json:"generic,omitempty"`
}

// GoogleConfig contains Google-specific OAuth configuration options.
type GoogleConfig struct {
	HostedDomain string `json:"hd"`
}

// GitHubConfig contains GitHub-specific OAuth configuration options.
type GitHubConfig struct {
	Hostname string `json:"hostname"`
}

// GenericConfig contains generic OAuth2/OIDC provider configuration options.
type GenericConfig struct {
	AuthorizationURL   string `json:"authorization_url"`
	TokenURL           string `json:"token_url"`
	UserinfoURL        string `json:"userinfo_url"`
	EmailField         string `json:"email_field,omitempty"`          // JSON field name for email in userinfo response
	EmailVerifiedField string `json:"email_verified_field,omitempty"` // JSON field name for email verification status
}

// ClientConfig defines OIDC client-specific configuration.
// Each client can have custom redirect URIs and group override mappings.
type ClientConfig struct {
	RedirectURIs   []string `json:"redirect_uris"`
	GroupsOverride string   `json:"groups_override"`
	RequireGroups  *bool    `json:"require_groups,omitempty"`
}

// ShouldRequireGroups returns whether groups are required for authentication.
// It checks the client-specific setting first, falling back to the global setting.
// If neither is set, it defaults to true.
func (c *ClientConfig) ShouldRequireGroups(globalRequireGroups *bool) bool {
	if c.RequireGroups != nil {
		return *c.RequireGroups
	}
	if globalRequireGroups != nil {
		return *globalRequireGroups
	}
	return true
}
