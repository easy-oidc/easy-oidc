// Copyright 2025 Nadrama Pty Ltd
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/tidwall/jsonc"
)

// Load reads and parses a JSONC configuration file from the given path.
// It validates the configuration and returns an error if validation fails.
// The path parameter must be non-empty.
func Load(path string) (*Config, error) {
	if path == "" {
		return nil, fmt.Errorf("config path is required")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	data = jsonc.ToJSON(data)

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	if cfg.TokenTTLSeconds == 0 {
		cfg.TokenTTLSeconds = 3600
	}

	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

func validate(cfg *Config) error {
	if err := validateIssuerURL(cfg.IssuerURL); err != nil {
		return fmt.Errorf("issuer_url: %w", err)
	}

	if cfg.HTTPListenAddr == "" {
		return fmt.Errorf("http_listen_addr is required")
	}

	if cfg.DataDir == "" {
		return fmt.Errorf("data_dir is required")
	}

	if err := validateSecretsProvider(cfg.Secrets.Provider); err != nil {
		return fmt.Errorf("secrets.provider: %w", err)
	}

	if cfg.Secrets.Provider == "env" {
		if cfg.Secrets.EnvSigningKey == "" {
			return fmt.Errorf("secrets.env_signing_key is required for env provider")
		}
		if cfg.Secrets.EnvOAuthClientID == "" {
			return fmt.Errorf("secrets.env_oauth_client_id is required for env provider")
		}
		if cfg.Secrets.EnvOAuthClientSecret == "" {
			return fmt.Errorf("secrets.env_oauth_client_secret is required for env provider")
		}
	} else {
		if cfg.Secrets.SigningKeyName == "" {
			return fmt.Errorf("secrets.signing_key_name is required for cloud providers")
		}
		if cfg.Secrets.ConnectorSecretName == "" {
			return fmt.Errorf("secrets.connector_secret_name is required for cloud providers")
		}
	}

	if cfg.Secrets.Provider == "azure" && cfg.Secrets.AzureKeyVaultURL == "" {
		return fmt.Errorf("secrets.azure_keyvault_url is required for Azure provider")
	}

	if err := validateConnector(&cfg.Connector); err != nil {
		return fmt.Errorf("connector: %w", err)
	}

	if len(cfg.Clients) == 0 {
		return fmt.Errorf("at least one client must be configured")
	}

	for clientID, client := range cfg.Clients {
		if err := validateClient(clientID, client, cfg.DefaultRedirectURIs, cfg.GroupsOverrides); err != nil {
			return fmt.Errorf("client %q: %w", clientID, err)
		}
	}

	if err := validateGroupsOverrides(cfg.GroupsOverrides); err != nil {
		return fmt.Errorf("groups_overrides: %w", err)
	}

	return nil
}

func validateIssuerURL(issuer string) error {
	if issuer == "" {
		return fmt.Errorf("is required")
	}

	u, err := url.Parse(issuer)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("scheme must be http or https")
	}

	if u.Scheme == "http" && !strings.Contains(u.Host, "localhost") && !strings.Contains(u.Host, "127.0.0.1") {
		return fmt.Errorf("http scheme only allowed for localhost in development")
	}

	return nil
}

func validateSecretsProvider(provider string) error {
	valid := map[string]bool{"aws": true, "gcp": true, "azure": true, "env": true}
	if !valid[provider] {
		return fmt.Errorf("must be one of: aws, gcp, azure, env")
	}
	return nil
}

func validateConnector(c *ConnectorConfig) error {
	if c.Type != "google" && c.Type != "github" && c.Type != "generic" {
		return fmt.Errorf("type must be google, github, or generic")
	}

	if c.ClientID == "" {
		return fmt.Errorf("client_id is required")
	}

	if c.RedirectURL == "" {
		return fmt.Errorf("redirect_url is required")
	}

	if c.Type == "generic" {
		if c.Generic == nil {
			return fmt.Errorf("generic configuration is required for type generic")
		}
		if c.Generic.AuthorizationURL == "" {
			return fmt.Errorf("generic.authorization_url is required")
		}
		if c.Generic.TokenURL == "" {
			return fmt.Errorf("generic.token_url is required")
		}
		if c.Generic.UserinfoURL == "" {
			return fmt.Errorf("generic.userinfo_url is required")
		}
		if _, err := url.Parse(c.Generic.AuthorizationURL); err != nil {
			return fmt.Errorf("generic.authorization_url is not a valid URL: %w", err)
		}
		if _, err := url.Parse(c.Generic.TokenURL); err != nil {
			return fmt.Errorf("generic.token_url is not a valid URL: %w", err)
		}
		if _, err := url.Parse(c.Generic.UserinfoURL); err != nil {
			return fmt.Errorf("generic.userinfo_url is not a valid URL: %w", err)
		}
	}

	return nil
}

func validateClient(clientID string, c ClientConfig, defaultRedirectURIs []string, overrides map[string]map[string][]string) error {
	if clientID == "" {
		return fmt.Errorf("client_id cannot be empty")
	}

	redirectURIs := c.RedirectURIs
	if len(redirectURIs) == 0 {
		redirectURIs = defaultRedirectURIs
	}

	if len(redirectURIs) == 0 {
		return fmt.Errorf("redirect_uris must be specified either per-client or as default_redirect_uris")
	}

	for _, uri := range redirectURIs {
		if err := validateRedirectURI(uri); err != nil {
			return fmt.Errorf("invalid redirect_uri %q: %w", uri, err)
		}
	}

	if c.GroupsOverride != "" {
		if _, exists := overrides[c.GroupsOverride]; !exists {
			return fmt.Errorf("groups_override %q not found in groups_overrides", c.GroupsOverride)
		}
	}

	return nil
}

func validateRedirectURI(uri string) error {
	u, err := url.Parse(uri)
	if err != nil {
		return err
	}

	if u.Scheme == "http" {
		if !strings.Contains(u.Host, "localhost") && !strings.Contains(u.Host, "127.0.0.1") {
			return fmt.Errorf("http redirect URIs only allowed for localhost")
		}
	} else if u.Scheme != "https" {
		return fmt.Errorf("scheme must be http (localhost only) or https")
	}

	return nil
}

func validateGroupsOverrides(overrides map[string]map[string][]string) error {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

	for overrideName, mapping := range overrides {
		if overrideName == "" {
			return fmt.Errorf("override key cannot be empty")
		}

		for email := range mapping {
			if !emailRegex.MatchString(email) {
				return fmt.Errorf("invalid email format in override %q: %q", overrideName, email)
			}
		}
	}

	return nil
}
