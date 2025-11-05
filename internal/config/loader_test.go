// Copyright 2025 Nadrama Pty Ltd
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		expectError bool
	}{
		{
			name:        "empty path",
			path:        "",
			expectError: true,
		},
		{
			name:        "non-existent file",
			path:        "/tmp/nonexistent-config-12345.jsonc",
			expectError: true,
		},
		{
			name:        "valid config",
			path:        "testdata/valid-config.jsonc",
			expectError: false,
		},
		{
			name:        "invalid json",
			path:        "testdata/invalid-json.jsonc",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "valid config" {
				setupTestConfig(t)
				defer cleanupTestConfig(t)
			}
			if tt.name == "invalid json" {
				setupInvalidConfig(t)
				defer cleanupTestConfig(t)
			}

			_, err := Load(tt.path)
			if (err != nil) != tt.expectError {
				t.Errorf("expected error: %v, got: %v", tt.expectError, err)
			}
		})
	}
}

func TestValidateIssuerURL(t *testing.T) {
	tests := []struct {
		name        string
		issuer      string
		expectError bool
	}{
		{"valid https", "https://auth.example.com", false},
		{"valid https with port", "https://auth.example.com:8443", false},
		{"valid localhost http", "http://localhost:8080", false},
		{"valid 127.0.0.1 http", "http://127.0.0.1:8080", false},
		{"invalid http for production", "http://auth.example.com", true},
		{"empty issuer", "", true},
		{"invalid scheme", "ftp://auth.example.com", true},
		{"no scheme", "auth.example.com", true},
		{"invalid url", "://invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateIssuerURL(tt.issuer)
			if (err != nil) != tt.expectError {
				t.Errorf("expected error: %v, got: %v", tt.expectError, err)
			}
		})
	}
}

func TestValidateRedirectURI(t *testing.T) {
	tests := []struct {
		name        string
		uri         string
		expectError bool
	}{
		{"valid https", "https://app.example.com/callback", false},
		{"valid https with port", "https://app.example.com:8443/callback", false},
		{"valid localhost http", "http://localhost:8000", false},
		{"valid localhost with path", "http://localhost:8000/callback", false},
		{"valid 127.0.0.1 http", "http://127.0.0.1:8000", false},
		{"invalid http for production", "http://app.example.com/callback", true},
		{"invalid scheme", "ftp://localhost:8000", true},
		{"no scheme", "localhost:8000", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRedirectURI(tt.uri)
			if (err != nil) != tt.expectError {
				t.Errorf("expected error: %v, got: %v", tt.expectError, err)
			}
		})
	}
}

func TestValidateSecretsProvider(t *testing.T) {
	tests := []struct {
		name        string
		provider    string
		expectError bool
	}{
		{"valid aws", "aws", false},
		{"valid gcp", "gcp", false},
		{"valid azure", "azure", false},
		{"valid env", "env", false},
		{"invalid provider", "vault", true},
		{"empty provider", "", true},
		{"uppercase", "AWS", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSecretsProvider(tt.provider)
			if (err != nil) != tt.expectError {
				t.Errorf("expected error: %v, got: %v", tt.expectError, err)
			}
		})
	}
}

func TestValidateConnector(t *testing.T) {
	tests := []struct {
		name        string
		connector   ConnectorConfig
		expectError bool
	}{
		{
			name: "valid google",
			connector: ConnectorConfig{
				Type:        "google",
				ClientID:    "test-client",
				RedirectURL: "https://auth.example.com/callback/google",
			},
			expectError: false,
		},
		{
			name: "valid github",
			connector: ConnectorConfig{
				Type:        "github",
				ClientID:    "test-client",
				RedirectURL: "https://auth.example.com/callback/github",
			},
			expectError: false,
		},
		{
			name: "invalid type",
			connector: ConnectorConfig{
				Type:        "okta",
				ClientID:    "test-client",
				RedirectURL: "https://auth.example.com/callback",
			},
			expectError: true,
		},
		{
			name: "missing client_id",
			connector: ConnectorConfig{
				Type:        "google",
				RedirectURL: "https://auth.example.com/callback/google",
			},
			expectError: true,
		},
		{
			name: "missing redirect_url",
			connector: ConnectorConfig{
				Type:     "google",
				ClientID: "test-client",
			},
			expectError: true,
		},
		{
			name: "valid generic",
			connector: ConnectorConfig{
				Type:        "generic",
				ClientID:    "test-client",
				RedirectURL: "https://auth.example.com/callback/generic",
				Generic: &GenericConfig{
					AuthorizationURL: "https://dex.example.com/auth",
					TokenURL:         "https://dex.example.com/token",
					UserinfoURL:      "https://dex.example.com/userinfo",
				},
			},
			expectError: false,
		},
		{
			name: "generic missing config",
			connector: ConnectorConfig{
				Type:        "generic",
				ClientID:    "test-client",
				RedirectURL: "https://auth.example.com/callback/generic",
			},
			expectError: true,
		},
		{
			name: "generic missing authorization_url",
			connector: ConnectorConfig{
				Type:        "generic",
				ClientID:    "test-client",
				RedirectURL: "https://auth.example.com/callback/generic",
				Generic: &GenericConfig{
					TokenURL:    "https://dex.example.com/token",
					UserinfoURL: "https://dex.example.com/userinfo",
				},
			},
			expectError: true,
		},
		{
			name: "generic missing token_url",
			connector: ConnectorConfig{
				Type:        "generic",
				ClientID:    "test-client",
				RedirectURL: "https://auth.example.com/callback/generic",
				Generic: &GenericConfig{
					AuthorizationURL: "https://dex.example.com/auth",
					UserinfoURL:      "https://dex.example.com/userinfo",
				},
			},
			expectError: true,
		},
		{
			name: "generic missing userinfo_url",
			connector: ConnectorConfig{
				Type:        "generic",
				ClientID:    "test-client",
				RedirectURL: "https://auth.example.com/callback/generic",
				Generic: &GenericConfig{
					AuthorizationURL: "https://dex.example.com/auth",
					TokenURL:         "https://dex.example.com/token",
				},
			},
			expectError: true,
		},
		{
			name: "generic invalid authorization_url",
			connector: ConnectorConfig{
				Type:        "generic",
				ClientID:    "test-client",
				RedirectURL: "https://auth.example.com/callback/generic",
				Generic: &GenericConfig{
					AuthorizationURL: "://invalid",
					TokenURL:         "https://dex.example.com/token",
					UserinfoURL:      "https://dex.example.com/userinfo",
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConnector(&tt.connector)
			if (err != nil) != tt.expectError {
				t.Errorf("expected error: %v, got: %v", tt.expectError, err)
			}
		})
	}
}

func TestValidateClient(t *testing.T) {
	defaultRedirects := []string{"http://localhost:8000"}
	overrides := map[string]map[string][]string{
		"test-groups": {
			"alice@example.com": {"admins"},
		},
	}

	tests := []struct {
		name        string
		clientID    string
		client      ClientConfig
		expectError bool
	}{
		{
			name:     "valid with redirect URIs",
			clientID: "test-client",
			client: ClientConfig{
				RedirectURIs: []string{"https://app.example.com/callback"},
			},
			expectError: false,
		},
		{
			name:        "valid with defaults",
			clientID:    "test-client",
			client:      ClientConfig{},
			expectError: false,
		},
		{
			name:     "valid with groups override",
			clientID: "test-client",
			client: ClientConfig{
				GroupsOverride: "test-groups",
			},
			expectError: false,
		},
		{
			name:     "invalid groups override",
			clientID: "test-client",
			client: ClientConfig{
				GroupsOverride: "nonexistent",
			},
			expectError: true,
		},
		{
			name:     "invalid redirect URI",
			clientID: "test-client",
			client: ClientConfig{
				RedirectURIs: []string{"ftp://invalid"},
			},
			expectError: true,
		},
		{
			name:        "empty client ID",
			clientID:    "",
			client:      ClientConfig{},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateClient(tt.clientID, tt.client, defaultRedirects, overrides)
			if (err != nil) != tt.expectError {
				t.Errorf("expected error: %v, got: %v", tt.expectError, err)
			}
		})
	}
}

func TestValidateGroupsOverrides(t *testing.T) {
	tests := []struct {
		name        string
		overrides   map[string]map[string][]string
		expectError bool
	}{
		{
			name: "valid overrides",
			overrides: map[string]map[string][]string{
				"prod-groups": {
					"alice@example.com": {"admins"},
					"bob@example.com":   {"users"},
				},
			},
			expectError: false,
		},
		{
			name: "invalid email format",
			overrides: map[string]map[string][]string{
				"prod-groups": {
					"not-an-email": {"admins"},
				},
			},
			expectError: true,
		},
		{
			name: "empty override name",
			overrides: map[string]map[string][]string{
				"": {
					"alice@example.com": {"admins"},
				},
			},
			expectError: true,
		},
		{
			name: "complex emails",
			overrides: map[string]map[string][]string{
				"groups": {
					"alice+tag@example.com":     {"admins"},
					"bob.smith@sub.example.com": {"users"},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateGroupsOverrides(tt.overrides)
			if (err != nil) != tt.expectError {
				t.Errorf("expected error: %v, got: %v", tt.expectError, err)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid minimal config",
			config: Config{
				IssuerURL:      "https://auth.example.com",
				HTTPListenAddr: "127.0.0.1:8080",
				JWKSKID:        "key-1",
				DataDir:        "temp",
				Secrets: SecretsConfig{
					Provider:             "env",
					EnvSigningKey:        "SIGNING_KEY",
					EnvOAuthClientID:     "OAUTH_CLIENT_ID",
					EnvOAuthClientSecret: "OAUTH_CLIENT_SECRET",
				},
				Connector: ConnectorConfig{
					Type:        "google",
					ClientID:    "test-client",
					RedirectURL: "https://auth.example.com/callback",
				},
				DefaultRedirectURIs: []string{"http://localhost:8000"},
				Clients: map[string]ClientConfig{
					"test-client": {},
				},
			},
			expectError: false,
		},
		{
			name: "missing issuer_url",
			config: Config{
				HTTPListenAddr: "127.0.0.1:8080",
				JWKSKID:        "key-1",
			},
			expectError: true,
		},
		{
			name: "missing http_listen_addr",
			config: Config{
				IssuerURL: "https://auth.example.com",
				JWKSKID:   "key-1",
			},
			expectError: true,
		},
		{
			name: "missing jwks_kid",
			config: Config{
				IssuerURL:      "https://auth.example.com",
				HTTPListenAddr: "127.0.0.1:8080",
			},
			expectError: true,
		},
		{
			name: "invalid secrets provider",
			config: Config{
				IssuerURL:      "https://auth.example.com",
				HTTPListenAddr: "127.0.0.1:8080",
				JWKSKID:        "key-1",
				Secrets: SecretsConfig{
					Provider: "invalid",
				},
			},
			expectError: true,
		},
		{
			name: "aws without secret names",
			config: Config{
				IssuerURL:      "https://auth.example.com",
				HTTPListenAddr: "127.0.0.1:8080",
				JWKSKID:        "key-1",
				Secrets: SecretsConfig{
					Provider: "aws",
				},
			},
			expectError: true,
		},
		{
			name: "azure without vault url",
			config: Config{
				IssuerURL:      "https://auth.example.com",
				HTTPListenAddr: "127.0.0.1:8080",
				JWKSKID:        "key-1",
				Secrets: SecretsConfig{
					Provider:            "azure",
					SigningKeyName:      "key",
					ConnectorSecretName: "secret",
				},
			},
			expectError: true,
		},
		{
			name: "no clients",
			config: Config{
				IssuerURL:      "https://auth.example.com",
				HTTPListenAddr: "127.0.0.1:8080",
				JWKSKID:        "key-1",
				Secrets: SecretsConfig{
					Provider:             "env",
					EnvSigningKey:        "SIGNING_KEY",
					EnvOAuthClientID:     "OAUTH_CLIENT_ID",
					EnvOAuthClientSecret: "OAUTH_CLIENT_SECRET",
				},
				Connector: ConnectorConfig{
					Type:        "google",
					ClientID:    "test",
					RedirectURL: "https://auth.example.com/callback",
				},
				Clients: map[string]ClientConfig{},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validate(&tt.config)
			if (err != nil) != tt.expectError {
				t.Errorf("expected error: %v, got: %v (error: %v)", tt.expectError, err != nil, err)
			}
		})
	}
}

// Helper functions for test setup

func setupTestConfig(t *testing.T) {
	t.Helper()
	testDir := "testdata"
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	configContent := `{
		"issuer_url": "https://auth.example.com",
		"http_listen_addr": "127.0.0.1:8080",
		"jwks_kid": "test-key",
		"data_dir": "temp",
		"secrets": {
			"provider": "env",
			"env_signing_key": "SIGNING_KEY",
			"env_oauth_client_id": "OAUTH_CLIENT_ID",
			"env_oauth_client_secret": "OAUTH_CLIENT_SECRET"
		},
		"connector": {
			"type": "google",
			"client_id": "test-client",
			"redirect_url": "https://auth.example.com/callback/google"
		},
		"default_redirect_uris": ["http://localhost:8000"],
		"clients": {
			"test-client": {}
		}
	}`

	if err := os.WriteFile(filepath.Join(testDir, "valid-config.jsonc"), []byte(configContent), 0644); err != nil {
		t.Fatal(err)
	}
}

func setupInvalidConfig(t *testing.T) {
	t.Helper()
	testDir := "testdata"
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(testDir, "invalid-json.jsonc"), []byte("{invalid json"), 0644); err != nil {
		t.Fatal(err)
	}
}

func cleanupTestConfig(t *testing.T) {
	t.Helper()
	if err := os.RemoveAll("testdata"); err != nil {
		t.Logf("failed to remove testdata: %v", err)
	}
}
