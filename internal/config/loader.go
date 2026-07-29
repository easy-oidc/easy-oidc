// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/mail"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/tailscale/hujson"
)

const DefaultSigningAlgorithm = "RS256"

var supportedSigningAlgorithms = map[string]struct{}{
	"RS256": {}, "RS384": {}, "RS512": {},
	"ES256": {}, "ES384": {}, "ES512": {},
	"PS256": {}, "PS384": {}, "PS512": {},
	"EdDSA": {},
}

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

	data, err = hujson.Standardize(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	var cfg Config
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	applyDurationDefault(&cfg.AccessTokenTTL, 15*time.Minute)
	applyDurationDefault(&cfg.IDTokenTTL, 15*time.Minute)
	if cfg.SigningAlgorithm == "" {
		cfg.SigningAlgorithm = DefaultSigningAlgorithm
	}

	if cfg.RequireGroups == nil {
		defaultRequireGroups := true
		cfg.RequireGroups = &defaultRequireGroups
	}
	if override := os.Getenv("EASYOIDC_TEMPLATES_DIR"); override != "" {
		cfg.TemplatesDir = override
	}
	if cfg.Email != nil && cfg.Email.VerificationMode == "" {
		cfg.Email.VerificationMode = "disabled"
	}
	if cfg.Email != nil {
		applyDurationDefault(&cfg.Email.OTPTTL, 5*time.Minute)
	}
	for id, connector := range cfg.Connectors {
		if connector.Generic != nil && connector.Generic.SubjectField == "" {
			connector.Generic.SubjectField = "sub"
			cfg.Connectors[id] = connector
		}
	}
	for id, client := range cfg.Clients {
		applyRefreshDefaults(&client.RefreshTokens)
		cfg.Clients[id] = client
	}

	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

// applyDurationDefault applies a documented default only when the field was omitted.
func applyDurationDefault(value *Duration, fallback time.Duration) {
	if value.Duration() == 0 {
		*value = Duration(fallback)
	}
}

// applyRefreshDefaults fills omitted refresh lifetime fields.
func applyRefreshDefaults(policy *RefreshTokenConfig) {
	applyDurationDefault(&policy.SessionIdleTTL, 30*time.Minute)
	applyDurationDefault(&policy.SessionAbsoluteTTL, 10*time.Hour)
	applyDurationDefault(&policy.OfflineIdleTTL, 30*24*time.Hour)
	applyDurationDefault(&policy.OfflineAbsoluteTTL, 90*24*time.Hour)
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

	if _, ok := supportedSigningAlgorithms[cfg.SigningAlgorithm]; !ok {
		return fmt.Errorf("signing_algorithm must be one of RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512, or EdDSA")
	}

	if err := validateSecretsProvider(cfg.Secrets.Provider); err != nil {
		return fmt.Errorf("secrets.provider: %w", err)
	}

	if cfg.Secrets.SigningKeyName == "" {
		return fmt.Errorf("secrets.signing_key_name is required")
	}

	if cfg.Secrets.Provider == "azure" && cfg.Secrets.AzureKeyVaultURL == "" {
		return fmt.Errorf("secrets.azure_keyvault_url is required for Azure provider")
	}

	if len(cfg.Connectors) == 0 {
		return fmt.Errorf("at least one connector must be configured")
	}
	idPattern := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
	hasEmailConnector := false
	needsEncryption := false
	for id, connector := range cfg.Connectors {
		if !idPattern.MatchString(id) {
			return fmt.Errorf("connector ID %q is not path-safe", id)
		}
		if err := validateConnector(&connector); err != nil {
			return fmt.Errorf("connector %q: %w", id, err)
		}
		if connector.DisplayName == "" {
			return fmt.Errorf("connector %q: display_name is required", id)
		}
		if connector.Type == "email" {
			hasEmailConnector = true
		} else if connector.CredentialsSecret == "" {
			return fmt.Errorf("connector %q: credentials_secret is required", id)
		}
		needsEncryption = needsEncryption || connector.Type == "github"
		for _, client := range cfg.Clients {
			needsEncryption = needsEncryption || (client.RefreshTokens.Enabled && connector.Type != "email")
		}
	}
	if needsEncryption && cfg.Secrets.EncryptionKeyName == "" {
		return fmt.Errorf("secrets.encryption_key_name is required when a refresh-enabled client can use a non-email connector")
	}
	if cfg.Email == nil {
		if hasEmailConnector {
			return fmt.Errorf("email configuration is required when an email connector is configured")
		}
	} else {
		if cfg.Email.VerificationMode != "disabled" && cfg.Email.VerificationMode != "provider" && cfg.Email.VerificationMode != "strict" {
			return fmt.Errorf("email.verification_mode must be disabled, provider, or strict")
		}
		needsEmailDelivery := hasEmailConnector || cfg.Email.VerificationMode == "provider" || cfg.Email.VerificationMode == "strict"
		if needsEmailDelivery && cfg.Email.OTPSecretName == "" {
			return fmt.Errorf("email.otp_secret_name is required when email verification can occur")
		}
		if needsEmailDelivery && cfg.Email.SMTP == nil {
			return fmt.Errorf("complete email.smtp configuration is required")
		}
		otpTTL := cfg.Email.OTPTTL.Duration()
		if needsEmailDelivery && (otpTTL < time.Minute || otpTTL > 10*time.Minute || otpTTL%time.Minute != 0) {
			return fmt.Errorf("email.otp_ttl must be a whole number of minutes from 1m through 10m")
		}
		if cfg.Email.SMTP != nil {
			smtp := cfg.Email.SMTP
			if smtp.Host == "" || smtp.Port < 1 || smtp.Port > 65535 || smtp.FromAddress == "" || smtp.CredentialsSecret == "" {
				return fmt.Errorf("complete email.smtp configuration is required")
			}
			from, err := mail.ParseAddress(smtp.FromAddress)
			if err != nil || from.Address != smtp.FromAddress {
				return fmt.Errorf("email.smtp.from_address must be a bare email address")
			}
			if smtp.TLSMode == "" {
				smtp.TLSMode = "starttls"
			}
			if smtp.TLSMode != "starttls" && smtp.TLSMode != "implicit" && smtp.TLSMode != "plaintext" {
				return fmt.Errorf("email.smtp.tls_mode must be starttls, implicit, or plaintext")
			}
			if smtp.TLSMode == "plaintext" && smtp.Host != "localhost" {
				return fmt.Errorf("email.smtp.tls_mode plaintext is only permitted when host is localhost")
			}
		}
		if cfg.Email.Turnstile != nil && ((cfg.Email.Turnstile.SiteKey == "") != (cfg.Email.Turnstile.SecretName == "")) {
			return fmt.Errorf("email.turnstile site_key and secret_name must be set together")
		}
	}

	if len(cfg.Clients) == 0 {
		return fmt.Errorf("at least one client must be configured")
	}

	for clientID, client := range cfg.Clients {
		if client.RefreshTokens.AllowOfflineAccess && !client.RefreshTokens.Enabled {
			return fmt.Errorf("client %q: refresh_tokens.allow_offline_access requires refresh_tokens.enabled", clientID)
		}
		if client.RefreshTokens.SessionIdleTTL.Duration() > client.RefreshTokens.SessionAbsoluteTTL.Duration() {
			return fmt.Errorf("client %q: refresh_tokens.session_idle_ttl must not exceed session_absolute_ttl", clientID)
		}
		if client.RefreshTokens.OfflineIdleTTL.Duration() > client.RefreshTokens.OfflineAbsoluteTTL.Duration() {
			return fmt.Errorf("client %q: refresh_tokens.offline_idle_ttl must not exceed offline_absolute_ttl", clientID)
		}
		if err := validateClient(clientID, client, cfg.DefaultRedirectURIs, cfg.GroupsOverrides); err != nil {
			return fmt.Errorf("client %q: %w", clientID, err)
		}
	}

	if err := validateGroupsOverrides(cfg.GroupsOverrides); err != nil {
		return fmt.Errorf("groups_overrides: %w", err)
	}
	if err := validateTrust(cfg); err != nil {
		return fmt.Errorf("oidc_trust: %w", err)
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

	if u.Scheme == "http" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1" {
		return fmt.Errorf("http scheme only allowed for localhost in development")
	}

	return nil
}

func validateSecretsProvider(provider string) error {
	valid := map[string]bool{"aws-secrets-manager": true, "aws-parameter-store": true, "google-secret-manager": true, "azure": true, "env": true}
	if !valid[provider] {
		return fmt.Errorf("must be one of: aws-secrets-manager, aws-parameter-store, google-secret-manager, azure, env")
	}
	return nil
}

func validateConnector(c *ConnectorConfig) error {
	if c.Type != "google" && c.Type != "github" && c.Type != "generic" && c.Type != "email" {
		return fmt.Errorf("type must be google, github, generic, or email")
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
		if c.Generic.Refresh != nil {
			owned := map[string]bool{"client_id": true, "redirect_uri": true, "response_type": true, "scope": true, "state": true, "nonce": true, "code_challenge": true, "code_challenge_method": true}
			for key := range c.Generic.Refresh.AuthorizationParams {
				if owned[key] {
					return fmt.Errorf("generic.refresh.authorization_params may not set Easy OIDC-owned parameter %q", key)
				}
				if key == "" {
					return fmt.Errorf("generic.refresh.authorization_params keys must not be empty")
				}
			}
			for _, scope := range c.Generic.Refresh.Scopes {
				if strings.TrimSpace(scope) == "" || strings.ContainsAny(scope, " \t\r\n") {
					return fmt.Errorf("generic.refresh.scopes must contain nonempty individual scope values")
				}
			}
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
		if u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" {
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
