// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package config

// Config represents the top-level configuration structure for easy-oidc.
type Config struct {
	Schema              string                         `json:"$schema,omitempty"`
	IssuerURL           string                         `json:"issuer_url"`
	HTTPListenAddr      string                         `json:"http_listen_addr"`
	DataDir             string                         `json:"data_dir"`
	SigningAlgorithm    string                         `json:"signing_algorithm,omitempty"`
	JWKSKID             string                         `json:"jwks_kid,omitempty"`
	TokenTTLSeconds     int                            `json:"token_ttl_seconds,omitempty"`
	RequireGroups       *bool                          `json:"require_groups,omitempty"`
	Secrets             SecretsConfig                  `json:"secrets"`
	Connectors          map[string]ConnectorConfig     `json:"connectors"`
	TemplatesDir        string                         `json:"templates_dir,omitempty"`
	Email               *EmailConfig                   `json:"email,omitempty"`
	DefaultRedirectURIs []string                       `json:"default_redirect_uris"`
	GroupsOverrides     map[string]map[string][]string `json:"groups_overrides"`
	Clients             map[string]ClientConfig        `json:"clients"`
}

// SecretsConfig defines the secrets provider configuration.
// Supports AWS Secrets Manager, AWS Systems Manager Parameter Store,
// Google Secret Manager, Azure Key Vault, and env-based secrets.
type SecretsConfig struct {
	Provider          string `json:"provider"`
	SigningKeyName    string `json:"signing_key_name"`
	EncryptionKeyName string `json:"encryption_key_name,omitempty"`
	AWSRegion         string `json:"aws_region,omitempty"`
	AzureKeyVaultURL  string `json:"azure_keyvault_url"`
}

// ConnectorConfig defines the upstream OAuth provider configuration.
// Supports Google, GitHub, and generic OAuth2/OIDC providers.
type ConnectorConfig struct {
	Type              string         `json:"type"`
	DisplayName       string         `json:"display_name"`
	Order             int            `json:"order,omitempty"`
	CredentialsSecret string         `json:"credentials_secret,omitempty"`
	Scopes            []string       `json:"scopes"`
	Google            *GoogleConfig  `json:"google,omitempty"`
	GitHub            *GitHubConfig  `json:"github,omitempty"`
	Generic           *GenericConfig `json:"generic,omitempty"`
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
	SubjectField       string `json:"subject_field,omitempty"`
}

// EmailConfig controls optional email verification and direct email authentication.
type EmailConfig struct {
	VerificationMode string           `json:"verification_mode"`
	OTPSecretName    string           `json:"otp_secret_name"`
	OTPTTLSeconds    int              `json:"otp_ttl_seconds,omitempty"`
	SMTP             *SMTPConfig      `json:"smtp,omitempty"`
	Turnstile        *TurnstileConfig `json:"turnstile,omitempty"`
}

// SMTPConfig configures the verification email SMTP transport.
type SMTPConfig struct {
	Host              string `json:"host"`
	Port              int    `json:"port"`
	FromName          string `json:"from_name"`
	FromAddress       string `json:"from_address"`
	CredentialsSecret string `json:"credentials_secret"`
	TLSMode           string `json:"tls_mode,omitempty"`
}

// TurnstileConfig configures Cloudflare Turnstile verification.
type TurnstileConfig struct {
	SiteKey    string `json:"site_key"`
	SecretName string `json:"secret_name"`
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
