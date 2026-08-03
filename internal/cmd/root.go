// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/easy-oidc/easy-oidc/internal/authpolicy"
	"github.com/easy-oidc/easy-oidc/internal/buildvars"
	"github.com/easy-oidc/easy-oidc/internal/challenge"
	"github.com/easy-oidc/easy-oidc/internal/config"
	"github.com/easy-oidc/easy-oidc/internal/email"
	"github.com/easy-oidc/easy-oidc/internal/oidc"
	"github.com/easy-oidc/easy-oidc/internal/secrets"
	"github.com/easy-oidc/easy-oidc/internal/statedb"
	"github.com/easy-oidc/easy-oidc/internal/templates"
	"github.com/easy-oidc/easy-oidc/internal/tokens"
	"github.com/easy-oidc/easy-oidc/internal/upstream"
	"github.com/spf13/cobra"
)

// NewRootCmd creates and returns the root Cobra command for easy-oidc.
func NewRootCmd() *cobra.Command {
	var debugMode bool
	var showVersion bool

	// Determine the config file path before binding it as the flag default.
	configPath := os.Getenv("EASYOIDC_CONFIG_PATH")
	if configPath == "" {
		configPath = "./config.jsonc"
	}
	cmd := &cobra.Command{
		Use:   "easy-oidc",
		Short: "Minimal OIDC server for Kubernetes",
		Long: `easy-oidc is a lightweight OIDC server designed for Kubernetes clusters.
It delegates authentication to upstream identity providers and maps users to groups via static configuration.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if showVersion {
				fmt.Printf("easy-oidc version %s\n", buildvars.BuildVersion())
				if debugMode {
					fmt.Printf("  Build date:   %s\n", buildvars.BuildDate())
					fmt.Printf("  Commit:       %s\n", buildvars.CommitHash())
					fmt.Printf("  Commit date:  %s\n", buildvars.CommitDate())
					fmt.Printf("  Branch:       %s\n", buildvars.CommitBranch())
				}
				return nil
			}
			return run(cmd.Context(), cmd.OutOrStdout(), configPath, debugMode)
		},
	}

	cmd.Flags().BoolVarP(&debugMode, "debug", "v", false, "Enable debug logging")
	cmd.Flags().BoolVar(&showVersion, "version", false, "Show version and exit")
	cmd.Flags().StringVar(&configPath, "config", configPath, "Path to config file")
	cmd.AddCommand(newCheckCmd(), newDevCmd(), newMigrateCmd(&configPath))
	return cmd
}

// run assembles and serves Easy OIDC until cancellation or an interrupt.
func run(ctx context.Context, output io.Writer, configPath string, debug bool) error {
	// Set up structured logging.
	logLevel := slog.LevelInfo
	if debug {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(output, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	// Load the configuration and precompile all effective templates.
	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Error("failed to load configuration", "error", err)
		return fmt.Errorf("configuration error: %w", err)
	}
	templateManager, err := templates.Load(cfg.TemplatesDir)
	if err != nil {
		return fmt.Errorf("load templates: %w", err)
	}

	// Set up the configured secrets provider.
	secretsProvider, err := secrets.NewProvider(ctx, cfg.Secrets)
	if err != nil {
		logger.Error("failed to create secrets provider", "error", err)
		return err
	}

	// Set up the optional policy database.
	var policyDatabase *authpolicy.PostgreSQL
	if cfg.PolicyDatabase != nil {
		connectionString, getErr := secretsProvider.GetSecret(ctx, cfg.PolicyDatabase.ConnectionStringSecret)
		if getErr != nil {
			return fmt.Errorf("load policy database connection string")
		}
		startupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		policyDatabase, err = authpolicy.NewPostgreSQL(startupCtx, connectionString, *cfg.PolicyDatabase, cfg.OIDCTrust.Issuers, logger)
		cancel()
		if err != nil {
			return fmt.Errorf("initialize policy database: %w", err)
		}
		defer policyDatabase.Close()
	}
	policyResolver := authpolicy.NewResolver(cfg, policyDatabase)

	// Load the downstream OIDC token signing key.
	signingKeyPEM, err := secretsProvider.GetSecret(ctx, cfg.Secrets.SigningKeyName)
	if err != nil {
		logger.Error("failed to get signing key", "error", err)
		return err
	}
	signingKey, err := tokens.ParsePrivateKey(signingKeyPEM, cfg.SigningAlgorithm)
	if err != nil {
		logger.Error("failed to parse signing key", "error", err)
		return err
	}

	// Generate the key ID from the signing key when it is not configured.
	if cfg.JWKSKID == "" {
		cfg.JWKSKID, err = tokens.GenerateKeyID(signingKey)
		if err != nil {
			logger.Error("failed to generate signing key ID", "error", err)
			return err
		}
		logger.Info("generated jwks_kid from key fingerprint", "kid", cfg.JWKSKID)
	}

	// Load credentials and initialize every configured upstream connector.
	connectors := make(map[string]upstream.Connector)
	for id, connectorConfig := range cfg.Connectors {
		if connectorConfig.Type == "email" {
			continue
		}
		raw, getErr := secretsProvider.GetSecret(ctx, connectorConfig.CredentialsSecret)
		if getErr != nil {
			return getErr
		}
		credentials, parseErr := secrets.ParseOAuthCredentials(raw)
		if parseErr != nil {
			return parseErr
		}
		connector, newErr := upstream.NewConnector(connectorConfig, cfg.IssuerURL+"/callback/"+id, credentials.ClientID, credentials.ClientSecret)
		if newErr != nil {
			return newErr
		}
		connectors[id] = connector
	}

	// Derive the identity-selection key from the generic encryption master key.
	var selectionKey, encryptionKey []byte
	if cfg.Secrets.EncryptionKeyName != "" {
		rawEncryptionKey, getErr := secretsProvider.GetSecret(ctx, cfg.Secrets.EncryptionKeyName)
		if getErr != nil {
			return fmt.Errorf("get encryption key: %w", getErr)
		}
		var decodeErr error
		encryptionKey, decodeErr = hex.DecodeString(rawEncryptionKey)
		if decodeErr != nil || len(encryptionKey) != 32 {
			return fmt.Errorf("encryption key must be a 64-character hex-encoded 32-byte key (generate with: openssl rand -hex 32)")
		}
		selectionKey, err = hkdf.Key(sha256.New, encryptionKey, nil, "easy-oidc/identity-selection/v1", 32)
		if err != nil {
			return fmt.Errorf("derive identity selection key: %w", err)
		}
	}

	// Configure email delivery, OTP verification, and optional bot protection.
	var mailer email.Sender
	var challengeVerifier challenge.Verifier = challenge.Noop{}
	var otpSecret []byte
	if cfg.Email != nil {
		hasEmailConnector := false
		for _, connectorConfig := range cfg.Connectors {
			if connectorConfig.Type == "email" {
				hasEmailConnector = true
				break
			}
		}
		needsEmailDelivery := hasEmailConnector || cfg.Email.VerificationMode == "provider" || cfg.Email.VerificationMode == "strict"
		if needsEmailDelivery {
			rawOTP, getErr := secretsProvider.GetSecret(ctx, cfg.Email.OTPSecretName)
			if getErr != nil {
				return getErr
			}
			otpSecret = []byte(rawOTP)
			if len(otpSecret) < 32 {
				return fmt.Errorf("OTP HMAC secret must be at least 32 bytes")
			}
		}
		if cfg.Email.SMTP != nil {
			if cfg.Email.SMTP.TLSMode == "plaintext" {
				logger.Warn("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
				logger.Warn("SECURITY WARNING: SMTP TLS IS DISABLED; SMTP CREDENTIALS, EMAIL ADDRESSES, AND ONE-TIME CODES MAY BE TRANSMITTED IN PLAINTEXT")
				logger.Warn("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
			}
			rawSMTP, getErr := secretsProvider.GetSecret(ctx, cfg.Email.SMTP.CredentialsSecret)
			if getErr != nil {
				return getErr
			}
			smtpCredentials, parseErr := email.ParseCredentials(rawSMTP)
			if parseErr != nil {
				return parseErr
			}
			if needsEmailDelivery {
				smtpMailer := email.NewSMTPMailer(*cfg.Email.SMTP, smtpCredentials)
				mailer = email.NewOTPMailer(smtpMailer, templateManager, cfg.Email.OTPTTL.Duration())
			}
		}
		if cfg.Email.Turnstile != nil && cfg.Email.Turnstile.SecretName != "" {
			raw, getErr := secretsProvider.GetSecret(ctx, cfg.Email.Turnstile.SecretName)
			if getErr != nil {
				return getErr
			}
			challengeVerifier = challenge.Turnstile{Secret: raw}
		} else if hasEmailConnector {
			logger.Warn("email authentication configured without Turnstile bot protection")
		}
	}

	// Set up the downstream token signer and public JWKS document.
	signer := tokens.NewSigner(signingKey, cfg.JWKSKID, cfg.IssuerURL, cfg.IDTokenTTL.Duration())
	jwksData, err := tokens.GenerateJWKS(signingKey, cfg.JWKSKID)
	if err != nil {
		logger.Error("failed to generate JWKS", "error", err)
		return err
	}

	// Set up authoritative protocol state storage.
	var store *statedb.Store
	if cfg.StateDatabase.Driver == "postgresql" {
		connectionString, getErr := secretsProvider.GetSecret(ctx, cfg.StateDatabase.ConnectionStringSecret)
		if getErr != nil {
			return fmt.Errorf("load state database connection string: %w", getErr)
		}
		store, err = statedb.NewPostgreSQL(ctx, connectionString, cfg.StateDatabase.MaxConnections, cfg.StateDatabase.QueryTimeout.Duration(), logger)
	} else {
		directory := filepath.Dir(cfg.StateDatabase.Path)
		if err = os.MkdirAll(directory, 0755); err != nil {
			logger.Error("failed to create state database directory", "error", err, "path", directory)
			return err
		}
		store, err = statedb.NewSQLite(cfg.StateDatabase.Path, logger)
	}
	if err != nil {
		logger.Error("failed to initialize storage", "error", err)
		return err
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			logger.Error("failed to close storage", "error", closeErr)
		}
	}()

	// Set up the authorization code manager.
	authCodeManager, err := oidc.NewAuthCodeManager(store)
	if err != nil {
		logger.Error("failed to create auth code manager", "error", err)
		return err
	}

	// Set up the OIDC server and HTTP routes.
	server := oidc.NewServer(cfg, connectors, authCodeManager, signer, jwksData, logger, store, templateManager, mailer, challengeVerifier, otpSecret, selectionKey, encryptionKey, policyResolver)
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", server.HandleDiscovery)
	mux.HandleFunc("/jwks", server.HandleJWKS)
	mux.HandleFunc("/authorize", server.HandleAuthorize)
	mux.HandleFunc("/token", server.HandleToken)
	mux.HandleFunc("/revoke", server.HandleRevoke)
	mux.HandleFunc("GET /grants", server.HandleGrants)
	mux.HandleFunc("POST /grants/revoke", server.HandleGrantRevoke)
	mux.HandleFunc("POST /consent", server.HandleConsent)
	mux.HandleFunc("/userinfo", server.HandleUserInfo)
	mux.HandleFunc("/healthz", server.HandleHealth)
	mux.HandleFunc("/callback/", server.HandleCallback)
	mux.HandleFunc("POST /identity/select", server.HandleIdentitySelect)
	mux.HandleFunc("GET /select/{connector}", server.HandleSelect)
	mux.HandleFunc("POST /email/start", server.HandleEmailStart)
	mux.HandleFunc("POST /email/verify", server.HandleEmailVerify)
	mux.HandleFunc("POST /email/resend", server.HandleEmailResend)
	httpServer := &http.Server{Addr: cfg.HTTPListenAddr, Handler: mux, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}

	// Run the server and wait for either a server error or a shutdown signal.
	logger.Info("starting easy-oidc server", "version", buildvars.BuildVersion(), "issuer", cfg.IssuerURL, "listen_addr", cfg.HTTPListenAddr, "connectors", len(cfg.Connectors))
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- httpServer.ListenAndServe()
	}()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case err = <-serverErrors:
		if err != http.ErrServerClosed {
			return fmt.Errorf("serve HTTP: %w", err)
		}
		return nil
	case <-ctx.Done():
	}

	// Gracefully shut down active HTTP requests.
	logger.Info("shutting down server")
	shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err = httpServer.Shutdown(shutdownContext); err != nil {
		logger.Error("server shutdown error", "error", err)
		return err
	}
	logger.Info("server stopped")
	return nil
}
