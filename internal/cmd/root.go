// Copyright 2025 Nadrama Pty Ltd
// SPDX-License-Identifier: Apache-2.0

// Package cmd provides the command-line interface for easy-oidc using Cobra.
// It handles command parsing, flag management, and application bootstrapping.
package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/easy-oidc/easy-oidc/internal/buildvars"
	"github.com/easy-oidc/easy-oidc/internal/config"
	"github.com/easy-oidc/easy-oidc/internal/oidc"
	"github.com/easy-oidc/easy-oidc/internal/secrets"
	"github.com/easy-oidc/easy-oidc/internal/storage"
	"github.com/easy-oidc/easy-oidc/internal/tokens"
	"github.com/easy-oidc/easy-oidc/internal/upstream"
	"github.com/spf13/cobra"
)

var (
	debugMode    bool
	showVersion  bool
	validateOnly bool
	configPath   string
)

// NewRootCmd creates and returns the root Cobra command for easy-oidc.
// The command supports flags for debug mode, version display, config validation,
// and custom config file paths.
func NewRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "easy-oidc",
		Short: "Minimal OIDC server for Kubernetes",
		Long: `easy-oidc is a lightweight OIDC server designed for Kubernetes clusters.
It delegates authentication to Google or GitHub and maps users to groups via static configuration.`,
		RunE: run,
	}

	cmd.Flags().BoolVarP(&debugMode, "debug", "v", false, "Enable debug logging")
	cmd.Flags().BoolVar(&showVersion, "version", false, "Show version and exit")
	cmd.Flags().BoolVar(&validateOnly, "validate", false, "Validate configuration and exit")
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config file (default: ./config.jsonc or EASYOIDC_CONFIG_PATH)")

	return cmd
}

func run(cmd *cobra.Command, args []string) error {
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

	ctx := context.Background()

	// set up logger
	logLevel := slog.LevelInfo
	if debugMode {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))
	slog.SetDefault(logger)

	// determine config file path
	configFilePath := configPath
	if configFilePath == "" {
		if envPath := os.Getenv("EASYOIDC_CONFIG_PATH"); envPath != "" {
			configFilePath = envPath
		} else {
			configFilePath = "./config.jsonc"
		}
	}

	// load config
	cfg, err := config.Load(configFilePath)
	if err != nil {
		logger.Error("failed to load configuration", "error", err)
		return fmt.Errorf("configuration error: %w", err)
	}
	if validateOnly {
		logger.Info("configuration is valid")
		return nil
	}

	// set up secrets provider
	secretsProvider, err := secrets.NewProvider(ctx, cfg.Secrets)
	if err != nil {
		logger.Error("failed to create secrets provider", "error", err)
		return err
	}

	// load OIDC token signing key
	var signingKeyPEM string
	if cfg.Secrets.Provider == "env" {
		signingKeyPEM, err = secretsProvider.GetSecret(ctx, "signing_key")
	} else {
		signingKeyPEM, err = secretsProvider.GetSecret(ctx, cfg.Secrets.SigningKeyName)
	}
	if err != nil {
		logger.Error("failed to get signing key", "error", err)
		return err
	}
	keyPair, err := tokens.ParseEd25519PrivateKey(signingKeyPEM)
	if err != nil {
		logger.Error("failed to parse signing key", "error", err)
		return err
	}

	// generate key ID if not provided
	if cfg.JWKSKID == "" {
		cfg.JWKSKID = tokens.GenerateKeyID(keyPair)
		logger.Info("generated jwks_kid from key fingerprint", "kid", cfg.JWKSKID)
	}

	// load upstream oauth connector credentials
	var oauthCredsJSON string
	if cfg.Secrets.Provider == "env" {
		oauthCredsJSON, err = secretsProvider.GetSecret(ctx, "oauth_credentials")
	} else {
		oauthCredsJSON, err = secretsProvider.GetSecret(ctx, cfg.Secrets.ConnectorSecretName)
	}
	if err != nil {
		logger.Error("failed to get OAuth credentials", "error", err)
		return err
	}
	oauthCreds, err := secrets.ParseOAuthCredentials(oauthCredsJSON)
	if err != nil {
		logger.Error("failed to parse OAuth credentials", "error", err)
		return err
	}

	// set up upstream connector
	connector, err := upstream.NewConnector(cfg.Connector, oauthCreds.ClientID, oauthCreds.ClientSecret)
	if err != nil {
		logger.Error("failed to create connector", "error", err)
		return err
	}

	// set up token signer
	tokenTTL := time.Duration(cfg.TokenTTLSeconds) * time.Second
	signer := tokens.NewSigner(keyPair, cfg.JWKSKID, cfg.IssuerURL, tokenTTL)

	// generate JWKS
	jwksData, err := tokens.GenerateJWKS(keyPair, cfg.JWKSKID)
	if err != nil {
		logger.Error("failed to generate JWKS", "error", err)
		return err
	}

	// set up SQLite storage
	// Create data directory if it doesn't exist
	if err := os.MkdirAll(cfg.DataDir, 0755); err != nil {
		logger.Error("failed to create data directory", "error", err, "path", cfg.DataDir)
		return err
	}

	dbPath := filepath.Join(cfg.DataDir, "easy-oidc.db")
	store, err := storage.New(dbPath, logger)
	if err != nil {
		logger.Error("failed to initialize storage", "error", err)
		return err
	}
	defer func() {
		if err := store.Close(); err != nil {
			logger.Error("failed to close storage", "error", err)
		}
	}()

	// set up auth code manager
	authCodeMgr, err := oidc.NewAuthCodeManager(store)
	if err != nil {
		logger.Error("failed to create auth code manager", "error", err)
		return err
	}

	// set up group resolver
	groupResolver := tokens.NewGroupResolver(cfg.GroupsOverrides)

	// run server
	server := oidc.NewServer(cfg, connector, authCodeMgr, signer, groupResolver, jwksData, logger)
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", server.HandleDiscovery)
	mux.HandleFunc("/jwks", server.HandleJWKS)
	mux.HandleFunc("/authorize", server.HandleAuthorize)
	mux.HandleFunc("/token", server.HandleToken)
	mux.HandleFunc("/userinfo", server.HandleUserInfo)
	mux.HandleFunc("/healthz", server.HandleHealth)
	switch cfg.Connector.Type {
	case "google":
		mux.HandleFunc("/callback/google", server.HandleCallback)
	case "github":
		mux.HandleFunc("/callback/github", server.HandleCallback)
	case "generic":
		mux.HandleFunc("/callback/generic", server.HandleCallback)
	}
	httpServer := &http.Server{
		Addr:         cfg.HTTPListenAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// run and trap signals
	logger.Info("starting easy-oidc server",
		"version", buildvars.BuildVersion(),
		"issuer", cfg.IssuerURL,
		"listen_addr", cfg.HTTPListenAddr,
		"connector", cfg.Connector.Type,
	)
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server error", "error", err)
			os.Exit(1)
		}
	}()
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	// handle shutdown
	logger.Info("shutting down server")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("server shutdown error", "error", err)
		return err
	}
	logger.Info("server stopped")
	return nil
}
