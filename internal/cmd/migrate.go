// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	"github.com/easy-oidc/easy-oidc/internal/config"
	"github.com/easy-oidc/easy-oidc/internal/secrets"
	"github.com/easy-oidc/easy-oidc/internal/statedb"
	"github.com/spf13/cobra"
)

// newMigrateCmd creates the explicit state-schema migration command.
func newMigrateCmd(configPath *string) *cobra.Command {
	command := &cobra.Command{Use: "migrate", Short: "Apply state database migrations", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		cfg, err := config.Load(*configPath)
		if err != nil {
			return fmt.Errorf("configuration error: %w", err)
		}
		if cfg.StateDatabase.Driver != "postgresql" {
			return fmt.Errorf("state database migrations are not required for sqlite")
		}
		provider, err := secrets.NewProvider(command.Context(), cfg.Secrets)
		if err != nil {
			return fmt.Errorf("create secrets provider: %w", err)
		}
		secretName := ""
		if cfg.StateDatabase.Migrations != nil {
			secretName = cfg.StateDatabase.Migrations.ConnectionStringSecret
		}
		if secretName == "" {
			secretName = cfg.StateDatabase.ConnectionStringSecret
		}
		connectionString, err := provider.GetSecret(command.Context(), secretName)
		if err != nil {
			return fmt.Errorf("load state database migration connection string: %w", err)
		}
		return statedb.MigratePostgreSQL(connectionString)
	}}
	command.Flags().StringVar(configPath, "config", *configPath, "Path to config file")
	return command
}
