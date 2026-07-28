// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"

	"github.com/easy-oidc/easy-oidc/internal/config"
	"github.com/spf13/cobra"
)

// newValidateCmd constructs the configuration validation command.
func newValidateCmd() *cobra.Command {
	configPath := os.Getenv("EASYOIDC_CONFIG_PATH")
	if configPath == "" {
		configPath = "./config.jsonc"
	}
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate configuration and templates",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := config.Load(configPath); err != nil {
				return fmt.Errorf("configuration error: %w", err)
			}
			_, err := fmt.Fprintln(cmd.OutOrStdout(), "configuration and templates are valid")
			return err
		},
	}
	cmd.Flags().StringVar(&configPath, "config", configPath, "Path to config file")
	return cmd
}
