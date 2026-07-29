// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	"github.com/easy-oidc/easy-oidc/internal/config"
	"github.com/spf13/cobra"
)

// newCheckConfigCmd constructs the configuration validation command.
func newCheckConfigCmd(configPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "config",
		Short: "Validate configuration",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := config.Load(*configPath); err != nil {
				return fmt.Errorf("configuration error: %w", err)
			}
			_, err := fmt.Fprintln(cmd.OutOrStdout(), "configuration is valid")
			return err
		},
	}
}
