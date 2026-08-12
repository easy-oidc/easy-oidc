// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// newCheckCmd constructs the configuration, template, and trust checking command group.
func newCheckCmd() *cobra.Command {
	configPath := os.Getenv("TRUSTER_CONFIG_PATH")
	if configPath == "" {
		configPath = "./config.jsonc"
	}
	command := &cobra.Command{Use: "check", Short: "Check configuration, templates, or external OIDC trust"}
	command.PersistentFlags().StringVar(&configPath, "config", configPath, "Path to config file")
	command.AddCommand(newCheckConfigCmd(&configPath), newCheckTemplatesCmd(&configPath), newCheckTrustCmd(&configPath))
	return command
}
