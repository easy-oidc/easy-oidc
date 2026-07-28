// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"os"

	"github.com/easy-oidc/easy-oidc/internal/dev"
	"github.com/spf13/cobra"
)

// newDevCmd constructs the template development command.
func newDevCmd() *cobra.Command {
	templatesDir := os.Getenv("EASYOIDC_TEMPLATES_DIR")
	if templatesDir == "" {
		templatesDir = "./templates"
	}
	listenAddr := "127.0.0.1:0"
	cmd := &cobra.Command{
		Use:   "dev",
		Short: "Develop templates with mock data and live reload",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return dev.Run(cmd.Context(), cmd.InOrStdin(), cmd.OutOrStdout(), templatesDir, listenAddr)
		},
	}
	cmd.Flags().StringVar(&templatesDir, "templates-dir", templatesDir, "Template overlay directory")
	cmd.Flags().StringVar(&listenAddr, "listen", listenAddr, "Development server listen address")
	return cmd
}
