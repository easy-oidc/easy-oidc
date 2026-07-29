// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/easy-oidc/easy-oidc/internal/config"
	"github.com/easy-oidc/easy-oidc/internal/trust"
	"github.com/spf13/cobra"
)

// newCheckTrustCmd creates the configured external token verifier and trust evaluator command.
func newCheckTrustCmd(configPath *string) *cobra.Command {
	var clientID, tokenFile string
	command := &cobra.Command{Use: "trust", Short: "Verify an external OIDC token against trust policies", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		if clientID == "" || tokenFile == "" {
			return fmt.Errorf("--client-id and --token-file are required")
		}
		cfg, err := config.Load(*configPath)
		if err != nil {
			return err
		}
		var reader io.Reader
		if tokenFile == "-" {
			reader = command.InOrStdin()
		} else {
			file, openErr := os.Open(tokenFile)
			if openErr != nil {
				return fmt.Errorf("open token file: unavailable")
			}
			defer func() { _ = file.Close() }()
			reader = file
		}
		data, err := io.ReadAll(io.LimitReader(reader, trust.MaxJWTBytes+1))
		if err != nil || len(data) > trust.MaxJWTBytes {
			return fmt.Errorf("read token: input exceeds safe limit")
		}
		result, verifyErr := trust.NewService(cfg).VerifyAndEvaluate(command.Context(), strings.TrimSpace(string(data)), clientID)
		if result != nil {
			var report strings.Builder
			fmt.Fprintf(&report, "issuer: %s\nstandard claims: verified\n", result.Issuer)
			for _, diagnostic := range result.Diagnostics {
				status := "no match"
				if diagnostic.Match {
					status = "match"
				}
				fmt.Fprintf(&report, "binding %s: %s", diagnostic.BindingID, status)
				if diagnostic.Reason != "" {
					fmt.Fprintf(&report, " (%s)", diagnostic.Reason)
				}
				report.WriteByte('\n')
			}
			if verifyErr == nil && result.Binding != nil {
				fmt.Fprintf(&report, "subject: %s\ngroups: %s\n", result.Binding.Subject, strings.Join(result.Binding.Groups, ", "))
			}
			if _, err = io.WriteString(command.OutOrStdout(), report.String()); err != nil {
				return fmt.Errorf("write report: %w", err)
			}
		}
		if verifyErr != nil {
			return fmt.Errorf("trust check denied: %w", verifyErr)
		}
		return nil
	}}
	command.Flags().StringVar(&clientID, "client-id", "", "Target Easy OIDC client ID")
	command.Flags().StringVar(&tokenFile, "token-file", "", "External token file, or - for stdin")
	return command
}
