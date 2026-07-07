// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"

	"github.com/easy-oidc/easy-oidc/internal/cmd"
)

func main() {
	if err := cmd.NewRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
