// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package exampleconfig

import _ "embed"

//go:embed config-email-dev.jsonc
var emailDemoConfig string

// EmailDemo returns the embedded local email demonstration configuration.
func EmailDemo() string {
	return emailDemoConfig
}
