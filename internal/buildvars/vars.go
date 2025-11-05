// Copyright 2025 Nadrama Pty Ltd
// SPDX-License-Identifier: Apache-2.0

package buildvars

var (
	buildVersion = "dev"
	buildDate    = "unknown"
	commitHash   = "unknown"
	commitDate   = "unknown"
	commitBranch = "unknown"
)

func BuildVersion() string {
	return buildVersion
}

func BuildDate() string {
	return buildDate
}

func CommitHash() string {
	return commitHash
}

func CommitDate() string {
	return commitDate
}

func CommitBranch() string {
	return commitBranch
}
