// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package authpolicy

import (
	"sort"
	"strings"

	"github.com/easy-oidc/easy-oidc/internal/config"
)

// resolveStaticUser returns effective user groups from static configuration.
func resolveStaticUser(cfg *config.Config, policy config.ClientConfig, subject string) (ResolvedUser, error) {
	groups := resolveStaticGroups(cfg.GroupsOverrides, policy.GroupsOverride, subject)
	if policy.ShouldRequireGroups(cfg.RequireGroups) && len(groups) == 0 {
		return ResolvedUser{}, ErrDenied
	}
	return ResolvedUser{Groups: groups}, nil
}

// resolveStaticTrust returns effective static trust bindings for an issuer.
func resolveStaticTrust(policy config.ClientConfig, issuerID string) []config.EffectiveTrustBinding {
	bindings := make([]config.EffectiveTrustBinding, 0, len(policy.TrustBindings))
	for _, binding := range policy.TrustBindings {
		if binding.Effective != nil && binding.Effective.Issuer == issuerID {
			bindings = append(bindings, *binding.Effective)
		}
	}
	return bindings
}

// resolveStaticGroups resolves normalized, deduplicated, and sorted static groups.
func resolveStaticGroups(overrides map[string]map[string][]string, overrideID, subject string) []string {
	if overrideID == "" {
		return []string{}
	}
	groups := overrides[overrideID][strings.ToLower(strings.TrimSpace(subject))]
	seen := make(map[string]bool, len(groups))
	resolved := make([]string, 0, len(groups))
	for _, group := range groups {
		if !seen[group] {
			seen[group] = true
			resolved = append(resolved, group)
		}
	}
	sort.Strings(resolved)
	return resolved
}
