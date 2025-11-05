// Copyright 2025 Nadrama Pty Ltd
// SPDX-License-Identifier: Apache-2.0

// Package tokens provides functionality for signing tokens and managing groups.
package tokens

import (
	"sort"
)

// GroupResolver resolves user groups based on email and group override configurations.
type GroupResolver struct {
	groupsOverrides map[string]map[string][]string
}

// NewGroupResolver creates a new group resolver with the provided group override mappings.
func NewGroupResolver(groupsOverrides map[string]map[string][]string) *GroupResolver {
	return &GroupResolver{
		groupsOverrides: groupsOverrides,
	}
}

// ResolveGroups returns the groups for a user based on their email and the client's group override.
// The email is normalized to lowercase before lookup. Groups are deduplicated and sorted.
func (r *GroupResolver) ResolveGroups(clientGroupsOverride, email string) []string {
	normalizedEmail := NormalizeEmail(email)

	if clientGroupsOverride == "" {
		return []string{}
	}

	override, exists := r.groupsOverrides[clientGroupsOverride]
	if !exists {
		return []string{}
	}

	groups, exists := override[normalizedEmail]
	if !exists {
		return []string{}
	}

	deduped := deduplicate(groups)
	sort.Strings(deduped)
	return deduped
}

func deduplicate(items []string) []string {
	seen := make(map[string]bool)
	result := []string{}

	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}
