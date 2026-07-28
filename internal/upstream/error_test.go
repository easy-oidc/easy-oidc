// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package upstream

import (
	"errors"
	"net/http"
	"testing"

	"golang.org/x/oauth2"
)

// TestClassifyInvalidClientDistinguishesConfiguration verifies invalid_client is not token denial.
func TestClassifyInvalidClientDistinguishesConfiguration(t *testing.T) {
	err := ClassifyError("refresh", &oauth2.RetrieveError{ErrorCode: "invalid_client"})
	kind, _ := ErrorInfo(err)
	if kind != ErrorConfiguration {
		t.Fatalf("kind = %q", kind)
	}
	if !errors.As(err, new(*ConnectorError)) {
		t.Fatalf("error was not typed: %v", err)
	}
}

// TestGitHubForbiddenRateLimit recognizes GitHub's non-429 rate-limit response.
func TestGitHubForbiddenRateLimit(t *testing.T) {
	response := &http.Response{StatusCode: http.StatusForbidden, Header: http.Header{"X-Ratelimit-Remaining": []string{"0"}}}
	kind, _ := ErrorInfo(classifyGitHubStatus("user", response))
	if kind != ErrorRateLimit {
		t.Fatalf("kind = %q", kind)
	}
}

// TestClassifyHTTPStatusDefaultsToTemporary verifies ambiguous provider responses preserve grants.
func TestClassifyHTTPStatusDefaultsToTemporary(t *testing.T) {
	for _, status := range []int{http.StatusRequestTimeout, http.StatusNotFound, http.StatusInternalServerError} {
		kind, _ := ErrorInfo(ClassifyHTTPStatus("userinfo", status, ""))
		if kind != ErrorTemporary {
			t.Fatalf("status %d kind = %s, want %s", status, kind, ErrorTemporary)
		}
	}
}
