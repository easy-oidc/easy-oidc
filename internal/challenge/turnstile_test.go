// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package challenge

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

// roundTripFunc adapts a function into an HTTP transport.
type roundTripFunc func(*http.Request) (*http.Response, error)

// RoundTrip invokes the adapted transport function.
func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

// TestTurnstileFailsClosed verifies rejected and missing challenges fail.
func TestTurnstileFailsClosed(t *testing.T) {
	verifier := Turnstile{Secret: "secret", Client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(request.Body)
		if !strings.Contains(string(body), "secret=secret") || !strings.Contains(string(body), "response=response") {
			t.Fatalf("unexpected request body: %s", body)
		}
		responseBody := fmt.Sprintf("{%q:%t}", "success", false)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(responseBody))}, nil
	})}}
	if err := verifier.Verify(context.Background(), "response", ""); err == nil {
		t.Fatal("failed Turnstile response accepted")
	}
	if err := verifier.Verify(context.Background(), "", ""); err == nil {
		t.Fatal("missing Turnstile response accepted")
	}
}
