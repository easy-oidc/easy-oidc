// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package dev

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTemplateServerUsesMockDataWithoutTurnstile verifies safe preview data.
func TestTemplateServerUsesMockDataWithoutTurnstile(t *testing.T) {
	server := newTemplateServer(t.TempDir())
	response := httptest.NewRecorder()
	server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	body := response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(body, `href="/pages/selector.html"`) || !strings.Contains(body, `href="/pages/identity.html"`) || !strings.Contains(body, `href="/email/otp.txt"`) {
		t.Fatalf("unexpected preview index: %d %s", response.Code, body)
	}
	response = httptest.NewRecorder()
	server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/pages/selector.html", nil))
	body = response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(body, "Google") || !strings.Contains(body, `action="/email/start"`) {
		t.Fatalf("unexpected selector preview: %d %s", response.Code, body)
	}
	if strings.Contains(body, "cf-turnstile") || !strings.Contains(body, "/__truster_dev/revision") {
		t.Fatalf("selector preview included Turnstile or omitted live reload: %s", body)
	}
	response = httptest.NewRecorder()
	server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/pages/identity.html", nil))
	body = response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(body, "primary@example.com") || !strings.Contains(body, "Unverified") {
		t.Fatalf("unexpected identity selection preview: %d %s", response.Code, body)
	}
}

// TestTemplateServerReloadsAndDisplaysErrors verifies live reload and parse errors.
func TestTemplateServerReloadsAndDisplaysErrors(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "pages"), 0755); err != nil {
		t.Fatal(err)
	}
	server := newTemplateServer(dir)
	path := filepath.Join(dir, "pages/error.html")
	if err := os.WriteFile(path, []byte(`{{define "content"}}custom {{.Message}}{{end}}`), 0600); err != nil {
		t.Fatal(err)
	}
	server.reload(false)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/pages/error.html", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "custom This is a mock error message.") {
		t.Fatalf("overlay was not reloaded: %d %s", response.Code, response.Body.String())
	}
	if err := os.WriteFile(path, []byte(`{{define "content"}}{{.Missing}}{{end}}`), 0600); err != nil {
		t.Fatal(err)
	}
	server.reload(false)
	response = httptest.NewRecorder()
	server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/pages/error.html", nil))
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "Template error") {
		t.Fatalf("template error was not displayed: %d %s", response.Code, response.Body.String())
	}
}

// TestHandleInputOpensForLowerAndUppercaseO verifies both open shortcuts.
func TestHandleInputOpensForLowerAndUppercaseO(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	opened := make([]string, 0, 2)
	handleInput(ctx, cancel, bytes.NewBufferString("xOo"), io.Discard, "http://127.0.0.1:1234/", func(url string) error {
		opened = append(opened, url)
		return nil
	})
	if len(opened) != 2 || opened[0] != "http://127.0.0.1:1234/" || opened[1] != opened[0] {
		t.Fatalf("browser opens = %v", opened)
	}
}
