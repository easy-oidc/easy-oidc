// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package templates

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLoadDefaultsAndOverlay verifies embedded defaults and page overlays.
func TestLoadDefaultsAndOverlay(t *testing.T) {
	m, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err = m.RenderPage(&b, "error", ErrorData{"Title", "Message"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "<main>") || !strings.Contains(b.String(), "Message") {
		t.Fatal("layout not applied")
	}
	dir := t.TempDir()
	if err = os.MkdirAll(filepath.Join(dir, "pages"), 0755); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "pages/error.html"), []byte(`{{define "content"}}custom {{.Message}}{{end}}`), 0600); err != nil {
		t.Fatal(err)
	}
	m, err = Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	b.Reset()
	_ = m.RenderPage(&b, "error", ErrorData{"T", "M"})
	if !strings.Contains(b.String(), "custom M") {
		t.Fatal("overlay not used")
	}
}

// TestLoadRejectsInvalidOverlay verifies invalid page overlays fail loading.
func TestLoadRejectsInvalidOverlay(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "pages"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pages/error.html"), []byte(`{{define "content"}}{{.Unknown}}{{end}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("missing key accepted")
	}
}

// TestLoadAppliesPartialEmailOverlays verifies independent email template overlays.
func TestLoadAppliesPartialEmailOverlays(t *testing.T) {
	tests := []struct {
		name, path, body, format, want, fallback string
	}{
		{"HTML layout", "email/layout.html", `{{define "layout"}}<section class="brand">{{template "content" .}}</section>{{end}}`, "html", `class="brand"`, "12345678"},
		{"HTML content", "email/otp.html", `{{define "content"}}<p class="custom">Code: {{.Code}}</p>{{end}}`, "html", `class="custom"`, "<!doctype html>"},
		{"text layout", "email/layout.txt", `{{define "layout"}}BRAND: {{template "content" .}}{{end}}`, "text", "BRAND:", "12345678"},
		{"text content", "email/otp.txt", `{{define "content"}}Custom code: {{.Code}}{{end}}`, "text", "Custom code:", "12345678"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.MkdirAll(filepath.Join(dir, "email"), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, tt.path), []byte(tt.body), 0600); err != nil {
				t.Fatal(err)
			}
			m, err := Load(dir)
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if err = m.RenderEmail(&out, tt.format, OTPEmailData{Code: "12345678", ExpiresAt: time.Date(2026, time.July, 27, 12, 34, 0, 0, time.UTC), ExpiresIn: 5 * time.Minute}); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), tt.want) || !strings.Contains(out.String(), tt.fallback) {
				t.Fatalf("email overlay or fallback missing: %s", out.String())
			}
		})
	}
}

// TestDefaultEmailIncludesExpiry verifies default email templates render the exact expiry.
func TestDefaultEmailIncludesExpiry(t *testing.T) {
	m, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	data := OTPEmailData{Code: "12345678", ExpiresAt: time.Date(2026, time.July, 27, 12, 34, 0, 0, time.UTC), ExpiresIn: 7 * time.Minute}
	for _, format := range []string{"html", "text"} {
		var out bytes.Buffer
		if err = m.RenderEmail(&out, format, data); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "12:34 UTC on 27 July 2026") || !strings.Contains(out.String(), "in 7 minutes") {
			t.Fatalf("%s email omitted expiry: %s", format, out.String())
		}
	}
}

// TestLoadRejectsInvalidEmailOverlay verifies invalid email overlays fail loading.
func TestLoadRejectsInvalidEmailOverlay(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "email"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "email/layout.txt"), []byte(`{{define "layout"}}{{.Missing}}{{end}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("invalid email template accepted")
	}
}
