// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/tailscale/hujson"
)

const configSchemaID = "https://easy-oidc.dev/schema/v2/config.schema.json"

// TestExampleConfigs validates every example against both the v2 JSON Schema
// and the application's authoritative configuration loader.
func TestExampleConfigs(t *testing.T) {
	compiledSchema := compileConfigSchema(t)

	examples, err := filepath.Glob(filepath.Join("..", "..", "examples", "config", "*.jsonc"))
	if err != nil {
		t.Fatalf("find example configurations: %v", err)
	}
	if len(examples) == 0 {
		t.Fatal("no example configurations found")
	}

	t.Setenv("EASYOIDC_TEMPLATES_DIR", "")
	for _, examplePath := range examples {
		t.Run(filepath.Base(examplePath), func(t *testing.T) {
			data, readErr := os.ReadFile(examplePath)
			if readErr != nil {
				t.Fatalf("read example: %v", readErr)
			}
			instance := parseJSONCInstance(t, data)
			if validateErr := compiledSchema.Validate(instance); validateErr != nil {
				t.Errorf("schema validation failed: %v", validateErr)
			}
			if _, loadErr := Load(examplePath); loadErr != nil {
				t.Errorf("application validation failed: %v", loadErr)
			}
		})
	}
}

// TestConfigSchemaContracts verifies conditional and cross-field constraints
// that cannot be demonstrated by valid examples alone.
func TestConfigSchemaContracts(t *testing.T) {
	compiledSchema := compileConfigSchema(t)
	base := map[string]any{
		"issuer_url":       "https://auth.example.com",
		"http_listen_addr": "127.0.0.1:8080",
		"data_dir":         "/var/lib/easy-oidc",
		"secrets": map[string]any{
			"provider":         "env",
			"signing_key_name": "EASYOIDC_SIGNING_KEY",
		},
		"connectors": map[string]any{
			"google": map[string]any{
				"type":               "google",
				"display_name":       "Google",
				"credentials_secret": "EASYOIDC_GOOGLE_CREDENTIALS",
			},
		},
		"default_redirect_uris": []any{"http://localhost:8000"},
		"clients": map[string]any{
			"kubelogin": map[string]any{},
		},
	}
	addGitHub := func(cfg map[string]any) {
		cfg["connectors"].(map[string]any)["github"] = map[string]any{
			"type":               "github",
			"display_name":       "GitHub",
			"credentials_secret": "EASYOIDC_GITHUB_CREDENTIALS",
		}
	}
	addEmail := func(cfg map[string]any) {
		cfg["connectors"].(map[string]any)["email"] = map[string]any{
			"type":         "email",
			"display_name": "Email code",
		}
		cfg["email"] = map[string]any{
			"verification_mode": "disabled",
			"otp_secret_name":   "EASYOIDC_OTP_SECRET",
			"smtp": map[string]any{
				"host":               "smtp.example.com",
				"port":               json.Number("587"),
				"from_address":       "auth@example.com",
				"credentials_secret": "EASYOIDC_SMTP_CREDENTIALS",
			},
		}
	}

	tests := []struct {
		name   string
		valid  bool
		mutate func(map[string]any)
	}{
		{"base configuration", true, func(map[string]any) {}},
		{"mixed connectors require encryption", false, addGitHub},
		{"GitHub with encryption", true, func(cfg map[string]any) {
			addGitHub(cfg)
			cfg["secrets"].(map[string]any)["encryption_key_name"] = "EASYOIDC_ENCRYPTION_KEY"
		}},
		{"email connector requires email configuration", false, func(cfg map[string]any) {
			cfg["connectors"].(map[string]any)["email"] = map[string]any{
				"type":         "email",
				"display_name": "Email code",
			}
		}},
		{"email connector with delivery configuration", true, addEmail},
		{"provider verification requires delivery configuration", false, func(cfg map[string]any) {
			cfg["email"] = map[string]any{"verification_mode": "provider"}
		}},
		{"client requires effective redirect URI", false, func(cfg map[string]any) {
			delete(cfg, "default_redirect_uris")
		}},
		{"client redirect URI can replace defaults", true, func(cfg map[string]any) {
			delete(cfg, "default_redirect_uris")
			cfg["clients"].(map[string]any)["kubelogin"] = map[string]any{
				"redirect_uris": []any{"https://app.example.com/callback"},
			}
		}},
		{"external HTTP issuer", false, func(cfg map[string]any) {
			cfg["issuer_url"] = "http://auth.example.com"
		}},
		{"unsupported redirect URI scheme", false, func(cfg map[string]any) {
			cfg["default_redirect_uris"] = []any{"ftp://app.example.com/callback"}
		}},
		{"display name is not a bare sender address", false, func(cfg map[string]any) {
			addEmail(cfg)
			cfg["email"].(map[string]any)["smtp"].(map[string]any)["from_address"] = "Easy OIDC <auth@example.com>"
		}},
		{"group mapping requires a dotted email domain", false, func(cfg map[string]any) {
			cfg["groups_overrides"] = map[string]any{
				"groups": map[string]any{"alice@localhost": []any{"developers"}},
			}
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			instance := cloneJSONValue(t, base).(map[string]any)
			test.mutate(instance)
			err := compiledSchema.Validate(instance)
			if (err == nil) != test.valid {
				t.Fatalf("validation error = %v, want valid = %v", err, test.valid)
			}
		})
	}
}

// compileConfigSchema compiles the repository's v2 configuration schema.
func compileConfigSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	schemaPath := filepath.Join("..", "..", "schema", "v2", "config.schema.json")
	schemaFile, err := os.Open(schemaPath)
	if err != nil {
		t.Fatalf("open schema: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := schemaFile.Close(); closeErr != nil {
			t.Errorf("close schema: %v", closeErr)
		}
	})

	schemaDocument, err := jsonschema.UnmarshalJSON(schemaFile)
	if err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err := compiler.AddResource(configSchemaID, schemaDocument); err != nil {
		t.Fatalf("add schema: %v", err)
	}
	compiledSchema, err := compiler.Compile(configSchemaID)
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	return compiledSchema
}

// parseJSONCInstance parses a JSONC document into a schema-validation value.
func parseJSONCInstance(t *testing.T, data []byte) any {
	t.Helper()
	standardJSON, err := hujson.Standardize(data)
	if err != nil {
		t.Fatalf("standardize JSONC: %v", err)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(standardJSON))
	if err != nil {
		t.Fatalf("parse JSONC: %v", err)
	}
	return instance
}

// cloneJSONValue returns an independent JSON-compatible copy of a value.
func cloneJSONValue(t *testing.T, value any) any {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal JSON value: %v", err)
	}
	return parseJSONCInstance(t, data)
}
