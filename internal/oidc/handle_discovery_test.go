// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/easy-oidc/easy-oidc/internal/config"
)

func TestHandleDiscoveryAdvertisesConfiguredSigningAlgorithm(t *testing.T) {
	server := NewServer(
		&config.Config{IssuerURL: "https://auth.example.com", SigningAlgorithm: "PS512"},
		nil, nil, nil, nil, nil, nil,
	)
	response := httptest.NewRecorder()
	server.HandleDiscovery(response, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))

	var discovery struct {
		SigningAlgorithms []string `json:"id_token_signing_alg_values_supported"`
	}
	if err := json.NewDecoder(response.Body).Decode(&discovery); err != nil {
		t.Fatal(err)
	}
	if len(discovery.SigningAlgorithms) != 1 || discovery.SigningAlgorithms[0] != "PS512" {
		t.Fatalf("signing algorithms = %v, want [PS512]", discovery.SigningAlgorithms)
	}
}
