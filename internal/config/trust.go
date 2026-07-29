// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

const maxTrustBindings = 100

var trustNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`)

// denySchemaLoader prevents all external schema retrieval.
type denySchemaLoader struct{}

// Load always rejects external schema retrieval.
func (denySchemaLoader) Load(location string) (any, error) {
	return nil, fmt.Errorf("external schema %q is disabled", location)
}

// OIDCTrustConfig separates trusted issuers from reusable policies.
type OIDCTrustConfig struct {
	Issuers  map[string]TrustIssuerConfig `json:"issuers,omitempty"`
	Policies map[string]TrustPolicyConfig `json:"policies,omitempty"`
}

// TrustIssuerConfig configures external OIDC verification.
type TrustIssuerConfig struct {
	Provider    string   `json:"provider"`
	IssuerURL   string   `json:"issuer_url,omitempty"`
	SigningAlgs []string `json:"signing_algs,omitempty"`
	MaxTokenAge Duration `json:"max_token_age,omitempty"`
}

// TrustPolicyConfig defines reusable claim restrictions and identity output.
type TrustPolicyConfig struct {
	Issuer         string                     `json:"issuer"`
	Subject        string                     `json:"subject,omitempty"`
	Groups         []string                   `json:"groups,omitempty"`
	RequiredClaims map[string]json.RawMessage `json:"required_claims,omitempty"`
	Claims         map[string]json.RawMessage `json:"claims,omitempty"`
}

// TrustBindingConfig authorizes one policy for a downstream client.
type TrustBindingConfig struct {
	ID          string                     `json:"id"`
	TrustPolicy string                     `json:"trust_policy"`
	Subject     *string                    `json:"subject,omitempty"`
	Groups      []string                   `json:"groups,omitempty"`
	Claims      map[string]json.RawMessage `json:"claims,omitempty"`
	Effective   *EffectiveTrustBinding     `json:"-"`
}

// EffectiveTrustBinding is an immutable startup-compiled authorization rule.
type EffectiveTrustBinding struct {
	ID, Policy, Issuer, Subject string
	Groups                      []string
	Schema                      *jsonschema.Schema
}

var presetClaims = map[string]map[string]bool{
	"github":    {"actor": true, "actor_id": true, "base_ref": true, "check_run_id": true, "enterprise": true, "enterprise_id": true, "environment": true, "environment_node_id": true, "event_name": true, "head_ref": true, "issuer_scope": true, "job_workflow_ref": true, "job_workflow_sha": true, "ref": true, "ref_protected": true, "ref_type": true, "repository": true, "repository_id": true, "repository_owner": true, "repository_owner_id": true, "repository_visibility": true, "run_attempt": true, "run_id": true, "run_number": true, "runner_environment": true, "sha": true, "workflow": true, "workflow_ref": true, "workflow_sha": true},
	"buildkite": {"agent_id": true, "build_branch": true, "build_commit": true, "build_id": true, "build_number": true, "build_source": true, "build_tag": true, "cluster_id": true, "cluster_name": true, "job_id": true, "organization_id": true, "organization_slug": true, "pipeline_id": true, "pipeline_slug": true, "queue_id": true, "queue_key": true, "runner_environment": true, "step_key": true, "https://aws.amazon.com/tags": true},
}

// validateTrust applies presets, validates inheritance, and compiles every binding schema.
func validateTrust(cfg *Config) error {
	issuerURLs := make(map[string]string, len(cfg.OIDCTrust.Issuers))
	for name, issuer := range cfg.OIDCTrust.Issuers {
		if !trustNamePattern.MatchString(name) {
			return fmt.Errorf("issuer name %q is invalid", name)
		}
		switch issuer.Provider {
		case "github":
			if issuer.IssuerURL != "" || len(issuer.SigningAlgs) != 0 || issuer.MaxTokenAge != 0 {
				return fmt.Errorf("issuer %q: provider preset fields cannot be overridden", name)
			}
			issuer.IssuerURL, issuer.SigningAlgs, issuer.MaxTokenAge = "https://token.actions.githubusercontent.com", []string{"RS256"}, Duration(10*60*1e9)
		case "buildkite":
			if issuer.IssuerURL != "" || len(issuer.SigningAlgs) != 0 || issuer.MaxTokenAge != 0 {
				return fmt.Errorf("issuer %q: provider preset fields cannot be overridden", name)
			}
			issuer.IssuerURL, issuer.SigningAlgs, issuer.MaxTokenAge = "https://agent.buildkite.com", []string{"RS256"}, Duration(10*60*1e9)
		case "oidc":
			if err := validateIssuerURL(issuer.IssuerURL); err != nil {
				return fmt.Errorf("issuer %q: %w", name, err)
			}
			if len(issuer.SigningAlgs) == 0 || issuer.MaxTokenAge.Duration() <= 0 {
				return fmt.Errorf("issuer %q: signing_algs and max_token_age are required", name)
			}
		default:
			return fmt.Errorf("issuer %q: provider must be github, buildkite, or oidc", name)
		}
		u, _ := url.Parse(issuer.IssuerURL)
		if u.Fragment != "" || u.RawQuery != "" {
			return fmt.Errorf("issuer %q: issuer_url must not contain query or fragment", name)
		}
		for _, alg := range issuer.SigningAlgs {
			if !isTrustAlg(alg) {
				return fmt.Errorf("issuer %q: unsupported asymmetric signing algorithm %q", name, alg)
			}
		}
		if other, exists := issuerURLs[issuer.IssuerURL]; exists {
			return fmt.Errorf("issuers %q and %q have the same effective issuer_url", other, name)
		}
		issuerURLs[issuer.IssuerURL] = name
		cfg.OIDCTrust.Issuers[name] = issuer
	}
	for policyName, policy := range cfg.OIDCTrust.Policies {
		if !trustNamePattern.MatchString(policyName) {
			return fmt.Errorf("policy name %q is invalid", policyName)
		}
		issuer, ok := cfg.OIDCTrust.Issuers[policy.Issuer]
		if !ok {
			return fmt.Errorf("policy %q: unknown issuer", policyName)
		}
		if err := validatePolicyFragments(policy, issuer.Provider); err != nil {
			return fmt.Errorf("policy %q: %w", policyName, err)
		}
	}
	for clientID, client := range cfg.Clients {
		if len(client.TrustBindings) > maxTrustBindings {
			return fmt.Errorf("client %q: at most %d trust bindings are allowed", clientID, maxTrustBindings)
		}
		seen := map[string]bool{}
		for i := range client.TrustBindings {
			binding := &client.TrustBindings[i]
			if !trustNamePattern.MatchString(binding.ID) || seen[binding.ID] {
				return fmt.Errorf("client %q: trust binding IDs must be nonempty and unique", clientID)
			}
			seen[binding.ID] = true
			policy, ok := cfg.OIDCTrust.Policies[binding.TrustPolicy]
			if !ok {
				return fmt.Errorf("client %q binding %q: unknown trust_policy", clientID, binding.ID)
			}
			issuer := cfg.OIDCTrust.Issuers[policy.Issuer]
			subject := policy.Subject
			if binding.Subject != nil {
				subject = *binding.Subject
			}
			groups := policy.Groups
			if binding.Groups != nil {
				groups = binding.Groups
			}
			if !strings.HasPrefix(subject, "trusted:") || len(subject) > 256 || len(groups) == 0 || len(groups) > 100 {
				return fmt.Errorf("client %q binding %q: effective subject must begin trusted: and groups must contain 1-100 values", clientID, binding.ID)
			}
			for _, group := range groups {
				if group == "" || len(group) > 256 {
					return fmt.Errorf("client %q binding %q: group names must contain 1-256 characters", clientID, binding.ID)
				}
			}
			claims := make(map[string]json.RawMessage, len(policy.Claims)+len(binding.Claims))
			for k, v := range policy.Claims {
				claims[k] = v
			}
			for k, v := range binding.Claims {
				if err := validateClaimName(k, issuer.Provider); err != nil {
					return fmt.Errorf("client %q binding %q: %w", clientID, binding.ID, err)
				}
				var fragment any
				if err := decodeFragment(v, &fragment); err != nil {
					return fmt.Errorf("client %q binding %q claim %q: %w", clientID, binding.ID, k, err)
				}
				claims[k] = v
			}
			schema, err := compileTrustSchema(claims, policy.RequiredClaims)
			if err != nil {
				return fmt.Errorf("client %q binding %q: %w", clientID, binding.ID, err)
			}
			binding.Effective = &EffectiveTrustBinding{ID: binding.ID, Policy: binding.TrustPolicy, Issuer: policy.Issuer, Subject: subject, Groups: append([]string(nil), groups...), Schema: schema}
		}
		cfg.Clients[clientID] = client
	}
	return nil
}

// validatePolicyFragments validates every policy fragment before inheritance or overrides are applied.
func validatePolicyFragments(policy TrustPolicyConfig, provider string) error {
	for kind, fragments := range map[string]map[string]json.RawMessage{"claim": policy.Claims, "required claim": policy.RequiredClaims} {
		for name, raw := range fragments {
			if err := validateClaimName(name, provider); err != nil {
				return err
			}
			var fragment any
			if err := decodeFragment(raw, &fragment); err != nil {
				return fmt.Errorf("%s %q: %w", kind, name, err)
			}
		}
	}
	if len(policy.Claims) != 0 || len(policy.RequiredClaims) != 0 {
		if _, err := compileTrustSchema(policy.Claims, policy.RequiredClaims); err != nil {
			return fmt.Errorf("compile policy schema: %w", err)
		}
	}
	return nil
}

// validateClaimName accepts standard claims and narrowly bounded provider claims.
func validateClaimName(name, provider string) error {
	standard := map[string]bool{"iss": true, "sub": true, "aud": true, "exp": true, "nbf": true, "iat": true, "jti": true, "azp": true, "nonce": true, "email": true, "email_verified": true}
	providerClaim := presetClaims[provider] != nil && presetClaims[provider][name]
	dynamicClaim := provider == "oidc" || (provider == "github" && strings.HasPrefix(name, "repo_property_") && len(name) > len("repo_property_")) || (provider == "buildkite" && strings.HasPrefix(name, "agent_tag:") && len(name) > len("agent_tag:"))
	if name == "" || len(name) > 256 || (!standard[name] && !providerClaim && !dynamicClaim) {
		return fmt.Errorf("claim name %q is not allowed for provider %q", name, provider)
	}
	return nil
}

// isTrustAlg accepts only asymmetric JWT signature algorithms.
func isTrustAlg(alg string) bool { _, ok := supportedSigningAlgorithms[alg]; return ok }

// compileTrustSchema safely compiles one bounded effective object schema.
func compileTrustSchema(claims, required map[string]json.RawMessage) (*jsonschema.Schema, error) {
	properties, names := map[string]any{}, []any{}
	for name, raw := range claims {
		if name == "" || len(name) > 256 {
			return nil, fmt.Errorf("claim name %q is invalid", name)
		}
		var value any
		if err := decodeFragment(raw, &value); err != nil {
			return nil, fmt.Errorf("claim %q: %w", name, err)
		}
		properties[name] = value
		names = append(names, name)
	}
	for name, raw := range required {
		if name == "" || len(name) > 256 {
			return nil, fmt.Errorf("required claim name %q is invalid", name)
		}
		var value any
		if err := decodeFragment(raw, &value); err != nil {
			return nil, fmt.Errorf("required claim %q: %w", name, err)
		}
		if existing, ok := properties[name]; ok {
			properties[name] = map[string]any{"allOf": []any{value, existing}}
		} else {
			properties[name] = value
			names = append(names, name)
		}
	}
	doc := map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object", "required": names, "properties": properties}
	data, _ := json.Marshal(doc)
	if len(data) > 64<<10 || len(names) > 64 {
		return nil, fmt.Errorf("effective schema exceeds safe limits")
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.UseLoader(denySchemaLoader{})
	if err := c.AddResource("urn:easy-oidc:binding", doc); err != nil {
		return nil, err
	}
	return c.Compile("urn:easy-oidc:binding")
}

// decodeFragment rejects dangerous features and structurally oversized fragments.
func decodeFragment(raw json.RawMessage, value *any) error {
	if len(raw) == 0 || len(raw) > 16<<10 {
		return fmt.Errorf("schema fragment is empty or too large")
	}
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.UseNumber()
	if err := d.Decode(value); err != nil {
		return err
	}
	return inspectSchema(*value, 0)
}

// inspectSchema bounds depth/composition and rejects references, vocabularies, and content processing.
func inspectSchema(v any, depth int) error {
	if depth > 16 {
		return fmt.Errorf("schema exceeds maximum depth")
	}
	switch x := v.(type) {
	case map[string]any:
		if len(x) > 64 {
			return fmt.Errorf("schema object too large")
		}
		for k, val := range x {
			if k == "$schema" || k == "$id" || k == "$anchor" || k == "$dynamicAnchor" || k == "$ref" || k == "$dynamicRef" || k == "$recursiveRef" || k == "$vocabulary" || strings.HasPrefix(k, "content") {
				return fmt.Errorf("prohibited schema keyword %q", k)
			}
			if err := inspectSchema(val, depth+1); err != nil {
				return err
			}
		}
	case []any:
		if len(x) > 32 {
			return fmt.Errorf("schema composition or collection too large")
		}
		for _, val := range x {
			if err := inspectSchema(val, depth+1); err != nil {
				return err
			}
		}
	case string:
		if len(x) > 4096 {
			return fmt.Errorf("schema string too long")
		}
	}
	return nil
}
