# Truster <https://truster.dev>
# Copyright The Truster Authors
# SPDX-License-Identifier: Apache-2.0

output "issuer_url" {
  description = "OIDC issuer URL"
  value       = local.issuer_url
}

output "client_ids" {
  description = "List of statically configured OIDC client IDs (empty when clients are supplied only by policy_database)"
  value       = try(keys(var.truster_config.static_policy.clients), [])
}

output "enable_ipv4" {
  description = "Whether IPv4 is enabled"
  value       = var.enable_ipv4
}

output "enable_ipv6" {
  description = "Whether IPv6 is enabled"
  value       = var.enable_ipv6
}

output "instance_arch" {
  description = "Detected instance architecture (arm64 or amd64)"
  value       = local.instance_arch
}

output "truster_version" {
  description = "Resolved truster version (pinned from 'latest' if applicable)"
  value       = local.truster_version_resolved
}

output "caddy_version" {
  description = "Resolved Caddy version (pinned from 'latest' if applicable)"
  value       = local.caddy_version_resolved
}
