# Truster <https://truster.dev>
# Copyright The Truster Authors
# SPDX-License-Identifier: Apache-2.0

output "issuer_url" {
  description = "OIDC issuer URL"
  value       = module.truster.issuer_url
}

output "client_ids" {
  description = "Configured client IDs"
  value       = module.truster.client_ids
}

output "public_ipv4" {
  description = "Public IPv4 address"
  value       = module.truster.public_ipv4
}

output "public_ipv6" {
  description = "Public IPv6 address"
  value       = module.truster.public_ipv6
}
