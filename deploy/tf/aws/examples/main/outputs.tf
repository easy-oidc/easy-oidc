# Easy OIDC <https://easy-oidc.dev>
# Copyright The Easy OIDC Authors
# SPDX-License-Identifier: Apache-2.0

output "issuer_url" {
  description = "OIDC issuer URL"
  value       = module.easy_oidc.issuer_url
}

output "client_ids" {
  description = "Configured client IDs"
  value       = module.easy_oidc.client_ids
}

output "public_ipv4" {
  description = "Public IPv4 address"
  value       = module.easy_oidc.public_ipv4
}

output "public_ipv6" {
  description = "Public IPv6 address"
  value       = module.easy_oidc.public_ipv6
}
