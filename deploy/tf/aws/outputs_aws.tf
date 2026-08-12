# Truster <https://truster.dev>
# Copyright The Truster Authors
# SPDX-License-Identifier: Apache-2.0

output "public_ipv4" {
  description = "Public IPv4 address (null if IPv4 disabled)"
  value       = var.enable_ipv4 ? aws_eip.main[0].public_ip : null
}

output "public_ipv6" {
  description = "Public IPv6 address (null if IPv6 disabled)"
  value       = var.enable_ipv6 ? tolist(aws_network_interface.main.ipv6_addresses)[0] : null
}

output "network_interface_id" {
  description = "Network interface ID (stable across instance replacements)"
  value       = aws_network_interface.main.id
}

output "subnet_id" {
  description = "Subnet ID (created or provided)"
  value       = local.instance_subnet_id
}

output "security_group_id" {
  description = "Security group ID"
  value       = aws_security_group.main.id
}
