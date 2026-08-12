# Truster <https://truster.dev>
# Copyright The Truster Authors
# SPDX-License-Identifier: Apache-2.0

output "public_ipv4" {
  description = "Public IPv4 address (null if IPv4 disabled)"
  value       = var.enable_ipv4 ? google_compute_address.ipv4[0].address : null
}

output "public_ipv6" {
  description = "Public IPv6 address (null if IPv6 disabled)"
  value       = var.enable_ipv6 ? google_compute_address.ipv6[0].address : null
}

output "instance_id" {
  description = "Compute Engine instance ID"
  value       = google_compute_instance.main.instance_id
}

output "instance_name" {
  description = "Compute Engine instance name"
  value       = google_compute_instance.main.name
}

output "subnetwork" {
  description = "Subnetwork used by the instance"
  value       = local.subnetwork
}

output "service_account_email" {
  description = "Service account attached to the instance"
  value       = local.service_account_email
}
