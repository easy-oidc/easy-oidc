# Easy OIDC <https://easy-oidc.dev>
# Copyright The Easy OIDC Authors
# SPDX-License-Identifier: Apache-2.0

resource "google_compute_subnetwork" "main" {
  count = local.create_subnetwork ? 1 : 0

  project       = local.project_id
  name          = "${var.name_prefix}-subnet"
  region        = local.region
  network       = var.network
  ip_cidr_range = var.subnetwork_cidr

  stack_type       = var.enable_ipv6 ? "IPV4_IPV6" : "IPV4_ONLY"
  ipv6_access_type = var.enable_ipv6 ? "EXTERNAL" : null
}
