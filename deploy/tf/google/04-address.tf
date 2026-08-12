# Easy OIDC <https://easy-oidc.dev>
# Copyright The Easy OIDC Authors
# SPDX-License-Identifier: Apache-2.0

resource "google_compute_address" "ipv4" {
  count = var.enable_ipv4 ? 1 : 0

  project      = local.project_id
  name         = "${var.name_prefix}-ipv4"
  region       = local.region
  address_type = "EXTERNAL"
  ip_version   = "IPV4"
}

resource "google_compute_address" "ipv6" {
  count = var.enable_ipv6 ? 1 : 0

  project      = local.project_id
  name         = "${var.name_prefix}-ipv6"
  region       = local.region
  address_type = "EXTERNAL"
  ip_version   = "IPV6"
  subnetwork   = local.subnetwork
  network_tier = "PREMIUM"
}
