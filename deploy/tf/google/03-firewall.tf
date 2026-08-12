# Truster <https://truster.dev>
# Copyright The Truster Authors
# SPDX-License-Identifier: Apache-2.0

resource "google_compute_firewall" "http_https_ipv4" {
  count = var.enable_ipv4 ? 1 : 0

  project = local.project_id
  name    = "${var.name_prefix}-http-https-ipv4"
  network = var.network

  direction     = "INGRESS"
  source_ranges = var.allowed_cidrs_ipv4
  target_tags   = [local.network_tag]

  allow {
    protocol = "tcp"
    ports    = ["80", "443"]
  }
}

resource "google_compute_firewall" "http_https_ipv6" {
  count = var.enable_ipv6 ? 1 : 0

  project = local.project_id
  name    = "${var.name_prefix}-http-https-ipv6"
  network = var.network

  direction     = "INGRESS"
  source_ranges = var.allowed_cidrs_ipv6
  target_tags   = [local.network_tag]

  allow {
    protocol = "tcp"
    ports    = ["80", "443"]
  }
}

resource "google_compute_firewall" "ssh_ipv4" {
  count = length(var.ssh_keys) > 0 && var.enable_ipv4 && length(var.ssh_allowed_cidrs_ipv4) > 0 ? 1 : 0

  project = local.project_id
  name    = "${var.name_prefix}-ssh-ipv4"
  network = var.network

  direction     = "INGRESS"
  source_ranges = var.ssh_allowed_cidrs_ipv4
  target_tags   = [local.network_tag]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_firewall" "ssh_ipv6" {
  count = length(var.ssh_keys) > 0 && var.enable_ipv6 && length(var.ssh_allowed_cidrs_ipv6) > 0 ? 1 : 0

  project = local.project_id
  name    = "${var.name_prefix}-ssh-ipv6"
  network = var.network

  direction     = "INGRESS"
  source_ranges = var.ssh_allowed_cidrs_ipv6
  target_tags   = [local.network_tag]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}
