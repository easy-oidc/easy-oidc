# Truster <https://truster.dev>
# Copyright The Truster Authors
# SPDX-License-Identifier: Apache-2.0

data "google_client_config" "current" {}

data "google_compute_image" "debian" {
  family  = local.instance_arch == "arm64" ? "debian-13-arm64" : "debian-13"
  project = "debian-cloud"
}
