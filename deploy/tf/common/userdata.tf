# Truster <https://truster.dev>
# Copyright The Truster Authors
# SPDX-License-Identifier: Apache-2.0

data "http" "truster_latest_release" {
  count = var.truster_version == "latest" ? 1 : 0
  url   = "https://api.github.com/repos/truster-dev/truster/releases/latest"
}

data "http" "caddy_latest_release" {
  count = var.caddy_version == "latest" ? 1 : 0
  url   = "https://api.github.com/repos/caddyserver/caddy/releases/latest"
}

locals {
  truster_version_resolved = var.truster_version == "latest" ? jsondecode(data.http.truster_latest_release[0].response_body).tag_name : var.truster_version
  caddy_version_resolved   = var.caddy_version == "latest" ? jsondecode(data.http.caddy_latest_release[0].response_body).tag_name : var.caddy_version
}

data "http" "userdata_script" {
  url = "https://raw.githubusercontent.com/truster-dev/truster/${local.truster_version_resolved}/deploy/userdata.sh"
}

data "http" "truster_checksums" {
  url = "https://github.com/truster-dev/truster/releases/download/${local.truster_version_resolved}/truster_${trimprefix(local.truster_version_resolved, "v")}_checksums.txt"
}

data "http" "caddy_checksums" {
  url = "https://github.com/caddyserver/caddy/releases/download/${local.caddy_version_resolved}/caddy_${trimprefix(local.caddy_version_resolved, "v")}_checksums.txt"
}

locals {
  truster_sha512 = try(
    [for line in split("\n", data.http.truster_checksums.response_body) :
      split("  ", line)[0] if length(regexall("truster_.*_linux_${local.instance_arch}\\.tar\\.gz", line)) > 0
    ][0],
    ""
  )

  caddy_sha512 = try(
    [for line in split("\n", data.http.caddy_checksums.response_body) :
      split("  ", line)[0] if length(regexall("caddy_.*_linux_${local.instance_arch}\\.tar\\.gz", line)) > 0
    ][0],
    ""
  )

  userdata = <<-EOT
    #!/bin/bash
    TRUSTER_VERSION=${local.truster_version_resolved}
    TRUSTER_SHA512=${local.truster_sha512}
    CADDY_VERSION=${local.caddy_version_resolved}
    CADDY_SHA512=${local.caddy_sha512}
    OIDC_ADDR=${var.oidc_addr}
    TRUSTER_CONFIG=$(printf '%s' '${base64encode(local.config_jsonc)}' | base64 --decode)
    RUN_DB_MIGRATIONS=${var.run_db_migrations}
    SSH=${local.ssh_enabled}
    FIREWALL=false
    ${replace(data.http.userdata_script.response_body, "/^#!.*/", "")}
  EOT
}
