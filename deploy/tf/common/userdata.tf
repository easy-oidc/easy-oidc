# Easy OIDC <https://easy-oidc.dev>
# Copyright The Easy OIDC Authors
# SPDX-License-Identifier: Apache-2.0

data "http" "easy_oidc_latest_release" {
  count = var.easy_oidc_version == "latest" ? 1 : 0
  url   = "https://api.github.com/repos/easy-oidc/easy-oidc/releases/latest"
}

data "http" "caddy_latest_release" {
  count = var.caddy_version == "latest" ? 1 : 0
  url   = "https://api.github.com/repos/caddyserver/caddy/releases/latest"
}

locals {
  easy_oidc_version_resolved = var.easy_oidc_version == "latest" ? jsondecode(data.http.easy_oidc_latest_release[0].response_body).tag_name : var.easy_oidc_version
  caddy_version_resolved     = var.caddy_version == "latest" ? jsondecode(data.http.caddy_latest_release[0].response_body).tag_name : var.caddy_version
}

data "http" "userdata_script" {
  url = "https://raw.githubusercontent.com/easy-oidc/easy-oidc/${local.easy_oidc_version_resolved}/deploy/userdata.sh"
}

data "http" "easy_oidc_checksums" {
  url = "https://github.com/easy-oidc/easy-oidc/releases/download/${local.easy_oidc_version_resolved}/easy-oidc_${trimprefix(local.easy_oidc_version_resolved, "v")}_checksums.txt"
}

data "http" "caddy_checksums" {
  url = "https://github.com/caddyserver/caddy/releases/download/${local.caddy_version_resolved}/caddy_${trimprefix(local.caddy_version_resolved, "v")}_checksums.txt"
}

locals {
  easy_oidc_sha512 = try(
    [for line in split("\n", data.http.easy_oidc_checksums.response_body) :
      split("  ", line)[0] if length(regexall("easy-oidc_.*_linux_${local.instance_arch}\\.tar\\.gz", line)) > 0
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
    EASY_OIDC_VERSION=${local.easy_oidc_version_resolved}
    EASY_OIDC_SHA512=${local.easy_oidc_sha512}
    CADDY_VERSION=${local.caddy_version_resolved}
    CADDY_SHA512=${local.caddy_sha512}
    OIDC_ADDR=${var.oidc_addr}
    EASY_OIDC_CONFIG=$(printf '%s' '${base64encode(local.config_jsonc)}' | base64 --decode)
    RUN_DB_MIGRATIONS=${var.run_db_migrations}
    SSH=${local.ssh_enabled}
    FIREWALL=false
    ${replace(data.http.userdata_script.response_body, "/^#!.*/", "")}
  EOT
}
