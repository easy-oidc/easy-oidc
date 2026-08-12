# Easy OIDC <https://easy-oidc.dev>
# Copyright The Easy OIDC Authors
# SPDX-License-Identifier: Apache-2.0

locals {
  config_jsonc = jsonencode(merge(local.application_config, {
    issuer_url       = local.issuer_url
    http_listen_addr = "127.0.0.1:8080"
    secrets = merge(local.application_config.secrets, {
      provider = "google-secret-manager"
    })
  }))
}
