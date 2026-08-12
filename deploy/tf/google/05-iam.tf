# Easy OIDC <https://easy-oidc.dev>
# Copyright The Easy OIDC Authors
# SPDX-License-Identifier: Apache-2.0

resource "google_service_account" "main" {
  count = var.service_account_email == null ? 1 : 0

  project      = local.project_id
  account_id   = replace(var.name_prefix, "/[^a-z0-9-]/", "-")
  display_name = "easy-oidc instance service account"
}

resource "google_secret_manager_secret_iam_member" "secret_accessor" {
  for_each = var.grant_secret_accessor ? local.secret_resources : {}

  project   = each.value.project
  secret_id = each.value.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${local.service_account_email}"
}
