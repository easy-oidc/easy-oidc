# Easy OIDC <https://easy-oidc.dev>
# Copyright The Easy OIDC Authors
# SPDX-License-Identifier: Apache-2.0

locals {
  project_id = var.project_id != null ? var.project_id : data.google_client_config.current.project
  region     = var.region != null ? var.region : data.google_client_config.current.region
  zone       = var.zone != null ? var.zone : data.google_client_config.current.zone

  oidc_hostname = split(":", var.oidc_addr)[0]
  oidc_port     = length(split(":", var.oidc_addr)) > 1 ? split(":", var.oidc_addr)[1] : "443"
  issuer_url    = local.oidc_port == "443" ? "https://${local.oidc_hostname}" : "https://${var.oidc_addr}"

  create_subnetwork = var.subnetwork == null
  subnetwork        = local.create_subnetwork ? google_compute_subnetwork.main[0].self_link : var.subnetwork

  service_account_email = var.service_account_email != null ? var.service_account_email : google_service_account.main[0].email

  secret_references = toset(compact(concat(
    [try(var.easy_oidc_config.secrets.signing_key_name, null), try(var.easy_oidc_config.secrets.encryption_key_name, null)],
    try([for connector in values(var.easy_oidc_config.user_login_connectors) : try(connector.credentials_secret, null)], []),
    [
      try(var.easy_oidc_config.email.otp_secret_name, null),
      try(var.easy_oidc_config.email.smtp.credentials_secret, null),
      try(var.easy_oidc_config.email.turnstile.secret_name, null),
      try(var.easy_oidc_config.state_database.connection_string_secret, null),
      try(var.easy_oidc_config.policy_database.connection_string_secret, null),
    ],
    var.run_db_migrations ? [
      try(var.easy_oidc_config.state_database.migrations.connection_string_secret, null),
    ] : [],
  )))

  secret_resources = {
    for reference in local.secret_references : reference => {
      project   = split("/", reference)[1]
      secret_id = split("/", reference)[3]
    }
    if can(regex("^projects/[^/]+/secrets/[^/]+/versions/[^/]+$", reference))
  }

  labels = merge(
    var.labels,
    {
      app = "easy-oidc"
    }
  )

  network_tag = replace(var.name_prefix, "/[^a-z0-9-]/", "-")
}
