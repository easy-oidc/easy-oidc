# Truster <https://truster.dev>
# Copyright The Truster Authors
# SPDX-License-Identifier: Apache-2.0

resource "google_compute_instance" "main" {
  project      = local.project_id
  name         = var.name_prefix
  zone         = local.zone
  machine_type = var.machine_type

  tags   = [local.network_tag]
  labels = local.labels

  boot_disk {
    initialize_params {
      image = data.google_compute_image.debian.self_link
      size  = var.instance_disk_size_gb
      type  = var.boot_disk_type
    }
    kms_key_self_link = var.boot_disk_kms_key_self_link
  }

  network_interface {
    subnetwork = local.subnetwork

    dynamic "access_config" {
      for_each = var.enable_ipv4 ? [1] : []
      content {
        nat_ip       = google_compute_address.ipv4[0].address
        network_tier = "PREMIUM"
      }
    }

    dynamic "ipv6_access_config" {
      for_each = var.enable_ipv6 ? [1] : []
      content {
        external_ipv6               = google_compute_address.ipv6[0].address
        external_ipv6_prefix_length = 96
        network_tier                = "PREMIUM"
      }
    }
  }

  service_account {
    email  = local.service_account_email
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }

  metadata = merge(
    {
      enable-oslogin = "FALSE"
    },
    length(var.ssh_keys) > 0 ? {
      ssh-keys = join("\n", var.ssh_keys)
    } : {}
  )

  metadata_startup_script = local.userdata

  allow_stopping_for_update = true

  lifecycle {
    precondition {
      condition = alltrue([
        for reference in compact(concat(
          [var.truster_config.secrets.signing_key_name, var.truster_config.secrets.encryption_key_name],
          [for connector in values(var.truster_config.user_login_connectors) : connector.credentials_secret],
          [
            try(var.truster_config.email.otp_secret_name, null),
            try(var.truster_config.email.smtp.credentials_secret, null),
            try(var.truster_config.email.turnstile.secret_name, null),
            try(var.truster_config.state_database.connection_string_secret, null),
            try(var.truster_config.state_database.migrations.connection_string_secret, null),
            try(var.truster_config.policy_database.connection_string_secret, null),
          ],
        )) : can(regex("^projects/[^/]+/secrets/[^/]+/versions/[^/]+$", reference))
      ])
      error_message = "Secret references in truster_config must be full Secret Manager version names: projects/PROJECT/secrets/SECRET/versions/VERSION."
    }

    precondition {
      condition     = var.enable_ipv4 || var.enable_ipv6
      error_message = "At least one of enable_ipv4 or enable_ipv6 must be true so the instance can download dependencies and serve OIDC traffic."
    }

    precondition {
      condition = !var.run_db_migrations || (
        try(var.truster_config.state_database.driver == "postgresql", false) &&
        try(trimspace(var.truster_config.state_database.migrations.connection_string_secret) != "", false)
      )
      error_message = "run_db_migrations requires a PostgreSQL state_database and a non-empty state_database.migrations.connection_string_secret."
    }
  }
}
