# Easy OIDC <https://easy-oidc.dev>
# Copyright The Easy OIDC Authors
# SPDX-License-Identifier: Apache-2.0

locals {
  # Parse hostname and port from oidc_addr
  oidc_hostname = split(":", var.oidc_addr)[0]
  oidc_port     = length(split(":", var.oidc_addr)) > 1 ? split(":", var.oidc_addr)[1] : "443"
  issuer_url    = local.oidc_port == "443" ? "https://${local.oidc_hostname}" : "https://${var.oidc_addr}"

  # Create subnet if not provided
  create_subnet = var.subnet_id == null

  # Determine subnet for instance
  instance_subnet_id = local.create_subnet ? aws_subnet.main[0].id : var.subnet_id

  # Collect all secrets referenced by the application configuration
  secret_references = toset(compact(concat(
    [
      try(var.easy_oidc_config.secrets.signing_key_name, null),
      try(var.easy_oidc_config.secrets.encryption_key_name, null),
    ],
    [for connector in values(try(var.easy_oidc_config.user_login_connectors, {})) : try(connector.credentials_secret, null)],
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

  # Derive least-privilege IAM resource ARNs for the configured secrets provider
  secret_resource_arns = toset([
    for reference in local.secret_references : startswith(reference, "arn:") ? reference : (
      var.secrets_provider == "aws-parameter-store" ?
      "arn:${data.aws_partition.current.partition}:ssm:${data.aws_vpc.selected.region}:${data.aws_caller_identity.current.account_id}:parameter/${trimprefix(reference, "/")}" :
      "arn:${data.aws_partition.current.partition}:secretsmanager:${data.aws_vpc.selected.region}:${data.aws_caller_identity.current.account_id}:secret:${reference}-??????"
    )
  ])
}
