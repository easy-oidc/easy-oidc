# Easy OIDC <https://easy-oidc.dev>
# Copyright The Easy OIDC Authors
# SPDX-License-Identifier: Apache-2.0

# IAM role for instance
resource "aws_iam_role" "instance_role" {
  name_prefix = "${var.name_prefix}-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-instance-role"
    }
  )
}

# IAM policy for Parameter Store or Secrets Manager access
resource "aws_iam_role_policy" "instance_role_secret_access" {
  name_prefix = "${var.name_prefix}-instance-role-secrets-"
  role        = aws_iam_role.instance_role.id

  lifecycle {
    precondition {
      condition = alltrue([
        for reference in local.secret_references :
        !startswith(reference, "arn:") || can(regex(var.secrets_provider == "aws-parameter-store" ? ":ssm:" : ":secretsmanager:", reference))
      ])
      error_message = "Secret ARNs in easy_oidc_config must match secrets_provider."
    }

    precondition {
      condition = !var.run_db_migrations || (
        try(var.easy_oidc_config.state_database.driver == "postgresql", false) &&
        try(trimspace(var.easy_oidc_config.state_database.migrations.connection_string_secret) != "", false)
      )
      error_message = "run_db_migrations requires a PostgreSQL state_database and a non-empty state_database.migrations.connection_string_secret."
    }
  }

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = var.secrets_provider == "aws-parameter-store" ? [
          "ssm:GetParameter"
          ] : [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret",
        ]
        Resource = local.secret_resource_arns
      }
    ]
  })
}

# Attach IAM instance role to EC2 instance
resource "aws_iam_instance_profile" "instance_profile" {
  name_prefix = "${var.name_prefix}-"
  role        = aws_iam_role.instance_role.name

  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-instance-profile"
    }
  )
}
