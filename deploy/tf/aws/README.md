# terraform-aws-easy-oidc

OpenTofu/Terraform module for deploying [Easy OIDC](https://easy-oidc.dev) on AWS. It provisions a single EC2 instance, Caddy TLS proxy, dual-stack networking, and least-privilege access to AWS Systems Manager Parameter Store or AWS Secrets Manager.

## Features

- Single ARM64 or AMD64 EC2 instance (`t4g.nano` by default)
- IPv4-only, IPv6-only, or dual-stack networking with stable public addresses
- Optional automatic subnet creation
- Caddy with automatic Let's Encrypt TLS
- Explicit, least-privilege Parameter Store or Secrets Manager access
- Optional customer-managed KMS encryption and SSH access

## Prerequisites

Parameter Store is the default secrets backend. Create encrypted parameters before deploying:

```bash
aws ssm put-parameter \
  --name /easy-oidc/google-credentials \
  --type SecureString \
  --value '{"client_id":"123456789.apps.googleusercontent.com","client_secret":"GOCSPX-xxxxxxxx"}'

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 > signing-key.pem
aws ssm put-parameter \
  --name /easy-oidc/signing-key \
  --type SecureString \
  --value "$(cat signing-key.pem)"
rm signing-key.pem

aws ssm put-parameter \
  --name /easy-oidc/encryption-key \
  --type SecureString \
  --value "$(openssl rand -hex 32)"
```

## Usage

The typed `easy_oidc_config` value models the current [Easy OIDC v2 application configuration](https://easy-oidc.dev/docs/config/) so type and supported cross-field errors fail during planning. The module overrides `issuer_url`, `http_listen_addr`, `secrets.provider`, and `secrets.aws_region`. The schema-editor-only `$schema` field and native `serving_certificate` field are intentionally omitted: this deployment generates the configuration and terminates TLS with Caddy. It also defaults the deployment's state database to SQLite at `/var/lib/easy-oidc/easy-oidc-state.db`, including when an explicit SQLite configuration omits `path`; explicit PostgreSQL configuration is preserved. The module derives least-privilege IAM resources from the runtime secret references in this object.

By default, the migration-only
`state_database.migrations.connection_string_secret` is not granted to the
instance role. Set `run_db_migrations = true` to grant access to
that secret and run `easy-oidc migrate` before every service start. A failed
migration prevents Easy OIDC from starting. Because migration credentials
usually have broader database permissions than runtime credentials, keep the
default and run migrations with a separate deployment identity in stricter
environments. See the
[state database guide](https://easy-oidc.dev/docs/state-database/).

```hcl
module "easy_oidc" {
  source = "easy-oidc/easy-oidc/aws"

  vpc_id    = aws_vpc.main.id
  oidc_addr = "auth.example.com"

  easy_oidc_config = {
    secrets = {
      signing_key_name    = "/easy-oidc/signing-key"
      encryption_key_name = "/easy-oidc/encryption-key"
    }
    user_login_connectors = {
      google = {
        type               = "google"
        display_name       = "Google"
        credentials_secret = "/easy-oidc/google-credentials"
      }
    }
    static_policy = {
      user_group_mappings = {
        prod-groups = {
          "alice@example.com" = ["prod-admins", "developers"]
        }
      }
      clients = {
        kubelogin-prod = {
          redirect_uris      = ["http://localhost:8000"]
          user_group_mapping = "prod-groups"
        }
      }
    }
  }
}
```

To use Secrets Manager instead, set `secrets_provider = "aws-secrets-manager"`,
and use Secrets Manager names or full ARNs in `easy_oidc_config`.

Then run:

```bash
tofu init
tofu plan
tofu apply
```

See [`examples/main`](examples/main) for a complete VPC and DNS example.

## Kubernetes integration

Configure the API server with the module's `issuer_url` and one of its `client_ids`:

```text
--oidc-issuer-url=https://auth.example.com
--oidc-client-id=kubelogin-prod
--oidc-username-claim=email
--oidc-groups-claim=groups
```

Easy OIDC requires PKCE. For example, use
`kubectl oidc-login setup --oidc-pkce-method=S256`.

## IPv6-only deployment

Set `enable_ipv4 = false` and publish only the module's `public_ipv6` output:

```hcl
module "easy_oidc" {
  source = "easy-oidc/easy-oidc/aws"

  # Required inputs omitted.
  enable_ipv4 = false
}
```

## Variables

This table is the complete module input reference.

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `vpc_id` | VPC ID where Easy OIDC is deployed. | `string` | n/a | yes |
| `oidc_addr` | Public OIDC server address, such as `auth.example.com` or `auth.example.com:8443`. | `string` | n/a | yes |
| `easy_oidc_config` | Typed Easy OIDC v2 application configuration. Put application-owned settings here; deployment-owned fields are overridden as described above. | `object` | n/a | yes |
| `run_db_migrations` | Run migrations before every service start and grant access to the configured migration secret. | `bool` | `false` | no |
| `secrets_provider` | AWS secrets backend: `aws-parameter-store` or `aws-secrets-manager`. | `string` | `"aws-parameter-store"` | no |
| `name_prefix` | Prefix for resource names. | `string` | `"easy-oidc"` | no |
| `tags` | Additional tags applied to all resources. | `map(string)` | `{}` | no |
| `subnet_id` | Existing subnet ID; the module creates a subnet when omitted. | `string` | `null` | no |
| `enable_ipv4` | Enable a public IPv4 address. | `bool` | `true` | no |
| `enable_ipv6` | Enable a public IPv6 address. | `bool` | `true` | no |
| `instance_type` | EC2 instance type; its architecture selects the matching Debian 13 image. | `string` | `"t4g.nano"` | no |
| `instance_disk_size_gb` | Instance boot disk size in GB. | `number` | `10` | no |
| `allowed_cidrs_ipv4` | IPv4 CIDRs allowed to access HTTP/HTTPS; ignored when IPv4 is disabled. | `list(string)` | `["0.0.0.0/0"]` | no |
| `allowed_cidrs_ipv6` | IPv6 CIDRs allowed to access HTTP/HTTPS; ignored when IPv6 is disabled. | `list(string)` | `["::/0"]` | no |
| `easy_oidc_version` | Easy OIDC release to install; must be `v2.0.0` or later, or `latest`. | `string` | `"latest"` | no |
| `caddy_version` | Caddy version to install, or `latest`. | `string` | `"latest"` | no |
| `kms_key_id` | KMS key ID/ARN for EBS encryption; uses the AWS-managed key when omitted. | `string` | `null` | no |
| `ssh_key_name` | Existing EC2 key pair name; SSH is disabled when omitted. | `string` | `null` | no |
| `ssh_allowed_cidrs_ipv4` | IPv4 CIDRs allowed SSH access when `ssh_key_name` is set. | `list(string)` | `[]` | no |
| `ssh_allowed_cidrs_ipv6` | IPv6 CIDRs allowed SSH access when `ssh_key_name` is set. | `list(string)` | `[]` | no |

## Outputs

| Name | Description |
|------|-------------|
| `issuer_url` | OIDC issuer URL. |
| `client_ids` | Static client IDs derived from `easy_oidc_config.static_policy.clients`; empty when clients come only from the policy database. |
| `enable_ipv4` | Whether IPv4 is enabled. |
| `enable_ipv6` | Whether IPv6 is enabled. |
| `public_ipv4` | Public IPv4 address, or null when disabled. |
| `public_ipv6` | Public IPv6 address, or null when disabled. |
| `network_interface_id` | Stable network interface ID. |
| `subnet_id` | Created or supplied subnet ID. |
| `security_group_id` | Security group ID. |
| `instance_arch` | Detected instance architecture. |
| `easy_oidc_version` | Resolved installed Easy OIDC version. |
| `caddy_version` | Resolved installed Caddy version. |

## Security

- Secrets remain in Parameter Store or Secrets Manager; only parameter or secret names are included in the rendered configuration.
- The EC2 role receives only the read actions and resources derived from secret references in `easy_oidc_config`.
- Caddy provides automatic HTTPS, and Easy OIDC requires PKCE for clients.
- By default, protocol state is stored in `/var/lib/easy-oidc/easy-oidc-state.db`; configure `state_database` for PostgreSQL.

## License

Easy OIDC is licensed under the Apache License, Version 2.0.
Copyright The Easy OIDC Authors.
See the [LICENSE](./LICENSE) file for details.
