---
draft: false
title: 'Deploy to AWS using OpenTofu/Terraform'
linkTitle: 'AWS'
---

This guide deploys a persistent Easy OIDC issuer on AWS with Google sign-in and
one kubelogin client. It uses the official OpenTofu/Terraform module and creates
a small dual-stack VPC for the example.

The module runs Easy OIDC and Caddy on one EC2 instance. Caddy obtains the HTTPS
certificate, SQLite stores login state, and the instance reads only the encrypted
parameters named in your configuration.

## Before you begin

You need:

- an AWS account and credentials with permission to manage EC2, IAM, VPC,
  Route 53, and Systems Manager Parameter Store resources;
- a public Route 53 hosted zone, such as `example.com`;
- [OpenTofu](https://opentofu.org/) or Terraform 1.5 or later;
- the AWS CLI, OpenSSL, and curl; and
- a Google account that can create an OAuth application.

This guide uses these example values. Choose your own now and use them
consistently in every step.

| Setting | Example |
|---|---|
| AWS region | `us-east-1` |
| Route 53 hosted zone | `example.com` |
| Easy OIDC hostname | `auth.example.com` |
| Sign-in method ID | `google` |
| Google callback URL | `https://auth.example.com/callback/google` |
| kubelogin client ID | `kubelogin-prod` |
| Allowed user | `alice@example.com` |

The hostname must be final before you create the Google OAuth application,
because Google only redirects to callback URLs registered in advance.

## 1. Create the Google OAuth application

Follow the [Google sign-in provider guide](/docs/upstream/google/) to create a
web OAuth client. Register the callback URL from the table above, then keep the
client ID and client secret for the next step.

The provider guide also covers how to store these credentials. Skip that part
for now—the next step stores them in AWS Systems Manager Parameter Store.

## 2. Create the encrypted parameters

Parameter Store is the module's default secret backend. First put the Google
client ID and secret in a temporary JSON file:

```console
cat > google-credentials.json <<'EOF'
{"client_id":"YOUR_GOOGLE_CLIENT_ID","client_secret":"YOUR_GOOGLE_CLIENT_SECRET"}
EOF

aws ssm put-parameter \
  --region us-east-1 \
  --name /easy-oidc/google-credentials \
  --type SecureString \
  --value file://google-credentials.json

rm google-credentials.json
```

Generate the RSA signing key and store it as a second encrypted parameter:

```console
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 > signing-key.pem

aws ssm put-parameter \
  --region us-east-1 \
  --name /easy-oidc/signing-key \
  --type SecureString \
  --value "$(cat signing-key.pem)"

rm signing-key.pem
```

Use `--overwrite` only when you intentionally want to replace an existing
parameter. Replacing a signing key invalidates tokens signed by the previous key.

To use AWS Secrets Manager instead, set the module's `secrets_provider` to
`aws-secrets-manager` and use Secrets Manager names or ARNs in the application
configuration. See the [module input reference](https://github.com/easy-oidc/terraform-aws-easy-oidc#variables).

## 3. Create the OpenTofu configuration

Create an empty directory and save the following as `main.tf`. Change the region,
hosted zone, hostname, and allowed email address to your values.

```hcl
terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

locals {
  region        = "us-east-1"
  route53_zone  = "example.com"
  oidc_hostname = "auth.example.com"
}

provider "aws" {
  region = local.region
}

resource "aws_vpc" "main" {
  cidr_block                       = "10.0.0.0/16"
  assign_generated_ipv6_cidr_block = true
  enable_dns_hostnames             = true
  enable_dns_support               = true
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
}

resource "aws_route_table" "main" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  route {
    ipv6_cidr_block = "::/0"
    gateway_id      = aws_internet_gateway.main.id
  }
}

module "easy_oidc" {
  source = "easy-oidc/easy-oidc/aws"

  vpc_id    = aws_vpc.main.id
  oidc_addr = local.oidc_hostname

  easy_oidc_config = {
    secrets = {
      signing_key_name = "/easy-oidc/signing-key"
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
        kubernetes-users = {
          "alice@example.com" = ["developers"]
        }
      }
      clients = {
        kubelogin-prod = {
          redirect_uris      = ["http://localhost:8000"]
          user_group_mapping = "kubernetes-users"
        }
      }
    }
  }
}

resource "aws_route_table_association" "main" {
  subnet_id      = module.easy_oidc.subnet_id
  route_table_id = aws_route_table.main.id
}

data "aws_route53_zone" "main" {
  name = local.route53_zone
}

resource "aws_route53_record" "oidc_a" {
  count   = module.easy_oidc.enable_ipv4 ? 1 : 0
  zone_id = data.aws_route53_zone.main.zone_id
  name    = local.oidc_hostname
  type    = "A"
  ttl     = 300
  records = [module.easy_oidc.public_ipv4]
}

resource "aws_route53_record" "oidc_aaaa" {
  zone_id = data.aws_route53_zone.main.zone_id
  name    = local.oidc_hostname
  type    = "AAAA"
  ttl     = 300
  records = [module.easy_oidc.public_ipv6]
}
```

The module creates the subnet and security group. This example creates the VPC,
internet gateway, route table, and DNS records around it. For production, you can
instead pass an existing subnet and apply your normal networking controls.

Before production use, pin a reviewed module version and set
`easy_oidc_version` rather than tracking the latest releases implicitly.

## 4. Deploy

Review the plan before applying it:

```console
tofu init
tofu plan
tofu apply
```

If you use Terraform, replace `tofu` with `terraform`. The apply output includes
the issuer URL, client IDs, public addresses, and resolved software versions.
Certificate issuance can take a few minutes after the DNS records appear.

## 5. Verify the issuer and sign in

Check DNS propagation:

```bash
dig auth.example.com A
dig auth.example.com AAAA
```

Check that the OIDC discovery document is available:

```console
curl --fail https://auth.example.com/.well-known/openid-configuration
```

A successful request returns JSON describing the issuer and its endpoints. If it
fails, wait for DNS propagation, then check that ports 80 and 443 reach the
instance.

Install kubelogin as described in the [kubelogin guide](/docs/kubelogin/), then
test the browser flow:

```console
kubectl oidc-login setup \
  --oidc-issuer-url=https://auth.example.com \
  --oidc-client-id=kubelogin-prod \
  --oidc-use-pkce
```

Sign in with the allowed Google account. kubelogin should report the email and
`developers` group configured above. This confirms login; it does not yet grant
access to a Kubernetes cluster.

## 6. Connect Kubernetes

Follow the [Kubernetes integration guide](/docs/kubernetes/) to make the API
server trust this issuer and client ID. Create RBAC bindings for the
`developers` group, then follow the [kubelogin guide](/docs/kubelogin/) to add the
exec-based credentials to each user's kubeconfig.

## Configuration boundaries

The module injects the deployment-owned `issuer_url`, `http_listen_addr`,
`secrets.provider`, and `secrets.aws_region` settings. It also supplies a
writable SQLite state path when no state database is configured. Put the
remaining application settings under `easy_oidc_config`. The module derives its
IAM read permissions from the runtime parameters or secrets referenced there.
Migration credentials remain separate by default. To let the instance migrate
the state database before starting Easy OIDC, set
`run_state_database_migrations = true`; this grants it access to the configured
migration secret. See the [state database guide](/docs/state-database/) for the
least-privilege tradeoff.

Use the [module input reference](https://github.com/easy-oidc/terraform-aws-easy-oidc#variables)
for networking, KMS, SSH, tagging, secrets backends, and version controls. Use
the [application configuration reference](/docs/config/) for sign-in methods,
clients, users, groups, email verification, and templates.

## IPv6-Only Deployment

To deploy without IPv4:

```hcl
module "easy_oidc" {
  source = "easy-oidc/easy-oidc/aws"
  
  # ... other variables ...
  enable_ipv4 = false
}
```

This disables IPv4 addresses on the instance and security group rules. Only create the AAAA DNS record in this case.

## SSH Access (Optional)

To enable SSH access for debugging:

```hcl
resource "aws_key_pair" "easy_oidc" {
  key_name   = "easy-oidc-ssh"
  public_key = file("~/.ssh/id_rsa.pub")
}

module "easy_oidc" {
  source = "easy-oidc/easy-oidc/aws"
  
  # ... other variables ...
  ssh_key_name           = aws_key_pair.easy_oidc.key_name
  ssh_allowed_cidrs_ipv4 = ["1.2.3.4/32"]  # Your IP
}
```

## Instance Replacement and Updates

**Replacing the instance**:
- OpenTofu/Terraform will re-provision with identical configuration
- DNS records update automatically
- Users must re-login (existing tokens remain valid until expiry)

**Updating Easy OIDC version**:

```hcl
module "easy_oidc" {
  source = "easy-oidc/easy-oidc/aws"
  
  # ... other variables ...
  easy_oidc_version = "v2.0.0"  # Specify version
}
```

Then run `tofu apply` to trigger instance replacement.

## Troubleshooting

**Let's Encrypt certificate errors**:
- Verify DNS records point to the correct instance IP
- Ensure security group allows incoming HTTP (80) and HTTPS (443)
- Check Caddy logs with `journalctl -u caddy -f`

**OAuth callback errors**:
- Verify each OAuth app redirect URI matches `https://auth.example.com/callback/<connector-id>`
- Check Easy OIDC logs: `journalctl -u easy-oidc -f`

**Parameter Store errors**:
- Verify the instance role has `ssm:GetParameter` permission
- For a customer-managed KMS key, verify it also has `kms:Decrypt` permission
- Check parameter names and the AWS region against the application configuration

If you selected the optional Secrets Manager provider instead, verify
`secretsmanager:GetSecretValue` and the configured secret names or ARNs.

See [Troubleshooting](/docs/troubleshooting/) for more common issues.

## Next Steps

- [Configure Kubernetes integration](/docs/kubernetes/)
- [Set up kubelogin](/docs/kubelogin/)
- [Add clients and groups](/docs/config/)
- [Troubleshoot a deployment](/docs/troubleshooting/)
