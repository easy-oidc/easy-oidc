---
draft: false
title: 'Deploy to AWS using OpenTofu/Terraform'
linkTitle: 'AWS'
---

This guide shows you how to deploy Easy OIDC on AWS using the official OpenTofu/Terraform module.

## What Gets Deployed

The `terraform-aws-easy-oidc` module provisions:

- **EC2 Instance**: Single ARM64 or AMD64 instance (t4g.nano by default) running Debian 13 (Trixie)
    - **Easy OIDC Binary**: Downloaded and installed via systemd service
    - **Caddy Reverse Proxy**: Provides automatic HTTPS via Let's Encrypt
    - **SQLite Database**: Stored at `/var/lib/easy-oidc/easy-oidc-state.db` for OAuth state and authorization codes
- **Security Group**: Allows HTTP (80) and HTTPS (443) from configurable CIDRs
- **IAM Role**: Grants read-only access to explicitly listed Parameter Store parameters or Secrets Manager secrets
- **Subnet** (optional): Auto-created with dual-stack IPv4/IPv6 support if not provided

## What You Need to Provide

Before deploying, you must have:

1. **VPC with Internet Gateway**: For outbound connectivity to Google/GitHub OAuth endpoints
2. **Route53 DNS Zone**: For configuring DNS records (required for Let's Encrypt TLS)
3. **Encrypted parameters in AWS Systems Manager Parameter Store** (the default):
   - OAuth client credentials (created via [upstream provider setup](/docs/upstream/))
   - PKCS8 PEM private key compatible with `signing_algorithm` (RSA-3072 for the default RS256 algorithm)

The module **does not** create:
- VPC, Internet Gateway, or Route Table (you create these)
- Route53 DNS records (you create these, pointing to the instance IP)
- Parameter Store parameters or Secrets Manager secrets (you create these via AWS CLI before running OpenTofu/Terraform)

## Prerequisites

**Required:**
- OpenTofu/Terraform >= 1.5
- AWS CLI configured with appropriate credentials
- An existing VPC with an Internet Gateway
- A Route53 hosted zone for your domain
- OAuth app credentials (see [Google](/docs/upstream/google/) or [GitHub](/docs/upstream/github/) setup)

**Create Parameters First:**

```bash
aws ssm put-parameter \
  --name /easy-oidc/google-credentials \
  --type SecureString \
  --value '{"client_id":"your-client-id","client_secret":"your-client-secret"}'

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

Alternatively, select `aws-secrets-manager` in the module and create Secrets
Manager secrets:

```bash
# OAuth credentials (replace with your values)
aws secretsmanager create-secret \
  --name easy-oidc-google-credentials \
  --secret-string '{
    "client_id": "your-client-id",
    "client_secret": "your-client-secret"
  }'

# PKCS8 PEM private key (generates RSA-3072 key for the default RS256 algorithm)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 | aws secretsmanager create-secret \
  --name easy-oidc-signing-key \
  --secret-string file:///dev/stdin

# Encryption key
aws secretsmanager create-secret \
  --name easy-oidc-encryption-key \
  --secret-string "$(openssl rand -hex 32)"
```

## Example Deployment

Create a new directory and a `main.tf` file:

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
  vpc_cidr      = "10.0.0.0/16"
  route53_zone  = "example.com"
  oidc_hostname = "auth.example.com"

  easy_oidc_config = {
    secrets = {
      signing_key_name    = "/easy-oidc/signing-key"
      encryption_key_name = "/easy-oidc/encryption-key"
    }
    connectors = {
      google = {
        type               = "google"
        display_name       = "Google"
        credentials_secret = "/easy-oidc/google-credentials"
      }
    }
    default_redirect_uris = ["http://localhost:8000"]
    groups_overrides = {
      prod-groups = {
        "demo@example.com" = ["prod-admins", "devs"]
      }
    }
    clients = {
      kubelogin-prod = {
        groups_override = "prod-groups"
      }
    }
  }
}

provider "aws" {
  region = local.region
}

# VPC with dual-stack support
resource "aws_vpc" "main" {
  cidr_block                       = local.vpc_cidr
  assign_generated_ipv6_cidr_block = true
  enable_dns_hostnames             = true
  enable_dns_support               = true
  
  tags = {
    Name = "easy-oidc-vpc"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  
  tags = {
    Name = "easy-oidc-igw"
  }
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
  
  tags = {
    Name = "easy-oidc-rt"
  }
}

resource "aws_route_table_association" "main" {
  subnet_id      = module.easy_oidc.subnet_id
  route_table_id = aws_route_table.main.id
}

# Deploy easy-oidc
module "easy_oidc" {
  source = "easy-oidc/easy-oidc/aws"

  vpc_id           = aws_vpc.main.id
  oidc_addr        = local.oidc_hostname
  easy_oidc_config = local.easy_oidc_config
}

# DNS records (required for Let's Encrypt TLS)
data "aws_route53_zone" "main" {
  name = local.route53_zone
}

resource "aws_route53_record" "oidc_dns_a" {
  count   = module.easy_oidc.enable_ipv4 ? 1 : 0
  zone_id = data.aws_route53_zone.main.zone_id
  name    = local.oidc_hostname
  type    = "A"
  ttl     = 300
  records = [module.easy_oidc.public_ipv4]
}

resource "aws_route53_record" "oidc_dns_aaaa" {
  zone_id = data.aws_route53_zone.main.zone_id
  name    = local.oidc_hostname
  type    = "AAAA"
  ttl     = 300
  records = [module.easy_oidc.public_ipv6]
}
```

## Deploy

```bash
tofu init
tofu plan
tofu apply
```

After deployment completes, OpenTofu/Terraform will output the issuer URL and instance details.

## Verify Deployment

1. **Check DNS propagation**:

```bash
dig auth.example.com A
dig auth.example.com AAAA
```

2. **Test OIDC discovery endpoint**:

```bash
curl https://auth.example.com/.well-known/openid-configuration
```

You should see a JSON response with the OIDC configuration.

3. **Test authentication** (see [kubelogin guide](/docs/kubelogin/)):

```bash
kubectl oidc-login setup \
  --oidc-issuer-url=https://auth.example.com \
  --oidc-client-id=kubelogin-prod \
  --oidc-use-pkce
```

## Configuration boundaries

The module owns infrastructure and injects `issuer_url`, `http_listen_addr`,
`state_database`, `secrets.provider`, and `secrets.aws_region`. Put the
remaining Easy OIDC settings under `easy_oidc_config`. The module derives
least-privilege IAM resources from every parameter or secret referenced by
that object.

Use the module's [complete input reference](https://github.com/easy-oidc/terraform-aws-easy-oidc#variables)
for networking, KMS, SSH, tagging, and version controls. See the
[application configuration reference](/docs/config/) for connectors, secrets,
email verification, clients, groups, and templates.

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
- Check `/var/log/caddy.log` on the instance for errors

**OAuth callback errors**:
- Verify each OAuth app redirect URI matches `https://auth.example.com/callback/<connector-id>`
- Check Easy OIDC logs: `journalctl -u easy-oidc -f`

**Secrets Manager errors**:
- Verify IAM role has `secretsmanager:GetSecretValue` permission
- Check secret names match OpenTofu/Terraform configuration

See [Troubleshooting](/docs/troubleshooting/) for more common issues.

## Next Steps

- [Configure Kubernetes integration](/docs/kubernetes/)
- [Set up kubelogin for authentication](/docs/kubelogin/)
- [Configure additional clients and groups](/docs/config/)
