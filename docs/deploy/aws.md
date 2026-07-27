---
draft: false
title: 'Deploy to AWS using Terraform or OpenTofu'
linkTitle: 'AWS'
---

This guide shows you how to deploy Easy OIDC on AWS using the official Terraform module.

## What Gets Deployed

The `terraform-aws-easy-oidc` module provisions:

- **EC2 Instance**: Single ARM64 instance (t4g.nano by default) running Ubuntu 22.04 LTS
    - **Easy OIDC Binary**: Downloaded and installed via systemd service
    - **Caddy Reverse Proxy**: Provides automatic HTTPS via Let's Encrypt
    - **SQLite Database**: Stored at `/var/lib/easy-oidc/easy-oidc.db` for OAuth state and authorization codes
- **Security Group**: Allows HTTP (80) and HTTPS (443) from configurable CIDRs
- **IAM Role**: Grants read-only access to Secrets Manager for fetching signing keys and OAuth credentials
- **Subnet** (optional): Auto-created with dual-stack IPv4/IPv6 support if not provided

## What You Need to Provide

Before deploying, you must have:

1. **VPC with Internet Gateway**: For outbound connectivity to Google/GitHub OAuth endpoints
2. **Route53 DNS Zone**: For configuring DNS records (required for Let's Encrypt TLS)
3. **Secrets in AWS Secrets Manager**:
   - OAuth client credentials (created via [upstream provider setup](/docs/upstream/))
   - PKCS8 PEM private key compatible with `signing_algorithm` (RSA-3072 for the default RS256 algorithm)

The module **does not** create:
- VPC, Internet Gateway, or Route Table (you create these)
- Route53 DNS records (you create these, pointing to the instance IP)
- Secrets Manager secrets (you create these via AWS CLI before running Terraform)

## Prerequisites

**Required:**
- Terraform >= 1.5 or OpenTofu >= 1.5
- AWS CLI configured with appropriate credentials
- An existing VPC with an Internet Gateway
- A Route53 hosted zone for your domain
- OAuth app credentials (see [Google](/docs/upstream/google/) or [GitHub](/docs/upstream/github/) setup)

**Create Secrets First:**

```bash
# OAuth credentials (replace with your values)
aws secretsmanager create-secret \
  --name easy-oidc-connector-secret \
  --secret-string '{
    "client_id": "your-client-id",
    "client_secret": "your-client-secret"
  }'

# PKCS8 PEM private key (generates RSA-3072 key for the default RS256 algorithm)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 | aws secretsmanager create-secret \
  --name easy-oidc-signing-key \
  --secret-string file:///dev/stdin
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
    kubelogin-dev = {}
  }
}

provider "aws" {
  region = local.region
}

# Reference pre-created secrets
data "aws_secretsmanager_secret" "connector_secret" {
  name = "easy-oidc-connector-secret"
}

data "aws_secretsmanager_secret" "signing_key" {
  name = "easy-oidc-signing-key"
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

  vpc_id                        = aws_vpc.main.id
  oidc_addr                     = local.oidc_hostname
  connector_type                = "google"  # or "github"
  connector_client_secret_arn   = data.aws_secretsmanager_secret.connector_secret.arn
  signing_key_secret_arn        = data.aws_secretsmanager_secret.signing_key.arn
  
  default_redirect_uris = local.default_redirect_uris
  groups_overrides      = local.groups_overrides
  clients               = local.clients
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
terraform init
terraform plan
terraform apply
```

After deployment completes, Terraform will output the issuer URL and instance details.

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

## Configuration Options

### Key Terraform Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `vpc_id` | VPC ID (required) | - |
| `oidc_addr` | OIDC server hostname (required) | - |
| `connector_type` | Upstream IdP: `google` or `github` (required) | - |
| `connector_client_secret_arn` | Secrets Manager ARN for OAuth credentials (required) | - |
| `clients` | Map of OIDC client configurations (required) | - |
| `subnet_id` | Subnet ID (auto-created if omitted) | `null` |
| `signing_key_secret_arn` | Secrets Manager ARN for a PKCS8 PEM private key compatible with `signing_algorithm` | `null` |
| `signing_algorithm` | JWT signing algorithm | `"RS256"` |
| `default_redirect_uris` | Default redirect URIs for clients | `["http://localhost:8000"]` |
| `groups_overrides` | Static group mappings (email → groups) | `{}` |
| `enable_ipv4` | Enable IPv4 support | `true` |
| `instance_type` | EC2 instance type | `"t4g.nano"` |
| `allowed_cidrs_ipv4` | Allowed IPv4 CIDRs for HTTP/HTTPS | `["0.0.0.0/0"]` |
| `allowed_cidrs_ipv6` | Allowed IPv6 CIDRs for HTTP/HTTPS | `["::/0"]` |
| `connector_hosted_domain` | Google Workspace domain restriction | `null` |
| `connector_github_hostname` | GitHub Enterprise hostname | `"github.com"` |

See the [Configuration Reference](/docs/config/) for detailed explanation of client and group configurations.

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
- Terraform will re-provision with identical configuration
- DNS records update automatically
- Users must re-login (existing tokens remain valid until expiry)

**Updating Easy OIDC version**:

```hcl
module "easy_oidc" {
  source = "easy-oidc/easy-oidc/aws"
  
  # ... other variables ...
  easy_oidc_version = "v1.2.3"  # Specify version
}
```

Then run `terraform apply` to trigger instance replacement.

## Troubleshooting

**Let's Encrypt certificate errors**:
- Verify DNS records point to the correct instance IP
- Ensure security group allows incoming HTTP (80) and HTTPS (443)
- Check `/var/log/caddy.log` on the instance for errors

**OAuth callback errors**:
- Verify redirect URI in Google/GitHub OAuth app matches `https://auth.example.com/callback/{google|github}`
- Check Easy OIDC logs: `journalctl -u easy-oidc -f`

**Secrets Manager errors**:
- Verify IAM role has `secretsmanager:GetSecretValue` permission
- Check secret names match Terraform configuration

See [Troubleshooting](/docs/troubleshooting/) for more common issues.

## Next Steps

- [Configure Kubernetes integration](/docs/kubernetes/)
- [Set up kubelogin for authentication](/docs/kubelogin/)
- [Configure additional clients and groups](/docs/config/)
