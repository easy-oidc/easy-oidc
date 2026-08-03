---
draft: false
title: 'Getting Started'
linkTitle: 'Getting Started'
weight: 2
---

This guide walks you through setting up Easy OIDC from scratch on AWS. For a
Google Cloud deployment, use the official
[`terraform-google-easy-oidc`](https://github.com/easy-oidc/terraform-google-easy-oidc/blob/main/README.md#usage)
OpenTofu/Terraform module. By the end, you'll have a working OIDC provider for
Kubernetes authentication.

## Prerequisites

Before you begin, you'll need:

- An AWS account with permissions to create EC2 instances, security groups, and Parameter Store parameters
- A domain name with Route53 DNS (e.g., `example.com`)
- OpenTofu/Terraform installed locally
- A Kubernetes cluster (for testing the integration)
- An account with each upstream provider you want to configure

## Overview

Setting up Easy OIDC involves four main steps:

1. **Create one or more upstream OAuth apps**
2. **Store secrets** in AWS Systems Manager Parameter Store
3. **Deploy Easy OIDC** using OpenTofu/Terraform
4. **Configure Kubernetes** to use your OIDC provider

Let's walk through each step.

## Step 1: Create an OAuth App

Choose one or more upstream identity providers:

- [Google OAuth Setup](/docs/upstream/google/)
- [GitHub OAuth Setup](/docs/upstream/github/)

Follow the guide to create an OAuth application and note down your `client_id` and `client_secret`.

## Step 2: Store Secrets in AWS Parameter Store

Parameter Store is the AWS module's default. Create encrypted parameters for
the connector credentials, signing key, and encryption key:

```bash
aws ssm put-parameter \
  --name /easy-oidc/google-credentials \
  --type SecureString \
  --value '{"client_id":"your-client-id-here","client_secret":"your-client-secret-here"}'

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

**OAuth credentials** (use values from Step 1):

```bash
aws secretsmanager create-secret \
  --name easy-oidc-google-credentials \
  --secret-string '{
    "client_id": "your-client-id-here",
    "client_secret": "your-client-secret-here"
  }'
```

**PKCS8 PEM private key** (generates an RSA-3072 key for the default RS256 algorithm):

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 | aws secretsmanager create-secret \
  --name easy-oidc-signing-key \
  --secret-string file:///dev/stdin
```

**Encryption key**:

```bash
aws secretsmanager create-secret \
  --name easy-oidc-encryption-key \
  --secret-string "$(openssl rand -hex 32)"
```

## Step 3: Deploy Easy OIDC

Create a new directory for your OpenTofu/Terraform configuration:

```bash
mkdir easy-oidc-deployment
cd easy-oidc-deployment
```

Create `main.tf` with the following content (replace values marked with `YOUR_*`):

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
  route53_zone  = "example.com"           # YOUR_DOMAIN
  oidc_hostname = "auth.example.com"      # YOUR_OIDC_HOSTNAME
}

provider "aws" {
  region = local.region
}

# Create VPC with dual-stack networking
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

resource "aws_route_table_association" "main" {
  subnet_id      = module.easy_oidc.subnet_id
  route_table_id = aws_route_table.main.id
}

# Deploy easy-oidc
module "easy_oidc" {
  source = "easy-oidc/easy-oidc/aws"

  vpc_id    = aws_vpc.main.id
  oidc_addr = local.oidc_hostname

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
      default_redirect_uris = ["http://localhost:8000"]
      user_group_mappings = {
        prod-groups = {
          "alice@example.com" = ["cluster-admins", "developers"]
        }
      }
      clients = {
        kubelogin-prod = {
          user_group_mapping = "prod-groups"
        }
      }
    }
  }
}

# Configure DNS records
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

Deploy the infrastructure:

```bash
tofu init
tofu plan
tofu apply
```

After deployment completes, note the output `issuer_url` (e.g., `https://auth.example.com`).

The module's infrastructure inputs and `easy_oidc_config` boundary are documented
in its [complete input reference](https://github.com/easy-oidc/terraform-aws-easy-oidc#variables).
Application settings remain documented in the [configuration reference](/docs/config/).

## Step 4: Configure Kubernetes

Follow the [Kubernetes Integration guide](/docs/kubernetes/) to configure your cluster to use Easy OIDC.

## Step 5: Test Authentication

Install kubelogin:

```bash
# macOS
brew install int128/kubelogin/kubelogin

# Linux
# See https://github.com/int128/kubelogin/releases
```

Test the login flow:

```bash
kubectl oidc-login setup \
  --oidc-issuer-url=https://auth.example.com \
  --oidc-client-id=kubelogin-prod \
  --oidc-use-pkce
```

This will open your browser to complete authentication. If successful, you'll see your ID token claims including your email and groups.

## Next Steps

- [Configure additional clients](/docs/config/)
- [Add more group mappings](/docs/config/)
- [Set up RBAC in Kubernetes](/docs/kubernetes/)
- [Troubleshoot issues](/docs/troubleshooting/)
