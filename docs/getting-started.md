---
draft: false
title: 'Getting Started'
linkTitle: 'Getting Started'
weight: 2
---

This guide walks you through setting up Easy OIDC from scratch on AWS (support for Google Cloud and Azure are planned). By the end, you'll have a working OIDC provider for Kubernetes authentication.

## Prerequisites

Before you begin, you'll need:

- An AWS account with permissions to create EC2 instances, security groups, and Secrets Manager secrets
- A domain name with Route53 DNS (e.g., `example.com`)
- Terraform or OpenTofu installed locally
- A Kubernetes cluster (for testing the integration)
- A Google or GitHub account for OAuth app creation

## Overview

Setting up Easy OIDC involves four main steps:

1. **Create an OAuth app** in Google or GitHub
2. **Store secrets** in AWS Secrets Manager
3. **Deploy Easy OIDC** using Terraform
4. **Configure Kubernetes** to use your OIDC provider

Let's walk through each step.

## Step 1: Create an OAuth App

Choose your upstream identity provider:

- [Google OAuth Setup](/docs/upstream/google/)
- [GitHub OAuth Setup](/docs/upstream/github/)

Follow the guide to create an OAuth application and note down your `client_id` and `client_secret`.

## Step 2: Store Secrets in AWS Secrets Manager

Create two secrets in AWS Secrets Manager using the AWS CLI:

**OAuth credentials** (use values from Step 1):

```bash
aws secretsmanager create-secret \
  --name easy-oidc-connector-secret \
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

## Step 3: Deploy Easy OIDC

Create a new directory for your Terraform configuration:

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

# Reference secrets created in Step 2
data "aws_secretsmanager_secret" "connector_secret" {
  name = "easy-oidc-connector-secret"
}
data "aws_secretsmanager_secret" "signing_key" {
  name = "easy-oidc-signing-key"
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

  vpc_id                        = aws_vpc.main.id
  oidc_addr                     = local.oidc_hostname
  connector_type                = "google"  # or "github"
  connector_client_secret_arn   = data.aws_secretsmanager_secret.connector_secret.arn
  signing_key_secret_arn        = data.aws_secretsmanager_secret.signing_key.arn
  
  default_redirect_uris = ["http://localhost:8000"]
  
  groups_overrides = {
    prod-groups = {
      "alice@example.com" = ["cluster-admins", "developers"]
    }
  }
  
  clients = {
    kubelogin-prod = {
      groups_override = "prod-groups"
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
terraform init
terraform plan
terraform apply
```

After deployment completes, note the output `issuer_url` (e.g., `https://auth.example.com`).

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
