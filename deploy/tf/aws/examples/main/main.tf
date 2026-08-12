# Truster <https://truster.dev>
# Copyright The Truster Authors
# SPDX-License-Identifier: Apache-2.0

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
  truster_config = {
    secrets = {
      signing_key_name    = "/truster/signing-key"
      encryption_key_name = "/truster/encryption-key"
    }
    user_login_connectors = {
      google = {
        type               = "google"
        display_name       = "Google"
        credentials_secret = "/truster/google-credentials"
      }
    }
    static_policy = {
      user_group_mappings = {
        prod-groups = {
          "demo@example.com" = ["prod-admins", "devs"]
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
  # SSH configuration - setting a public key path will enable SSH access, null to disable
  ssh_public_key_path    = null # e.g., "~/.ssh/id_rsa.pub"
  ssh_allowed_cidrs_ipv4 = []   # e.g., ["1.2.3.4/32"]
  ssh_allowed_cidrs_ipv6 = []   # e.g., ["2001:db8::/64"]
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
    Name = "truster-vpc"
  }
}
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "truster-igw"
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
    Name = "truster-rt"
  }
}
resource "aws_route_table_association" "main" {
  subnet_id      = module.truster.subnet_id
  route_table_id = aws_route_table.main.id
}

# SSH key pair for instance access (enabled if ssh_public_key_path is set)
resource "aws_key_pair" "truster" {
  count = local.ssh_public_key_path != null ? 1 : 0

  key_name   = "truster-ssh"
  public_key = local.ssh_public_key_path != null ? file(local.ssh_public_key_path) : ""
}

# Deploy truster
module "truster" {
  # source = "truster/truster/aws"
  source = "../../"

  vpc_id         = aws_vpc.main.id
  oidc_addr      = local.oidc_hostname
  truster_config = local.truster_config

  # SSH access (enabled if ssh_public_key_path is set)
  ssh_key_name           = local.ssh_public_key_path != null ? aws_key_pair.truster[0].key_name : null
  ssh_allowed_cidrs_ipv4 = local.ssh_public_key_path != null ? local.ssh_allowed_cidrs_ipv4 : null
  ssh_allowed_cidrs_ipv6 = local.ssh_public_key_path != null ? local.ssh_allowed_cidrs_ipv6 : null
}

# DNS records (required for Caddy LetsEncrypt TLS to work - replace with your Route53 zone)
data "aws_route53_zone" "main" {
  name = local.route53_zone
}

resource "aws_route53_record" "oidc_dns_a" {
  count   = module.truster.enable_ipv4 ? 1 : 0
  zone_id = data.aws_route53_zone.main.zone_id
  name    = local.oidc_hostname
  type    = "A"
  ttl     = 300
  records = [module.truster.public_ipv4]
}

resource "aws_route53_record" "oidc_dns_aaaa" {
  zone_id = data.aws_route53_zone.main.zone_id
  name    = local.oidc_hostname
  type    = "AAAA"
  ttl     = 300
  records = [module.truster.public_ipv6]
}
