---
draft: false
title: 'Easy OIDC System Design & Specification'
linkTitle: 'Specification'
weight: 2
---

OIDC is a minimal OIDC provider designed for use with Kubernetes, with Google/GitHub federation, and static group mappings.

## Overview

`easy-oidc` is a lightweight OIDC provider that:
- Delegates authentication to Google or GitHub (no local passwords)
- Maps authenticated emails to Kubernetes groups via static configuration
- Supports Auth Code + PKCE only (public clients, no client secrets)
- Runs as a single binary with all configuration via environment variables
- Designed to run behind Caddy for automatic Let's Encrypt TLS

Terraform modules will be created for AWS, GCP, and Azure. The Go binary fetches secrets from cloud-native secret stores (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault) using official SDKs.

---

## Design Goals

**Included:**
- Authorization Code + PKCE flow only
- Public clients (kubectl/kubelogin/nadrama)
- Google OR GitHub upstream authentication
- Static email → groups mapping (per-cluster + global defaults)
- Minimal infrastructure: single EC2 instance
- No external dependencies beyond upstream IdP
- IPv4/IPv6 dual-stack support (IPv4 can be disabled for IPv6-only)

**Excluded (v1):**
- HA/ASG/load balancers
- Client secrets (only public clients)
- Local password authentication
- Admin UI for mappings
- Dynamic group resolution from upstream IdP (groups default to empty if no static overrides specified)
- Other OAuth2 flows (implicit, client credentials, etc.)

---

## Architecture

```
┌──────────┐                                     ┌─────────────┐
│kubelogin │──── OIDC Auth Code + PKCE ────────▶ │    Caddy    │
└──────────┘         (port 443)                  │ (Let's Enc) │
                                                 └──────┬──────┘
                                                        │ proxy
                                                        │ (127.0.0.1:8080)
                                                 ┌──────▼──────┐
                                                 │  easy-oidc  │◀─── Secrets Manager
                                                 └──────┬──────┘     (startup only)
                                                        │
                                        ┌───────────────┴───────────────┐
                                        │                               │
                                  ┌─────▼─────┐                  ┌──────▼──────┐
                                  │  Google   │                  │   GitHub    │
                                  │   OAuth   │                  │    OAuth    │
                                  └───────────┘                  └─────────────┘
```

**Flow:**
1. Client initiates OIDC login to `https://auth.example.com`
2. Caddy terminates TLS, proxies to `easy-oidc`
3. `easy-oidc` redirects user to Google/GitHub
4. On callback, validates upstream token and extracts verified email
5. Resolves groups from static configuration
6. Issues signed ID token with `groups` claim
7. Kubernetes API server validates token and enforces RBAC

---

## OIDC Endpoints

`easy-oidc` implements a standard OIDC provider:

| Endpoint | Purpose |
|----------|---------|
| `/.well-known/openid-configuration` | Discovery document |
| `/authorize` | Authorization endpoint (redirects to upstream IdP) |
| `/token` | Token endpoint (validates PKCE, issues tokens) |
| `/jwks` | Public signing keys |
| `/userinfo` | UserInfo endpoint |

---

## Configuration

All configuration in a **JSONC file** (parsed with `tidwall/jsonc`), e.g.:

```jsonc
{
  // Core settings
  "issuer_url": "https://auth.example.com",
  "http_listen_addr": "127.0.0.1:8080",
  "data_dir": "/var/lib/easy-oidc",
  "signing_algorithm": "RS256",
  
  // Signing key ID
  "jwks_kid": "key-2024-01",
  
  // Secrets configuration
  "secrets": {
    "provider": "aws",  // "aws", "gcp", "azure", or "env" for local dev
    "signing_key_name": "easy-oidc-signing-key",
    "connector_secret_name": "easy-oidc-connector-secret",
    
    // Azure-specific (only when provider=azure)
    "azure_keyvault_url": "https://my-vault.vault.azure.net/",
    
    // Local development (only when provider=env)
    "signing_key_pem": "-----BEGIN PRIVATE KEY-----...",
    "oauth_client_id": "...",
    "oauth_client_secret": "..."
  },
  
  // Upstream connector
  "connector": {
    "type": "google",  // or "github"
    "client_id": "123456789.apps.googleusercontent.com",
    "redirect_url": "https://auth.example.com/callback/google",
    
    // Optional
    "scopes": ["openid", "email", "profile"],  // defaults per connector type
    
    // Provider-specific options
    "google": {
      "hd": "example.com"  // hosted domain
    },
    "github": {
      "hostname": "github.com"  // for GitHub Enterprise
    }
  },
  
  // Default redirect URIs (used if not specified per client)
  "default_redirect_uris": ["http://localhost:8000"],
  
  // Groups overrides (email → groups mappings)
  // Optional: if not specified per client, uses groups from upstream IdP
  "groups_overrides": {
    "prod-groups": {
      "alice@example.com": ["prod-admins", "devs"],
      "bob@example.com": ["prod-readonly"]
    }
  },
  
  // OIDC clients (key is the client_id)
  "clients": {
    "kubelogin-prod": {
      "redirect_uris": ["http://localhost:8000"],
      "groups_override": "prod-groups"  // optional, omit to use upstream IdP groups
    },
    "kubelogin-dev": {
      // redirect_uris not set: uses default_redirect_uris
      // no groups_override: uses groups from upstream IdP (Google/GitHub)
    }
  }
}
```

**Key rotation:** Update `EASYOIDC_SIGNING_KEY_PEM` and `jwks_kid` in config, then restart.

**Key principles:**
- No key/certificate generation (provided via config)
- Embedded SQLite for OAuth state and authorization code storage (minimal persistent state)
- No HTTP server configuration (runs behind Caddy)

---

## Group Resolution Logic

For a given `client_id` and authenticated `email`:

1. Normalize email to lowercase
2. If `clients[client_id].groups_override` is set:
   - Check `groups_overrides[override_key][email]`
   - If found, use those groups; otherwise return `[]`
3. If `groups_override` is not set:
   - Return `[]` (empty groups)
4. Deduplicate and emit as `groups` claim

---

## ID Token Claims

Issued tokens include:

```json
{
  "iss": "https://auth.example.com",
  "aud": "kubelogin-prod",
  "sub": "alice@example.com",
  "email": "alice@example.com",
  "email_verified": true,
  "preferred_username": "alice",
  "groups": ["prod-admins", "devs"],
  "iat": 1234567890,
  "exp": 1234571490
}
```

---

## PKCE Enforcement

- `/authorize` requires `code_challenge` and `code_challenge_method=S256`
- `/token` requires `code_verifier` matching the challenge
- No fallback to non-PKCE flows

---

## Kubernetes Integration

### API Server Flags

```bash
--oidc-issuer-url=https://auth.example.com
--oidc-client-id=kubelogin-prod
--oidc-username-claim=email
--oidc-groups-claim=groups
```

### kubeconfig Example

```yaml
users:
  - name: oidc-prod
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1
        command: kubelogin
        args:
          - get-token
          - --oidc-issuer-url=https://auth.example.com
          - --oidc-client-id=kubelogin-prod
          - --oidc-extra-scope=email
          - --oidc-extra-scope=groups
```

---

## Terraform Module (`terraform-aws-easy-oidc`)

The companion Terraform module provisions:

### Usage Example

**Pre-requisites: Create secrets in Secrets Manager**

Use AWS CLI to keep secrets out of Terraform state and version control:

**1. OAuth client credentials:**
```bash
# For Google
aws secretsmanager create-secret \
  --name easy-oidc-connector-secret \
  --secret-string '{
    "client_id": "123456789.apps.googleusercontent.com",
    "client_secret": "GOCSPX-xxxxxxxxxxxxxxxxxxxxx"
  }'

# For GitHub
aws secretsmanager create-secret \
  --name easy-oidc-connector-secret \
  --secret-string '{
    "client_id": "Iv1.abc123def456",
    "client_secret": "abc123def456..."
  }'
```

**2. PKCS8 PEM private key (RSA-3072 for the default RS256 algorithm):**
```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 | aws secretsmanager create-secret \
  --name easy-oidc-signing-key \
  --secret-string file:///dev/stdin
```

Then reference them in Terraform:

> **Note:** Terraform will fail if these secrets don't exist. Create them before running `terraform apply`.

**Deploy the module:**
```hcl
# Configuration
locals {
  vpc_cidr      = "10.0.0.0/16"
  oidc_hostname = "auth.example.com"
}

# Reference secrets
data "aws_secretsmanager_secret" "connector_secret" {
  name = "easy-oidc-connector-secret"
}

data "aws_secretsmanager_secret" "signing_key" {
  name = "easy-oidc-signing-key"
}

# Create VPC, IGW, IPv6 egress gateway
resource "aws_vpc" "main" {
  cidr_block                       = local.vpc_cidr
  assign_generated_ipv6_cidr_block = true
  enable_dns_hostnames             = true
  enable_dns_support               = true
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
}

resource "aws_egress_only_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
}

resource "aws_route_table" "main" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  route {
    ipv6_cidr_block        = "::/0"
    egress_only_gateway_id = aws_egress_only_internet_gateway.main.id
  }
}

# Deploy easy-oidc
module "easy_oidc" {
  source = "easy-oidc/easy-oidc/aws"

  region                        = "us-east-1"
  vpc_id                        = aws_vpc.main.id
  oidc_addr                     = local.oidc_hostname
  
  connector_type                = "google"
  connector_client_secret_arn   = data.aws_secretsmanager_secret.connector_secret.arn
  signing_key_secret_arn        = data.aws_secretsmanager_secret.signing_key.arn
  
  default_redirect_uris = ["http://localhost:8000"]
  
  groups_overrides = {
    prod-groups = {
      "alice@example.com" = ["prod-admins", "devs"]
      "bob@example.com"   = ["prod-readonly"]
    }
  }
  
  clients = {
    kubelogin-prod = {
      groups_override = "prod-groups"  # override upstream IdP groups
    }
    kubelogin-dev = {
      # redirect_uris not set: uses default_redirect_uris
      # no groups_override: uses groups from Google/GitHub
    }
  }
  
  # Optional: IPv6-only deployment
  enable_ipv4 = false
}

# Configure DNS records
data "aws_route53_zone" "main" {
  name = "example.com"
}

resource "aws_route53_record" "oidc_a" {
  count   = module.easy_oidc.instance_public_ipv4 != null ? 1 : 0
  zone_id = data.aws_route53_zone.main.zone_id
  name    = local.oidc_hostname
  type    = "A"
  ttl     = 300
  records = [module.easy_oidc.instance_public_ipv4]
}

resource "aws_route53_record" "oidc_aaaa" {
  zone_id = data.aws_route53_zone.main.zone_id
  name    = local.oidc_hostname
  type    = "AAAA"
  ttl     = 300
  records = [module.easy_oidc.instance_public_ipv6]
}
```

### AWS Resources

- **EC2 Instance**: ARM64 (t4g.nano), Ubuntu LTS, dual-stack IPv4/IPv6 or IPv6-only
- **Subnet** (auto-created if not provided): Public subnet with IPv6 CIDR, optional IPv4 CIDR
- **Security Group**: 80/tcp and 443/tcp from configurable CIDRs
- **IAM Role**: Read-only access to Secrets Manager
- **Secrets Manager**: Signing keys + upstream OAuth credentials

### User Data Bootstrap

On instance launch:
1. Download `easy-oidc` and `caddy` ARM64 binaries
2. Render `/etc/easy-oidc/config.jsonc` from Terraform variables
3. Create `/var/lib/easy-oidc` directory with proper permissions
4. Install systemd units for `easy-oidc` and `caddy`
5. Start services (easy-oidc fetches secrets at startup using AWS SDK)

### Terraform Variables

**Required:**
- `region`, `vpc_id`
- `oidc_addr` (e.g., `auth.example.com` or `auth.example.com:8443`)
- `connector_type` (`google` or `github`)
- `connector_client_secret_arn` (pre-created secret ARN)
- `clients` (map of OIDC client definitions, keyed by client_id)

**Optional:**
- `subnet_id` (auto-created if omitted; requires VPC with IGW, IPv6 egress-only gateway, and route table with default routes configured)
- `enable_ipv4` (default: `true`; set to `false` for IPv6-only)
- `instance_type` (default: `t4g.nano`)
- `signing_key_secret_arn` (recommended to create manually via CLI to keep out of Terraform state)
- `allowed_cidrs_ipv4` (ignored if `enable_ipv4 = false`)
- `allowed_cidrs_ipv6`

### Terraform Outputs

- `issuer_url`
- `client_ids` (list of configured client IDs)
- `instance_id`, `instance_public_ipv4` (null if IPv4 disabled), `instance_public_ipv6`
- `subnet_id` (ID of created or provided subnet)
- `security_group_id`

---

## Security & Operations

**Reboot resilience:**
- Configuration persists in `/etc/easy-oidc/config.jsonc` and `/etc/easy-oidc/env` (reloaded from EBS root volume)
- Systemd auto-restarts services
- OAuth state and authorization codes persist across restarts (SQLite database in `/var/lib/easy-oidc/easy-oidc.db`)
- In-flight login sessions survive restarts

**Instance replacement:**
- Terraform re-provisions with identical config
- Secrets Manager provides keys and credentials
- DNS records updated automatically via Terraform
- Users must re-login; client configs and group mappings unchanged

**Secret management:**
- All secrets created manually via AWS CLI to keep them out of Terraform state
- Signing keys and OAuth credentials stored in Secrets Manager
- Terraform only references secrets by ARN (never contains secret values)
- EC2 IAM role grants read-only access to Secrets Manager (no write)

---

## Development Notes

**Dependencies:**
- `github.com/lestrrat-go/jwx/v2` - JWT/JWK/JWKS handling
- `golang.org/x/oauth2` - OAuth2 client (for Google/GitHub login flow)
- `github.com/tidwall/jsonc` - JSONC config parsing
- `github.com/spf13/cobra` - CLI framework
- `github.com/mattn/go-sqlite3` - Embedded SQLite for OAuth state and authorization code storage
- Standard library `crypto/rsa`, `crypto/ecdsa`, and `crypto/ed25519` for signing
- Cloud SDKs: AWS Secrets Manager, GCP Secret Manager, Azure Key Vault

**Architecture:**
- RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512, and EdDSA token signing; RS256 is the Kubernetes-compatible default
- All HTTP runs on loopback; Caddy handles public TLS
- Embedded SQLite for OAuth state and authorization code storage with replay protection
- ARM64-first design (t4g instances, ARM64 binaries)
