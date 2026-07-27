---
draft: false
title: 'Configuration Reference'
linkTitle: 'Configuration'
weight: 7
---

This page details all configuration options for Easy OIDC when deployed via Terraform.

## Overview

Easy OIDC configuration is specified through Terraform module variables, which are then rendered into a JSONC configuration file on the EC2 instance.

## Terraform Module Variables

### Required Variables

#### `vpc_id`
- **Type**: `string`
- **Description**: VPC ID where Easy OIDC will be deployed
- **Example**: `"vpc-0123456789abcdef0"`

#### `oidc_addr`
- **Type**: `string`
- **Description**: OIDC server hostname (used for issuer URL and Caddy configuration)
- **Example**: `"auth.example.com"`
- **Note**: Do not include `https://` prefix

#### `connector_type`
- **Type**: `string`
- **Description**: Upstream identity provider type
- **Allowed values**: `"google"`, `"github"`
- **Example**: `"google"`

#### `connector_client_secret_arn`
- **Type**: `string`
- **Description**: ARN of the AWS Secrets Manager secret containing OAuth client credentials
- **Example**: `"arn:aws:secretsmanager:us-east-1:123456789012:secret:easy-oidc-connector-secret-AbCdEf"`
- **Secret format**:
  ```json
  {
    "client_id": "your-client-id",
    "client_secret": "your-client-secret"
  }
  ```

#### `clients`
- **Type**: `map(object)`
- **Description**: Map of OIDC client configurations, keyed by client ID
- **Example**:
  ```hcl
  clients = {
    kubelogin-prod = {
      redirect_uris   = ["http://localhost:8000"]
      groups_override = "prod-groups"
    }
    kubelogin-dev = {
      # Uses default_redirect_uris
      # No groups_override: uses upstream IdP groups (empty by default)
    }
  }
  ```

### Optional Variables

#### `subnet_id`
- **Type**: `string`
- **Default**: `null` (auto-created)
- **Description**: Subnet ID for the EC2 instance. If not provided, a new subnet with dual-stack support is created
- **Example**: `"subnet-0123456789abcdef0"`

#### `signing_key_secret_arn`
- **Type**: `string`
- **Default**: `null`
- **Description**: ARN of the AWS Secrets Manager secret containing a PKCS8 PEM private key compatible with `signing_algorithm`
- **Example**: `"arn:aws:secretsmanager:us-east-1:123456789012:secret:easy-oidc-signing-key-XyZ123"`
- **Recommendation**: Create manually to control key lifecycle

#### `signing_algorithm`
- **Type**: `string`
- **Default**: `"RS256"`
- **Allowed values**: `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`, `PS256`, `PS384`, `PS512`, `EdDSA`
- **Description**: JWT signing algorithm. Kubernetes accepts RS256 by default; other Kubernetes-supported algorithms require matching API server configuration. EdDSA is supported by Easy OIDC but not Kubernetes.

#### `default_redirect_uris`
- **Type**: `list(string)`
- **Default**: `["http://localhost:8000"]`
- **Description**: Default redirect URIs used by clients that don't specify their own
- **Example**: `["http://localhost:8000", "http://localhost:18000"]`

#### `groups_overrides`
- **Type**: `map(map(list(string)))`
- **Default**: `{}`
- **Description**: Named sets of email-to-groups mappings
- **Example**:
  ```hcl
  groups_overrides = {
    prod-groups = {
      "alice@example.com" = ["cluster-admins", "developers"]
      "bob@example.com"   = ["developers"]
    }
    staging-groups = {
      "alice@example.com" = ["staging-admins"]
      "charlie@example.com" = ["qa-team"]
    }
  }
  ```

#### `enable_ipv4`
- **Type**: `bool`
- **Default**: `true`
- **Description**: Enable IPv4 support. Set to `false` for IPv6-only deployments
- **Example**: `false`

#### `instance_type`
- **Type**: `string`
- **Default**: `"t4g.nano"`
- **Description**: EC2 instance type. Must be ARM64-compatible
- **Example**: `"t4g.micro"`

#### `allowed_cidrs_ipv4`
- **Type**: `list(string)`
- **Default**: `["0.0.0.0/0"]`
- **Description**: IPv4 CIDRs allowed to access HTTP/HTTPS
- **Example**: `["10.0.0.0/8", "172.16.0.0/12"]`
- **Note**: Ignored if `enable_ipv4 = false`

#### `allowed_cidrs_ipv6`
- **Type**: `list(string)`
- **Default**: `["::/0"]`
- **Description**: IPv6 CIDRs allowed to access HTTP/HTTPS
- **Example**: `["2001:db8::/32"]`

#### `connector_hosted_domain`
- **Type**: `string`
- **Default**: `null`
- **Description**: Google Workspace hosted domain restriction (Google only)
- **Example**: `"example.com"`
- **Effect**: Only users with `@example.com` emails can authenticate

#### `connector_github_hostname`
- **Type**: `string`
- **Default**: `"github.com"`
- **Description**: GitHub hostname (for GitHub Enterprise Server)
- **Example**: `"github.yourcompany.com"`

#### `easy_oidc_version`
- **Type**: `string`
- **Default**: `"latest"`
- **Description**: Easy OIDC version to install
- **Example**: `"v1.0.0"`

#### `caddy_version`
- **Type**: `string`
- **Default**: `"latest"`
- **Description**: Caddy version to install
- **Example**: `"2.7.6"`

#### `kms_key_id`
- **Type**: `string`
- **Default**: `null` (uses AWS managed key)
- **Description**: KMS key ID or ARN for EBS encryption
- **Example**: `"arn:aws:kms:us-east-1:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef"`

#### `ssh_key_name`
- **Type**: `string`
- **Default**: `null`
- **Description**: EC2 key pair name for SSH access
- **Example**: `"my-ssh-key"`

#### `ssh_allowed_cidrs_ipv4`
- **Type**: `list(string)`
- **Default**: `null`
- **Description**: IPv4 CIDRs allowed to SSH (requires `ssh_key_name`)
- **Example**: `["1.2.3.4/32"]`

#### `ssh_allowed_cidrs_ipv6`
- **Type**: `list(string)`
- **Default**: `null`
- **Description**: IPv6 CIDRs allowed to SSH (requires `ssh_key_name`)
- **Example**: `["2001:db8::1/128"]`

#### `name_prefix`
- **Type**: `string`
- **Default**: `"easy-oidc"`
- **Description**: Prefix for resource names
- **Example**: `"my-oidc"`

#### `tags`
- **Type**: `map(string)`
- **Default**: `{}`
- **Description**: Additional tags to apply to all resources
- **Example**: `{ Environment = "production", Team = "platform" }`

## Client Configuration

Each client in the `clients` map represents an OIDC client application (e.g., kubectl).

### Client Object Structure

```hcl
clients = {
  "<client-id>" = {
    redirect_uris   = ["http://localhost:8000"]  # Optional
    groups_override = "prod-groups"               # Optional
  }
}
```

#### `redirect_uris` (optional)
- **Type**: `list(string)`
- **Default**: Uses `default_redirect_uris`
- **Description**: Allowed redirect URIs for this client
- **Example**: `["http://localhost:8000", "http://localhost:18000"]`

#### `groups_override` (optional)
- **Type**: `string`
- **Default**: `null` (no group override, groups claim is empty)
- **Description**: Reference to a named group override in `groups_overrides`
- **Example**: `"prod-groups"`

## Group Resolution Logic

For a given `client_id` and authenticated `email`:

1. **Normalize email** to lowercase
2. **If `groups_override` is set** for the client:
   - Look up `groups_overrides[override_name][email]`
   - If found, use those groups
   - If not found, return empty array `[]`
3. **If `groups_override` is not set**:
   - Return empty array `[]`
4. **Deduplicate** groups and include in ID token `groups` claim

### Example

```hcl
groups_overrides = {
  prod-groups = {
    "alice@example.com" = ["admins", "devs"]
    "bob@example.com"   = ["devs"]
  }
}

clients = {
  kubelogin-prod = {
    groups_override = "prod-groups"
  }
  kubelogin-dev = {
    # No groups_override
  }
}
```

**Authentication scenarios:**

| Client ID | Email | Groups Claim |
|-----------|-------|--------------|
| `kubelogin-prod` | `alice@example.com` | `["admins", "devs"]` |
| `kubelogin-prod` | `bob@example.com` | `["devs"]` |
| `kubelogin-prod` | `charlie@example.com` | `[]` (not in prod-groups) |
| `kubelogin-dev` | `alice@example.com` | `[]` (no override configured) |

## ID Token Claims

Tokens issued by Easy OIDC include:

```json
{
  "iss": "https://auth.example.com",
  "aud": "kubelogin-prod",
  "sub": "alice@example.com",
  "email": "alice@example.com",
  "email_verified": true,
  "preferred_username": "alice",
  "groups": ["admins", "devs"],
  "iat": 1234567890,
  "exp": 1234571490
}
```

**Claim descriptions:**
- `iss`: Issuer URL (your Easy OIDC server)
- `aud`: Audience (client ID)
- `sub`: Subject (user's email)
- `email`: User's verified email from Google/GitHub
- `email_verified`: Always `true` (Google/GitHub verifies emails)
- `preferred_username`: Local part of email (before `@`)
- `groups`: List of groups from static mappings
- `iat`: Issued at (Unix timestamp)
- `exp`: Expiration (Unix timestamp, typically `iat + 1 hour`)

## Example: Multi-Cluster Setup

Deploy Easy OIDC for three environments with different group mappings:

```hcl
module "easy_oidc" {
  source = "easy-oidc/easy-oidc/aws"

  vpc_id                      = aws_vpc.main.id
  oidc_addr                   = "auth.example.com"
  connector_type              = "google"
  connector_client_secret_arn = data.aws_secretsmanager_secret.connector.arn
  signing_key_secret_arn      = data.aws_secretsmanager_secret.signing_key.arn

  default_redirect_uris = ["http://localhost:8000"]

  groups_overrides = {
    prod-groups = {
      "alice@example.com" = ["cluster-admins"]
      "bob@example.com"   = ["developers"]
    }
    staging-groups = {
      "alice@example.com" = ["cluster-admins"]
      "bob@example.com"   = ["cluster-admins", "developers"]
      "charlie@example.com" = ["qa-team"]
    }
    dev-groups = {
      "alice@example.com" = ["cluster-admins"]
      "bob@example.com"   = ["cluster-admins"]
      "charlie@example.com" = ["cluster-admins"]
    }
  }

  clients = {
    kubelogin-prod = {
      groups_override = "prod-groups"
    }
    kubelogin-staging = {
      groups_override = "staging-groups"
    }
    kubelogin-dev = {
      groups_override = "dev-groups"
    }
  }
}
```

Configure each Kubernetes cluster with its respective client ID.

## Next Steps

- [Deploy to AWS](/docs/deploy/aws/)
- [Configure Kubernetes](/docs/kubernetes/)
- [Troubleshoot issues](/docs/troubleshooting/)
