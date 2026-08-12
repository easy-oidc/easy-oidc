# Main Example

This example demonstrates a complete deployment of truster with:

- VPC with dual-stack IPv4/IPv6 networking
- Internet Gateway for bidirectional internet access
- Google OAuth connector
- A `static_policy.user_group_mappings` entry for Kubernetes RBAC
- A static OIDC client that selects the mapping with `user_group_mapping`

## Prerequisites

Create encrypted parameters in AWS Systems Manager Parameter Store:

```bash
# OAuth credentials
aws ssm put-parameter \
  --name /truster/google-credentials \
  --type SecureString \
  --value '{
    "client_id": "123456789.apps.googleusercontent.com",
    "client_secret": "GOCSPX-xxxxxxxxxxxxxxxxxxxxx"
  }'

# PKCS8 PEM private key for the default RS256 algorithm
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 > signing-key.pem
aws ssm put-parameter \
  --name /truster/signing-key \
  --type SecureString \
  --value "$(cat signing-key.pem)"
rm signing-key.pem

# Encryption master key
aws ssm put-parameter \
  --name /truster/encryption-key \
  --type SecureString \
  --value "$(openssl rand -hex 32)"
```

## Usage

```bash
tofu init
tofu plan
tofu apply
```

## Kubernetes Integration

Use the issuer URL and static client IDs from outputs to configure your Kubernetes API server and kubeconfig. The `client_ids` output is empty when clients are supplied only by `policy_database`.
