---
draft: false
title: 'GitHub Upstream Auth'
linkTitle: "GitHub"
---

This guide shows you how to create a GitHub OAuth application for use with Easy OIDC.

## Prerequisites

- A GitHub account (personal or organization)
- Admin access to create OAuth applications

## Step 1: Create a GitHub OAuth App

1. Go to [GitHub Settings](https://github.com/settings/developers)
2. In the left sidebar, click **OAuth Apps**
3. Click **New OAuth App** (or **Register a new application**)

## Step 2: Configure the OAuth App

Fill in the application details:

- **Application name**: `Easy OIDC`
- **Homepage URL**: `https://auth.example.com`
  - Replace `auth.example.com` with your actual OIDC hostname
- **Application description** (optional): `OIDC provider for Kubernetes authentication`
- **Authorization callback URL**: `https://auth.example.com/callback/github`
  - Replace `auth.example.com` with your actual OIDC hostname
  - Replace `github` when your configured connector ID is different

Click **Register application**.

## Step 3: Generate a Client Secret

After creating the OAuth app, GitHub will show you the **Client ID**.

1. Click **Generate a new client secret**
2. Copy the generated secret immediately—you won't be able to see it again

You should now have:

- **Client ID**: `Iv1.abc123def456`
- **Client Secret**: `abc123def456789...` (long string)

**Important**: Copy these values now—you'll need them in the next step.

## Step 4: Store Secrets in AWS Secrets Manager

Use the AWS CLI to store your GitHub OAuth credentials and a random encryption
master key. Easy OIDC uses the encryption key to protect stateless identity
selection data.

```bash
aws secretsmanager create-secret \
  --name easy-oidc-github-credentials \
  --secret-string '{
    "client_id": "Iv1.abc123def456",
    "client_secret": "abc123def456789..."
  }'

aws secretsmanager create-secret \
  --name easy-oidc-encryption-key \
  --secret-string "$(openssl rand -hex 32)"
```

Replace the `client_id` and `client_secret` values with your actual credentials from Step 3.
Set `secrets.encryption_key_name` to `easy-oidc-encryption-key` in the Easy OIDC
configuration. See the [configuration reference](/docs/config/) for other
supported secrets providers.

## Organization OAuth Apps (Alternative)

If you're using GitHub Organizations, you can create an organization-owned OAuth app:

1. Go to your organization: `https://github.com/organizations/YOUR_ORG/settings/applications`
2. Click **OAuth Apps** → **New OAuth App**
3. Follow the same configuration steps as above

Organization OAuth apps are recommended for teams, as they provide better access control and audit logging.

## GitHub Enterprise

If you're using GitHub Enterprise Server (self-hosted):

1. Follow the same OAuth app creation steps on your GitHub Enterprise instance
2. Set the hostname on that connector:

```jsonc
"connectors": {
  "github": {
    "type": "github",
    "display_name": "GitHub Enterprise",
    "credentials_secret": "easy-oidc-github-credentials",
    "github": {"hostname": "github.yourcompany.com"}
  }
}
```

## Verification

To verify your OAuth app is configured correctly:

1. Note your callback URL: `https://auth.example.com/callback/github` (replace
   `github` with your connector ID)
2. After deploying Easy OIDC using the [AWS](/docs/deploy/aws/) or
   [Google Cloud](https://github.com/easy-oidc/terraform-google-easy-oidc/blob/main/README.md#usage)
   module, test authentication:

```bash
kubectl oidc-login setup \
  --oidc-issuer-url=https://auth.example.com \
  --oidc-client-id=kubelogin-prod \
  --oidc-use-pkce
```

You should be redirected to GitHub's authorization page.

## Important Notes

**Email selection**: Easy OIDC requests the account's email list. If GitHub
returns more than one address, the user chooses which identity to use; primary
and verified status are shown rather than silently selecting an address. An
unverified selection is subject to the configured email-verification policy.
GitHub-generated `users.noreply` addresses are excluded because they cannot
receive verification codes.

**Group Mappings**: GitHub's OAuth flow doesn't provide organization/team membership by default. Easy OIDC requires you to configure static group mappings (see [Configuration Reference](/docs/config/)).

## Next Steps

- [Deploy Easy OIDC to AWS](/docs/deploy/aws/)
- [Configure Kubernetes integration](/docs/kubernetes/)
- [Set up group mappings](/docs/config/)
