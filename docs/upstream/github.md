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

Click **Register application**.

## Step 3: Generate a Client Secret

After creating the OAuth app, GitHub will show you the **Client ID**.

1. Click **Generate a new client secret**
2. Copy the generated secret immediately—you won't be able to see it again

You should now have:

- **Client ID**: `Iv1.abc123def456`
- **Client Secret**: `abc123def456789...` (long string)

**Important**: Copy these values now—you'll need them in the next step.

## Step 4: Store Credentials in AWS Secrets Manager

Use the AWS CLI to store your GitHub OAuth credentials:

```bash
aws secretsmanager create-secret \
  --name easy-oidc-connector-secret \
  --secret-string '{
    "client_id": "Iv1.abc123def456",
    "client_secret": "abc123def456789..."
  }'
```

Replace the `client_id` and `client_secret` values with your actual credentials from Step 3.

## Organization OAuth Apps (Alternative)

If you're using GitHub Organizations, you can create an organization-owned OAuth app:

1. Go to your organization: `https://github.com/organizations/YOUR_ORG/settings/applications`
2. Click **OAuth Apps** → **New OAuth App**
3. Follow the same configuration steps as above

Organization OAuth apps are recommended for teams, as they provide better access control and audit logging.

## GitHub Enterprise

If you're using GitHub Enterprise Server (self-hosted):

1. Follow the same OAuth app creation steps on your GitHub Enterprise instance
2. When configuring Easy OIDC via Terraform, specify your GitHub Enterprise hostname:

```hcl
module "easy_oidc" {
  source = "easy-oidc/easy-oidc/aws"
  
  # ... other config ...
  connector_type            = "github"
  connector_github_hostname = "github.yourcompany.com"
}
```

## Verification

To verify your OAuth app is configured correctly:

1. Note your callback URL: `https://auth.example.com/callback/github`
2. After deploying Easy OIDC (see [Deploy to AWS](/docs/deploy/aws/)), test authentication:

```bash
kubectl oidc-login setup \
  --oidc-issuer-url=https://auth.example.com \
  --oidc-client-id=kubelogin-prod \
  --oidc-use-pkce
```

You should be redirected to GitHub's authorization page.

## Important Notes

**Email Privacy**: If users have enabled email privacy in their GitHub settings, their primary email may not be accessible. Easy OIDC uses the primary verified email from GitHub for authentication.

**Group Mappings**: GitHub's OAuth flow doesn't provide organization/team membership by default. Easy OIDC requires you to configure static group mappings (see [Configuration Reference](/docs/config/)).

## Next Steps

- [Deploy Easy OIDC to AWS](/docs/deploy/aws/)
- [Configure Kubernetes integration](/docs/kubernetes/)
- [Set up group mappings](/docs/config/)
