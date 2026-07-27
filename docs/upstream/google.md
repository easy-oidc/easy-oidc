---
draft: false
title: 'Google Upstream Auth'
linkTitle: "Google"
---

This guide shows you how to create a Google OAuth application for use with Easy OIDC.

## Prerequisites

- A Google account (Google Workspace or personal Gmail)
- Admin access to create OAuth applications

## Step 1: Create a Google Cloud Project

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Click **Select a project** → **New Project**
3. Enter a project name (e.g., `easy-oidc`)
4. Click **Create**

## Step 2: Configure OAuth Consent Screen

1. In the Google Cloud Console, navigate to **APIs & Services** → **OAuth consent screen**
2. Select **Internal** if you have a Google Workspace account (recommended), or **External** for personal Gmail
3. Click **Create**
4. Fill in the required fields:
   - **App name**: `Easy OIDC`
   - **User support email**: Your email address
   - **Developer contact information**: Your email address
5. Click **Save and Continue**
6. On the **Scopes** page, click **Add or Remove Scopes**
7. Select the following scopes:
   - `openid`
   - `email`
   - `profile`
8. Click **Update** → **Save and Continue**
9. Review and click **Back to Dashboard**

## Step 3: Create OAuth Credentials

1. Navigate to **APIs & Services** → **Credentials**
2. Click **Create Credentials** → **OAuth client ID**
3. Select **Application type**: **Web application**
4. Enter a **Name**: `Easy OIDC`
5. Under **Authorized redirect URIs**, click **Add URI**
6. Add your redirect URI: `https://auth.example.com/callback/google`
   - Replace `auth.example.com` with your actual OIDC hostname
7. Click **Create**

## Step 4: Save Client ID and Secret

After creating the OAuth client, Google will display your credentials:

- **Client ID**: `123456789-abcdefghijklmnop.apps.googleusercontent.com`
- **Client Secret**: `GOCSPX-xxxxxxxxxxxxxxxxxxxx`

**Important**: Copy these values now—you'll need them in the next step.

## Step 5: Store Credentials in AWS Secrets Manager

Use the AWS CLI to store your Google OAuth credentials:

```bash
aws secretsmanager create-secret \
  --name easy-oidc-connector-secret \
  --secret-string '{
    "client_id": "123456789-abcdefghijklmnop.apps.googleusercontent.com",
    "client_secret": "GOCSPX-xxxxxxxxxxxxxxxxxxxx"
  }'
```

Replace the `client_id` and `client_secret` values with your actual credentials from Step 4.

## Optional: Restrict to Google Workspace Domain

If you're using Google Workspace and want to restrict authentication to your organization's domain:

1. When configuring Easy OIDC via Terraform, add the `connector_hosted_domain` variable:

```hcl
module "easy_oidc" {
  source = "easy-oidc/easy-oidc/aws"
  
  # ... other config ...
  connector_type           = "google"
  connector_hosted_domain  = "example.com"  # Your Google Workspace domain
}
```

This ensures only users with `@example.com` email addresses can authenticate.

## Verification

To verify your OAuth app is configured correctly:

1. Note your redirect URI: `https://auth.example.com/callback/google`
2. After deploying Easy OIDC (see [Deploy to AWS](/docs/deploy/aws/)), test authentication:

```bash
kubectl oidc-login setup \
  --oidc-issuer-url=https://auth.example.com \
  --oidc-client-id=kubelogin-prod \
  --oidc-use-pkce
```

You should be redirected to Google's login page.

## Next Steps

- [Deploy Easy OIDC to AWS](/docs/deploy/aws/)
- [Configure Kubernetes integration](/docs/kubernetes/)
