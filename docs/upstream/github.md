---
draft: false
title: 'GitHub Upstream Auth'
linkTitle: "GitHub"
---

This guide connects GitHub as a sign-in provider. GitHub verifies the user's
GitHub account; Easy OIDC then decides whether to accept that identity and what
downstream identity and groups to issue.

## Prerequisites

- A GitHub account (personal or organization)
- Admin access to create OAuth applications

## 1. Create a GitHub OAuth App

1. Go to [GitHub Settings](https://github.com/settings/developers)
2. In the left sidebar, click **OAuth Apps**
3. Click **New OAuth App** (or **Register a new application**)

## 2. Configure the OAuth App

Fill in the application details:

- **Application name**: `Easy OIDC`
- **Homepage URL**: `https://auth.example.com`
  - Replace `auth.example.com` with your actual OIDC hostname
- **Application description** (optional): `OIDC provider for Kubernetes authentication`
- **Authorization callback URL**: `https://auth.example.com/callback/github`
  - Replace `auth.example.com` with your actual OIDC hostname
  - Replace `github` when your configured connector ID is different

Click **Register application**.

The callback URL is where GitHub returns the browser after sign-in. It must
exactly match the public Easy OIDC URL and connector ID.

## 3. Generate and store the credentials

After creating the OAuth app, GitHub will show you the **Client ID**.

1. Click **Generate a new client secret**
2. Copy the generated secret immediately—you won't be able to see it again

You should now have:

- **Client ID**: `Iv1.abc123def456`
- **Client Secret**: `abc123def456789...` (long string)

The client ID identifies Easy OIDC to GitHub. The client secret proves that
Easy OIDC is that registered application; copy it immediately because GitHub
does not show it again, and do not put it in source control. Store both values
using the secret provider for your chosen deployment, then reference that
credential from the connector. See the [configuration reference](/docs/config/)
and your [deployment documentation](/docs/deploy/).

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
"user_login_connectors": {
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
2. After deploying Easy OIDC, test authentication:

```bash
kubectl oidc-login setup \
  --oidc-issuer-url=https://auth.example.com \
  --oidc-client-id=kubelogin-prod \
  --oidc-pkce-method=S256
```

You should be redirected to GitHub's authorization page.

## Important Notes

**Email selection**: Easy OIDC requests the account's email list. If GitHub
returns more than one address, the user chooses which identity to use; primary
and verified status are shown rather than silently selecting an address. An
unverified selection is subject to the configured email-verification policy.
GitHub-generated `users.noreply` addresses are excluded because they cannot
receive verification codes.

**Identity acceptance**: GitHub confirms the account and email information, but
Easy OIDC's policy determines whether to accept it and which downstream groups
to issue. GitHub's OAuth flow does not provide organization/team membership by
default, so configure group mappings explicitly. Disabling this connector does
not necessarily block the same person or email address through another enabled
connector. See the [configuration reference](/docs/config/).

## Next Steps

- [Configure Easy OIDC](/docs/config/)
- [Choose a deployment](/docs/deploy/)
- [Configure Kubernetes integration](/docs/kubernetes/)
