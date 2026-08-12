---
draft: false
title: 'Google Upstream Auth'
linkTitle: "Google"
---

This guide connects Google as a sign-in provider. Google verifies the user's
Google account; Truster then decides whether to accept that identity and what
downstream identity and groups to issue.

## Prerequisites

- A Google account (Google Workspace or personal Gmail)
- Admin access to create OAuth applications

## 1. Create a Google project

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Click **Select a project** → **New Project**
3. Enter a project name (e.g., `truster`)
4. Click **Create**

## 2. Configure the OAuth consent screen

1. In the Google Cloud Console, navigate to **APIs & Services** → **OAuth consent screen**
2. Select **Internal** if you have a Google Workspace account (recommended), or **External** for personal Gmail
3. Click **Create**
4. Fill in the required fields:
   - **App name**: `Truster`
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

## 3. Create OAuth credentials

1. Navigate to **APIs & Services** → **Credentials**
2. Click **Create Credentials** → **OAuth client ID**
3. Select **Application type**: **Web application**
4. Enter a **Name**: `Truster`
5. Under **Authorized redirect URIs**, click **Add URI**
6. Add the callback URL: `https://auth.example.com/callback/google`
   - Replace `auth.example.com` with your actual OIDC hostname
   - Replace `google` when your configured connector ID is different
7. Click **Create**

The callback URL is where Google returns the browser after sign-in. It must
exactly match the public Truster URL and connector ID.

## 4. Store the client ID and secret

Google displays two credentials:

- **Client ID**: `123456789-abcdefghijklmnop.apps.googleusercontent.com`
- **Client Secret**: `GOCSPX-xxxxxxxxxxxxxxxxxxxx`

The client ID identifies Truster to Google. The client secret proves that
Truster is that registered application, so do not put it in source control.
Store both values using the secret provider for your chosen deployment, then
reference that credential from the connector. See the [configuration
reference](/docs/config/) and your [deployment documentation](/docs/deploy/).

## Optional: Hint a Google Workspace Domain

If you're using Google Workspace, you can hint your organization's domain in
Google's account chooser:

1. Set `google.hd` on that connector:

```jsonc
"user_login_connectors": {
  "google": {
    "type": "google",
    "display_name": "Google",
    "credentials_secret": "truster-google-credentials",
    "google": {"hd": "example.com"}
  }
}
```

The `hd` setting only improves Google's account chooser; it is not an access
control. Google confirms the account, but Truster's policy determines whether
to accept it. Configure allowed users and groups in the [configuration
reference](/docs/config/).

Disabling this connector blocks Google sign-in through this route, but does not
necessarily block the same person or email address through another enabled
connector.

## Verification

To verify your OAuth app is configured correctly:

1. Note your redirect URI: `https://auth.example.com/callback/google` (replace
   `google` with your connector ID)
2. After deploying Truster, test authentication:

```bash
kubectl oidc-login setup \
  --oidc-issuer-url=https://auth.example.com \
  --oidc-client-id=kubelogin-prod \
  --oidc-pkce-method=S256
```

You should be redirected to Google's login page.

## Next Steps

- [Configure Truster](/docs/config/)
- [Choose a deployment](/docs/deploy/)
- [Configure Kubernetes integration](/docs/kubernetes/)
