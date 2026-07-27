---
draft: false
title: 'Using kubelogin for kubectl Authentication'
linkTitle: 'kubelogin'
weight: 6
---

kubelogin is a kubectl plugin that handles OIDC authentication automatically. Instead of manually managing tokens, kubelogin opens your browser to authenticate and caches the token locally.

## What is kubelogin?

[kubelogin](https://github.com/int128/kubelogin) (also known as `kubectl oidc-login`) is a credential plugin for kubectl that:
- Implements the Kubernetes exec credential plugin API
- Handles the OIDC authentication flow (Authorization Code + PKCE)
- Caches tokens locally to avoid repeated logins
- Automatically refreshes expired tokens

When you run `kubectl get pods`, kubelogin:
1. Checks for a cached, valid token
2. If the token is missing or expired, opens a browser for authentication
3. Handles the OAuth2/OIDC flow with Easy OIDC
4. Returns the ID token to kubectl
5. kubectl includes the token in API requests

## Installation

### macOS

```bash
brew install int128/kubelogin/kubelogin
```

### Linux

Download the latest release from [GitHub](https://github.com/int128/kubelogin/releases):

```bash
# Example for Linux amd64
curl -LO https://github.com/int128/kubelogin/releases/latest/download/kubelogin_linux_amd64.zip
unzip kubelogin_linux_amd64.zip
sudo mv kubelogin /usr/local/bin/
```

### Windows

```powershell
# Using Chocolatey
choco install kubelogin

# Or download from GitHub releases
```

### Verify Installation

```bash
kubelogin --version
```

## Configure kubeconfig

Add a user to your kubeconfig that uses kubelogin:

```yaml
apiVersion: v1
kind: Config
users:
- name: oidc-user
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: kubelogin
      args:
      - get-token
      - --oidc-issuer-url=https://auth.example.com
      - --oidc-client-id=kubelogin-prod
      - --oidc-use-pkce
      interactiveMode: IfAvailable
      provideClusterInfo: false
```

Then create a context that uses this user:

```yaml
contexts:
- context:
    cluster: my-cluster
    user: oidc-user
  name: my-cluster-oidc
current-context: my-cluster-oidc
```

## Test Authentication

Run the setup wizard to test authentication:

```bash
kubectl oidc-login setup \
  --oidc-issuer-url=https://auth.example.com \
  --oidc-client-id=kubelogin-prod \
  --oidc-use-pkce
```

This will:
1. Open your browser
2. Redirect to Google or GitHub (depending on your Easy OIDC configuration)
3. After successful login, display your ID token and claims

**Expected output:**

```
Opening in existing browser session.
authentication in progress...

## 2. Verify authentication

You got a token with the following claims:

{
  "iss": "https://auth.example.com",
  "sub": "alice@example.com",
  "aud": "kubelogin-prod",
  "email": "alice@example.com",
  "email_verified": true,
  "groups": ["prod-admins", "devs"],
  "exp": 1234567890,
  "iat": 1234564290
}

## 3. Bind a cluster role

kubectl create clusterrolebinding oidc-cluster-admin \
  --clusterrole=cluster-admin \
  --user='https://auth.example.com#alice@example.com'
```

## Using kubectl with OIDC

Once configured, use kubectl normally:

```bash
kubectl get pods
kubectl get nodes
kubectl apply -f deployment.yaml
```

**On first use**, kubelogin will open a browser for authentication. Subsequent commands use the cached token until it expires (default 1 hour).

## Token Caching

Tokens are cached in `~/.kube/cache/oidc-login/` directory. Each issuer and client_id combination gets its own cache file.

**Cache location:**

```
~/.kube/cache/oidc-login/
  └── <hash-of-issuer-and-client-id>
      └── token.json
```

**Permissions**: Ensure `~/.kube/cache` has restrictive permissions (`0700`) to protect tokens.

## Automatic Token Refresh

kubelogin automatically handles token expiry:
- Before each kubectl command, kubelogin checks if the token is still valid
- If expired, it triggers a new authentication flow (opens browser)
- If valid, it returns the cached token immediately

No manual intervention required.

## Multiple Clusters

You can configure multiple clusters with different Easy OIDC client IDs:

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
      - --oidc-use-pkce

- name: oidc-staging
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: kubelogin
      args:
      - get-token
      - --oidc-issuer-url=https://auth.example.com
      - --oidc-client-id=kubelogin-staging
      - --oidc-use-pkce

contexts:
- context:
    cluster: prod-cluster
    user: oidc-prod
  name: prod

- context:
    cluster: staging-cluster
    user: oidc-staging
  name: staging
```

Switch contexts:

```bash
kubectl config use-context prod
kubectl get pods  # Uses kubelogin-prod client

kubectl config use-context staging
kubectl get pods  # Uses kubelogin-staging client
```

## Non-Interactive Environments (CI/CD)

kubelogin requires a browser for interactive authentication. For CI/CD pipelines, use Kubernetes ServiceAccounts instead:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ci-deploy
  namespace: default
```

Then bind the ServiceAccount to a Role or ClusterRole, and use its token in the pipeline.

## Troubleshooting

**"browser did not open"**:
- Ensure you're on a machine with a browser installed
- For remote servers (SSH), kubelogin won't work—use ServiceAccounts instead
- Check that port `8000` is available (kubelogin's default callback listener)

**"failed to get token"**:
- Verify Easy OIDC is accessible: `curl https://auth.example.com/.well-known/openid-configuration`
- Check that the `--oidc-client-id` matches a client configured in Easy OIDC
- Ensure the redirect URI `http://localhost:8000` is in the client's `default_redirect_uris`

**"token expired" on every command**:
- Check system clock is synchronized (use NTP)
- Verify token cache directory exists and is writable: `~/.kube/cache/oidc-login/`

**"certificate signed by unknown authority"**:
- Easy OIDC uses Let's Encrypt, which should be trusted by default
- If using a custom CA, add `--certificate-authority=<path>` to kubelogin args

See [Troubleshooting](/docs/troubleshooting/) for more issues.

## Advanced Options

**Change callback port** (if 8000 is in use):

```yaml
args:
- get-token
- --oidc-issuer-url=https://auth.example.com
- --oidc-client-id=kubelogin-prod
- --oidc-use-pkce
- --listen-address=127.0.0.1:18000
```

Don't forget to update `default_redirect_uris` in Easy OIDC to `["http://localhost:18000"]`.

**Skip browser opening** (display URL instead):

```yaml
args:
- get-token
- --oidc-issuer-url=https://auth.example.com
- --oidc-client-id=kubelogin-prod
- --oidc-use-pkce
- --skip-open-browser
```

Useful for SSH sessions where you want to copy/paste the URL to your local browser.

## Next Steps

- [Configure RBAC in Kubernetes](/docs/kubernetes/)
- [Add more group mappings](/docs/config/)
- [Review security best practices](/docs/troubleshooting/)
