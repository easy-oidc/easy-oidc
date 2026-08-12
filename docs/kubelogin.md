---
draft: false
title: 'Using kubelogin for kubectl Authentication'
linkTitle: 'kubelogin'
weight: 6
---

[kubelogin](https://github.com/int128/kubelogin), also invoked as
`kubectl oidc-login`, is a user-side Kubernetes exec credential plugin. It opens
an OIDC browser flow, returns an ID token to kubectl, and caches credentials.

This page assumes a cluster administrator has already configured API server OIDC
trust and RBAC. See [Kubernetes integration](/docs/kubernetes/) for that
cluster-side setup.

## Install kubelogin

### macOS

```bash
brew install int128/kubelogin/kubelogin
```

### Linux

Download the archive for your architecture from the
[kubelogin releases](https://github.com/int128/kubelogin/releases), extract the
binary, and place it on your `PATH`.

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

### Verify the installation:

```bash
kubelogin --version
```

## Configure kubeconfig

Add an exec user and use it from the desired context:

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
      - --oidc-pkce-method=S256
      interactiveMode: IfAvailable
      provideClusterInfo: false
contexts:
- name: my-cluster-oidc
  context:
    cluster: my-cluster
    user: oidc-user
```

The issuer and client ID must match the cluster-side OIDC settings and the
Truster client. Repeat the user entry with another client ID if a second cluster
uses a separate client and group mapping.

Request `offline_access` only when the Truster client explicitly allows
offline grants:

```yaml
- --oidc-extra-scope=offline_access
```

## Log in with a browser

Test the flow and inspect the issued claims before using the context:

```bash
kubectl oidc-login setup \
  --oidc-issuer-url=https://auth.example.com \
  --oidc-client-id=kubelogin-prod \
  --oidc-pkce-method=S256
```

kubelogin starts a localhost callback listener, opens Truster in the browser,
and prints the resulting claims after authentication. Confirm `iss`, `aud`,
`email`, and `groups` with your cluster administrator. Then use kubectl normally:

```bash
kubectl --context my-cluster-oidc get pods
```

On first use, kubelogin starts the same browser flow if no usable cached
credential exists.

## Token cache and refresh

kubelogin caches credentials under `~/.kube/cache/oidc-login/`, separated by
issuer and client ID. Protect the cache as sensitive data and keep its parent
directory accessible only to your user (for example, mode `0700`).

Truster ID tokens expire after 15 minutes by default. Before each command,
kubelogin returns a valid cached token, refreshes it if a refresh token is
available, or starts a new browser login. Refresh tokens require
`refresh_tokens.enabled` in Truster. Long-lived offline grants additionally
require the client to permit offline access and kubelogin to request the
`offline_access` scope. Without a refresh token, a new browser login after
expiry is expected.

For non-interactive workloads, use a Kubernetes ServiceAccount or another
workload credential instead of storing a human's kubelogin cache in CI.

## User-side troubleshooting

### Browser does not open

Add `--skip-open-browser` to the exec args and open the printed URL in a browser.
For a remote shell, remember that the callback listener runs on the machine
where kubelogin runs; browser and network forwarding must be able to reach it.

### Callback port is busy

Add `--listen-address=127.0.0.1:18000` (or another free port), and ask the Truster
administrator to allow the corresponding `http://localhost:18000` redirect
URI for the client.

### Login or refresh repeatedly fails

- Verify the local clock is synchronized and the cache directory is writable.
- Verify discovery is reachable with
  `curl https://auth.example.com/.well-known/openid-configuration`.
- Confirm the client ID, callback URI, and optional `offline_access` policy.
- Run the command with `--v=1` for kubelogin diagnostics. Remove only the cache
  entry for this issuer/client if you need to force a clean browser login.
- For a private issuer CA, configure kubelogin's certificate-authority option.

If kubelogin obtains a token but kubectl reports `Unauthorized` or `Forbidden`,
handoff to the cluster administrator and use the checks in
[Kubernetes integration](/docs/kubernetes/). See
[Troubleshooting](/docs/troubleshooting/) for service and deployment issues.

## Next Steps

- [Configure RBAC in Kubernetes](/docs/kubernetes/)
- [Add more group mappings](/docs/config/)
- [Review security best practices](/docs/troubleshooting/)
