---
draft: false
title: 'Kubernetes Integration'
linkTitle: 'Kubernetes'
weight: 5
---

This guide shows you how to configure your Kubernetes cluster to use Easy OIDC for authentication.

## Overview

Kubernetes can validate OIDC tokens issued by Easy OIDC using the API server's built-in OIDC authentication. Once configured, users authenticate via their browser (Google/GitHub), receive an ID token, and kubectl uses that token for API requests.

## Configure Kubernetes API Server

Add the following flags to your Kubernetes API server configuration. The exact method depends on how your cluster is provisioned.

### API Server Flags

```bash
--oidc-issuer-url=https://auth.example.com
--oidc-client-id=kubelogin-prod
--oidc-username-claim=email
--oidc-groups-claim=groups
```

**Explanation:**
- `--oidc-issuer-url`: Your Easy OIDC issuer URL
- `--oidc-client-id`: The client ID for your kubectl users (must match a client configured in Easy OIDC)
- `--oidc-username-claim`: Use the `email` claim as the username in Kubernetes
- `--oidc-groups-claim`: Use the `groups` claim for RBAC authorization

### Configuration by Cluster Type

**kubeadm clusters**: Edit `/etc/kubernetes/manifests/kube-apiserver.yaml` on control plane nodes and add the flags under `spec.containers[0].command`.

**kops**: Add the flags to your cluster spec:

```yaml
spec:
  kubeAPIServer:
    oidcIssuerURL: https://auth.example.com
    oidcClientID: kubelogin-prod
    oidcUsernameClaim: email
    oidcGroupsClaim: groups
```

Then run `kops update cluster --yes` and `kops rolling-update cluster --yes`.

**EKS**: Use an identity provider association (see AWS documentation), or manually add flags via cluster configuration.

**GKE**: Not supported directly (GKE enforces Google's own OIDC provider).

**kind (for testing)**:

```yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        oidc-issuer-url: "https://auth.example.com"
        oidc-client-id: "kubelogin-prod"
        oidc-username-claim: "email"
        oidc-groups-claim: "groups"
```

## Configure RBAC

After enabling OIDC authentication, you need to grant users permissions via RBAC.

### Example: Grant Cluster Admin

Grant `alice@example.com` cluster-admin privileges:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: alice-cluster-admin
subjects:
- kind: User
  name: alice@example.com  # matches the email claim
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
```

### Example: Grant Group-Based Access

Grant the `prod-admins` group cluster-admin privileges:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: prod-admins-cluster-admin
subjects:
- kind: Group
  name: prod-admins  # matches a group in the groups claim
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
```

This is why group mappings in Easy OIDC are powerful—you can manage access by email in Easy OIDC, and RBAC in Kubernetes uses the groups.

### Example: Read-Only Access

Grant `bob@example.com` read-only access to all resources:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: bob-view
subjects:
- kind: User
  name: bob@example.com
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: view
  apiGroup: rbac.authorization.k8s.io
```

## Configure kubeconfig

Users need a kubeconfig that triggers OIDC authentication via kubelogin.

### Method 1: kubelogin (Recommended)

Use [kubelogin](https://github.com/int128/kubelogin) to handle OIDC authentication automatically.

Add a user to your kubeconfig:

```yaml
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
```

Then reference this user in your contexts:

```yaml
contexts:
- context:
    cluster: my-cluster
    user: oidc-user
  name: my-cluster-oidc
```

When you run `kubectl` commands, kubelogin will:
1. Check for a cached token
2. If expired or missing, open a browser for authentication
3. Exchange the auth code for an ID token
4. Return the token to kubectl

See the [kubelogin guide](/docs/kubelogin/) for detailed setup.

### Method 2: Manual Token Setup (Not Recommended)

You can manually obtain an ID token and add it to kubeconfig, but this requires re-pasting the token every time it expires (typically 1 hour). Use kubelogin instead.

## Verify Authentication

Test that authentication works:

```bash
kubectl --context my-cluster-oidc get pods
```

If this is your first time, kubelogin will open a browser for authentication. After logging in, kubectl should successfully make the API request.

## Token Expiry and Refresh

ID tokens issued by Easy OIDC expire after 1 hour (configurable). kubelogin handles re-authentication automatically:
- Tokens are cached locally
- When expired, kubelogin triggers a new browser-based login
- No manual intervention required

## Multi-Cluster Setup

You can use the same Easy OIDC instance for multiple Kubernetes clusters by configuring different client IDs with different group mappings.

**Example:**

```hcl
# In Terraform
clients = {
  kubelogin-prod = {
    groups_override = "prod-groups"
  }
  kubelogin-staging = {
    groups_override = "staging-groups"
  }
}

groups_overrides = {
  prod-groups = {
    "alice@example.com" = ["prod-admins"]
  }
  staging-groups = {
    "alice@example.com" = ["staging-admins"]
    "bob@example.com"   = ["staging-readonly"]
  }
}
```

Configure each cluster with its respective `client_id`:
- Production cluster: `--oidc-client-id=kubelogin-prod`
- Staging cluster: `--oidc-client-id=kubelogin-staging`

Alice will have different groups (and thus permissions) in each cluster.

## Security Considerations

**Token Storage**: kubelogin caches tokens in `~/.kube/cache/oidc-login`. Protect this directory (permissions should be `0700`).

**Revocation**: To revoke a user's access:
1. Remove their email from Easy OIDC group mappings (requires Terraform apply + instance restart)
2. Or remove their RBAC bindings in Kubernetes

Existing tokens remain valid until expiry (default 1 hour).

**Audit Logging**: Enable Kubernetes audit logging to track which users performed which actions. The username will be the email claim from the OIDC token.

## Troubleshooting

**"Unable to authenticate the request"**:
- Verify API server OIDC flags are correct
- Check that `--oidc-issuer-url` matches Easy OIDC's issuer URL
- Ensure `--oidc-client-id` matches the client you're authenticating with

**"x509: certificate signed by unknown authority"**:
- Easy OIDC uses Let's Encrypt certificates, which should be trusted by default
- If using a custom CA, configure the API server's `--oidc-ca-file` flag

**"User has no permissions"**:
- Check RBAC bindings
- Verify the username/groups in the token match your RBAC configuration
- Decode the ID token (use https://jwt.io) to inspect claims

See [Troubleshooting](/docs/troubleshooting/) for more issues.

## Next Steps

- [Set up kubelogin](/docs/kubelogin/)
- [Configure additional groups](/docs/config/)
- [Review security best practices](/docs/troubleshooting/)
