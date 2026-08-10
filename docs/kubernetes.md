---
draft: false
title: 'Kubernetes Integration'
linkTitle: 'Kubernetes'
weight: 5
---

This guide is for cluster administrators configuring Kubernetes to trust Easy
OIDC. For the user-side credential plugin and kubeconfig, see the
[kubelogin guide](/docs/kubelogin/).

## Responsibilities

Easy OIDC authenticates the user and issues signed ID tokens containing identity
claims. The Kubernetes API server validates those tokens and turns selected
claims into a username and groups. **Kubernetes RBAC, not Easy OIDC, authorizes
requests.** A valid token grants no Kubernetes permissions until a RoleBinding or
ClusterRoleBinding grants them.

## Configure API server trust

For a self-managed API server, configure:

```bash
--oidc-issuer-url=https://auth.example.com
--oidc-client-id=kubelogin-prod
--oidc-username-claim=email
--oidc-groups-claim=groups
```

- The issuer URL must exactly match Easy OIDC's configured issuer and be
  reachable from the control plane. Kubernetes discovers signing keys from it.
- The client ID must match the Easy OIDC client used by kubelogin; Kubernetes
  checks it against the token's audience.
- The username and groups settings select the claims Kubernetes passes to RBAC.
- If the issuer uses a private CA, configure `--oidc-ca-file` as well.

Apply equivalent fields if your provisioning tool uses a structured API server
configuration. For example, kubeadm places these values in
`apiServer.extraArgs`; static-pod installations place the flags in the API
server manifest. Restart or roll all control-plane API servers after changing
them.

## Choose claims deliberately

Easy OIDC uses the normalized email address as `sub` and also emits `email`.
Using `email` for `--oidc-username-claim` produces readable RBAC subjects. Using
`sub` is also possible, but bindings must then use the exact username Kubernetes
derives from that claim, including any configured/default prefix.

Set `--oidc-groups-claim=groups` when using Easy OIDC group mappings. Group-based
bindings usually scale better than per-user bindings. Keep separate Easy OIDC
clients and group mappings when clusters need different group sets, and set each
cluster's `--oidc-client-id` accordingly.

Inspect the claims reported by `kubectl oidc-login setup` before creating
bindings. RBAC subject names must exactly match the username and groups produced
by the API server's claim and prefix settings.

## Configure RBAC

Prefer a group binding. This example grants the Easy OIDC `prod-admins` group a
pre-existing cluster role:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: prod-admins
subjects:
- kind: Group
  name: prod-admins
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
```

To scope access to a namespace, use a RoleBinding there instead. A direct user
binding has the same shape with `kind: User` and a `name` matching the configured
username claim, such as `alice@example.com`.

Removing a binding changes authorization immediately. Removing a user from an
Easy OIDC group mapping prevents that group from appearing in newly issued
tokens; an existing token remains valid until it expires (15 minutes by default).

## Managed-cluster constraints

Hosted control planes often do not allow arbitrary API server flags:

- Use the provider's supported OIDC identity-provider association or
  authentication configuration when one is available (for example, Amazon EKS
  supports OIDC identity-provider associations for user authentication).
- Do not confuse Kubernetes user authentication with the similarly named OIDC
  provider used for workload/service-account identity.
- Some products restrict the issuer, claims, prefixes, or number of identity
  providers; some do not support an external OIDC issuer at all. GKE's supported
  authentication options, for example, depend on the GKE product and mode rather
  than user-supplied API server flags.

Check the provider and cluster-version documentation before deploying Easy OIDC.
If the provider cannot express the issuer, audience, and claim mapping above,
this integration cannot be enabled through direct API server OIDC authentication.

## Verify the cluster side

After a user completes the [kubelogin setup](/docs/kubelogin/), distinguish:

- `Unauthorized`: token trust or authentication failed. Check issuer, audience,
  signing-key discovery, CA trust, and API server logs.
- `Forbidden`: authentication succeeded but RBAC did not authorize the username
  or groups. Check the actual claims and binding subjects.

See [Troubleshooting](/docs/troubleshooting/) for a short diagnostic index.
