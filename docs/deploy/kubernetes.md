---
draft: false
title: 'Deploy on Kubernetes'
linkTitle: 'Kubernetes'
weight: 2
---

Easy OIDC publishes a Linux AMD64 and ARM64 container image and an OCI Helm
chart with each release. The chart runs one replica with persistent SQLite by
default. Use PostgreSQL before scaling to multiple replicas.

## Prepare configuration and secrets

Kubernetes Secrets are not recommended for storing secrets as they are stored in etcd unencrypted. Instead, install the [Secrets Store CSI Driver](https://secrets-store-csi-driver.sigs.k8s.io/)
and your external secret manager's provider. Create a provider-specific
`SecretProviderClass` that mounts each Easy OIDC secret as a file. Do not enable
`secretObjects`: that optional synchronization feature creates a Kubernetes
Secret and stores the values in etcd.

The chart generates `config.jsonc` from values that follow the Easy OIDC
[configuration structure](/docs/config/). Create `values.yaml` with the public
issuer, connectors, clients, and the name of your `SecretProviderClass`:

```yaml
config:
  issuer_url: https://auth.example.com
  user_login_connectors:
    google:
      type: google
      display_name: Google
      credentials_secret: google-credentials.json
  static_policy:
    clients:
      kubelogin:
        redirect_uris:
          - http://localhost:8000

secretFiles:
  enabled: true
  csi:
    secretProviderClass: easy-oidc

ingress:
  enabled: true
  className: nginx
  hosts:
    - host: auth.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: easy-oidc-tls
      hosts:
        - auth.example.com
```

The default generated secret configuration uses the `file` provider,
reads files below `/var/run/secrets/easy-oidc`, and expects the signing key in
`signing-key.pem`. Connector credential files are usually JSON objects; see the
relevant [upstream provider guide](/docs/upstream/). Easy OIDC loads files once
at startup, so restart it after rotating a secret.

Kubernetes Secrets remain supported through the chart's `env` and `envFrom`
values when CSI is unavailable. This fallback stores secret values in etcd and
exposes them as environment variables. If it is unavoidable, enable etcd
encryption at rest and tightly restrict Secret RBAC. Set
`config.secrets.provider: env`, use environment variable names for configured
secrets, and reference the Kubernetes Secret with `envFrom`.

## Install the chart

Install a released chart version:

```console
helm install easy-oidc oci://ghcr.io/easy-oidc/charts/easy-oidc \
  --version VERSION \
  --namespace easy-oidc \
  --values values.yaml
```

Replace `VERSION` with the release version without its leading `v`. The chart
can use an existing ConfigMap instead of storing configuration in the Helm
release; see the chart's bundled README for all values.

The issuer URL must exactly match the external HTTPS origin. Configure TLS at
the Ingress or another trusted proxy. The chart can also use an existing TLS
Secret or create a cert-manager `Certificate` for native HTTPS between the
Service and Easy OIDC; see the chart README for backend TLS and Ingress-specific
requirements. Then verify:

```console
curl https://auth.example.com/.well-known/openid-configuration
```

## Persistence, scaling, and migrations

The default PVC stores SQLite state at `/var/lib/easy-oidc`. Keep one replica
and the default `Recreate` deployment strategy with SQLite. For multiple
replicas, configure a shared PostgreSQL state database, disable the unnecessary
PVC, and change the strategy to `RollingUpdate`:

```yaml
config:
  state_database:
    driver: postgresql
    connection_string_secret: EASYOIDC_STATE_DB_URL

deploymentStrategy:
  type: RollingUpdate
```

The PostgreSQL driver automatically disables the SQLite PVC. Helm keeps a
chart-managed PVC when you uninstall the release; delete it separately only
when you intend to destroy the stored protocol state. The chart does not enable
Service session affinity, as Kubernetes client-IP affinity cannot guarantee that
proofs using the same DPoP key reach the same replica.

Set `migrations.enabled: true` to run `easy-oidc migrate` in an init container
before the server. Put migration-only environment variables under
`migrations.env` or `migrations.envFrom` so the server container does not receive
them. For file secrets, enable `migrations.secretFiles` with a separate
`SecretProviderClass`; the server does not mount that migration volume. Because
Kubernetes workload identity belongs to the whole Pod, use a separate
deployment job when migrations require a more privileged cloud identity.

The chart runs as numeric user 65532, drops Linux capabilities, uses a read-only
root filesystem, and does not mount a Kubernetes API token by default. It
creates no RBAC resources because Easy OIDC does not need access to the
Kubernetes API.
