# Truster Helm chart

This application chart deploys Truster on Kubernetes 1.24 or newer. It creates
a Deployment, Service, ServiceAccount, and (by default) a PVC. It deliberately
creates no RBAC resources because Truster does not access the Kubernetes API.

## Install

Install the [Secrets Store CSI Driver](https://secrets-store-csi-driver.sigs.k8s.io/)
and the provider for your external secret manager, then create a
`SecretProviderClass` that mounts files such as `signing-key.pem` and
`google-credentials.json`. Do not configure `secretObjects`; syncing CSI content
to a Kubernetes Secret would also copy it into etcd.

Configure Truster as Helm values. The chart writes these values to the
`config.jsonc` mounted by the Pod:

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
    secretProviderClass: truster
```

Pass that file when installing:

```bash
helm install truster ./deploy/helm --namespace truster --create-namespace \
  --values values.yaml
```

`config.rawOverride` accepts a complete JSONC document when generated
configuration is unsuitable. Alternatively, keep the entire configuration
lifecycle outside Helm:

```bash
kubectl -n truster create configmap truster-config \
  --from-file=config.jsonc=./config.jsonc
helm install truster ./deploy/helm --namespace truster \
  --set config.existingConfigMap=truster-config
```

Truster configuration is specific to each deployment: the issuer must match
the public URL and policy must allow at least one client. The chart therefore
requires these values rather than shipping placeholder identity or trust
policy. `config.existingConfigMapKey` changes the external source key; the file
is always mounted as `/etc/truster/config.jsonc`.

With `rawOverride` or `existingConfigMap`, keep
`config.state_database.driver` set to the driver in the opaque configuration so
the chart chooses the correct volume and rollout behavior. Persistent SQLite
must store its database beneath `/var/lib/truster`.

## Configuration

| Value | Description | Default |
|---|---|---|
| `image.repository` | Truster image | `ghcr.io/truster-dev/truster` |
| `image.tag` | Image tag; empty uses chart `appVersion` | `""` |
| `image.digest` | Image digest, including `sha256:`; takes precedence over tag | `""` |
| `replicaCount` | Deployment replicas | `1` |
| `deploymentStrategy` | Deployment update strategy; PostgreSQL may use `RollingUpdate` | `Recreate` |
| `config.issuer_url` | Public Truster issuer URL | `""` |
| `config.user_login_connectors` | Interactive login connectors | `{}` |
| `config.static_policy` | Static clients and authorization policy | empty clients |
| `config.rawOverride` | Complete JSONC replacing generated configuration | `""` |
| `config.existingConfigMap` | Existing ConfigMap name | `""` |
| `config.existingConfigMapKey` | Existing ConfigMap configuration key | `config.jsonc` |
| `config.state_database.driver` | State database driver; `postgresql` disables SQLite persistence | `sqlite` |
| `config.state_database.persistence.enabled` | Persist SQLite data; false uses `emptyDir` | `true` |
| `config.state_database.persistence.existingClaim` | Use an existing PVC | `""` |
| `config.state_database.persistence.storageClass` | PVC storage class; empty uses cluster default | `""` |
| `config.state_database.persistence.size` | Requested storage | `1Gi` |
| `secretFiles.enabled` | Mount external secrets through CSI | `false` |
| `secretFiles.mountPath` | File secrets directory | `/var/run/secrets/truster` |
| `secretFiles.csi.secretProviderClass` | Existing provider-specific `SecretProviderClass` | `""` |
| `service.type` / `service.port` | Service type and port | `ClusterIP` / `8080` |
| `ingress.enabled` | Create an Ingress | `false` |
| `server.tls.enabled` | Serve native HTTPS from Truster | `false` |
| `server.tls.secretName` | Existing TLS Secret; empty uses `<fullname>-tls` | `""` |
| `server.tls.certManager.enabled` | Create a cert-manager `Certificate` | `false` |
| `server.tls.certManager.issuerRef` | cert-manager issuer name, kind, and group | empty `Issuer` reference |
| `server.tls.certManager.dnsNames` | Subject alternative names for the serving certificate | `[]` |
| `migrations.enabled` | Run `truster migrate` before the server | `false` |
| `migrations.secretFiles.enabled` | Use a migration-only CSI volume | `false` |
| `migrations.secretFiles.csi.secretProviderClass` | Migration-only `SecretProviderClass` | `""` |
| `migrations.env` / `migrations.envFrom` | Additional secrets available only while migrating | `[]` / `[]` |
| `env` / `envFrom` | Container environment and sources | `[]` / `[]` |
| `serviceAccount.annotations` | ServiceAccount annotations | `{}` |
| `imagePullSecrets` | Pod image pull secrets | `[]` |

See `values.yaml` for resources, probes, security contexts, PVC access modes,
and node selector, affinity, toleration, and topology spread settings.

## Secrets and security

The recommended Kubernetes setup keeps secret values in an external manager and
mounts them as files with the Secrets Store CSI Driver. Set
`config.secrets.provider: file`; each configured secret name is a path relative
to `config.secrets.file_directory`. The chart defaults that
directory to `secretFiles.mountPath` and mounts the files read-only in both the
migration init container and the server container.

Truster reads secret files once during startup. Restart the workload after a
rotation; do not assume that an in-place CSI file update reloads keys or
credentials.

Kubernetes Secrets remain supported through `env` and `envFrom` for clusters
that cannot use CSI:

```yaml
config:
  secrets:
    provider: env
    signing_key_name: TRUSTER_SIGNING_KEY

envFrom:
  - secretRef:
      name: truster-secrets
```

This fallback stores secret material in Kubernetes etcd and exposes it as
environment variables. Use etcd encryption at rest and tightly restrict Secret
RBAC if it is unavoidable. Prefer CSI without `secretObjects` so Kubernetes
receives only the external provider reference, not a synchronized Secret.

The Distroless `:nonroot` image defaults to UID 65532. The chart explicitly
enforces UID/GID 65532 as defence in depth, uses `RuntimeDefault` seccomp, drops
all capabilities, prevents privilege escalation, disables API token mounting,
and makes the root filesystem read-only. A writable PVC and temporary `emptyDir`
are mounted only where needed. Terminate TLS at the Ingress or another trusted
proxy and protect configuration and Secret access with namespace policy. Pin a
production image by setting `image.digest` to its immutable `sha256:` digest.
The config's issuer must exactly match the public HTTPS origin.

SQLite supports a single writer and the default PVC is `ReadWriteOnce`; keep
`replicaCount: 1` when using SQLite. Use a supported external database before
scaling horizontally. Back up the PVC and test restoration. With SQLite,
setting `config.state_database.persistence.enabled: false` loses protocol state
whenever the Pod is replaced. The chart marks a managed PVC with Helm's `keep`
resource policy, so uninstalling the release leaves the database behind. Delete
the PVC explicitly only when its state is no longer needed. To protect the
SQLite database, chart validation requires one replica and the `Recreate`
strategy while persistence is enabled.

When the Truster configuration uses PostgreSQL, disable the unused PVC and
allow rolling updates in the Helm values:

```yaml
config:
  state_database:
    driver: postgresql
    connection_string_secret: TRUSTER_STATE_DB_URL

deploymentStrategy:
  type: RollingUpdate
```

`config.state_database.driver: postgresql` automatically replaces the SQLite
PVC with an ephemeral data volume. The chart does not enable Service session affinity:
Kubernetes supports only client-IP affinity, which cannot reliably bind requests using
the same DPoP key to one replica.

## Native HTTPS and cert-manager

Truster normally serves HTTP inside the Pod so an Ingress or another trusted
proxy can terminate TLS. To encrypt traffic to the Pod as well, provide a
standard `kubernetes.io/tls` Secret containing `tls.crt` and `tls.key`:

```yaml
server:
  tls:
    enabled: true
    secretName: truster-serving-tls
```

The chart mounts the whole Secret at `/var/run/truster/tls`, configures native
HTTPS, and switches its Service and HTTP probes to HTTPS. Truster reloads a
valid replacement certificate without restarting and keeps the last valid pair
if a projected update is temporarily incomplete.

If cert-manager is installed, the chart can create the `Certificate` and use
its generated Secret:

```yaml
server:
  tls:
    enabled: true
    certManager:
      enabled: true
      issuerRef:
        name: internal-ca
        kind: ClusterIssuer
      dnsNames:
        - truster.example-namespace.svc
        - truster.example-namespace.svc.cluster.local
```

Set `duration` and `renewBefore` under `server.tls.certManager` only when
your issuer requires non-default lifetimes. cert-manager stores the generated
private key in a Kubernetes Secret, so enable etcd encryption at rest and limit
Secret RBAC.

`ingress.tls` configures the certificate presented by the Ingress to clients;
it does not configure HTTPS from the Ingress to Truster. Backend TLS is
controller-specific. For ingress-nginx, add
`nginx.ingress.kubernetes.io/backend-protocol: HTTPS` to `ingress.annotations`.
Other controllers may require backend scheme, trust, or SNI configuration.

With `config.rawOverride` or `config.existingConfigMap`, the chart cannot modify
the opaque application configuration. When `server.tls.enabled` is
true, include these paths yourself:

```jsonc
"serving_certificate": {
  "certificate_file": "/var/run/truster/tls/tls.crt",
  "private_key_file": "/var/run/truster/tls/tls.key"
}
```

## Migrations and upgrades

Set `migrations.enabled: true` to run
`/truster migrate --config /etc/truster/config.jsonc` in an init container
using the same image, config, security context, and data volume as the server.
Shared `env` and `envFrom` values are available to both containers; use
`migrations.env` or `migrations.envFrom` for a more privileged database credential
that the server must not receive. With CSI, set
`migrations.secretFiles.enabled: true` and select a separate
`SecretProviderClass`; the init container mounts it instead of the runtime
secret volume. Workload identity still applies to the whole Pod, so run
migrations from a separate release process when migration and runtime cloud
identities must differ.

Back up the database before upgrades. Review Truster release notes for
migration and rollback compatibility, upgrade one replica at a time, and
disable the init container if migrations are managed by a separate release
process. Generated and raw override changes trigger a rollout via a checksum
Pod annotation; updates to an external ConfigMap require an explicit rollout.
