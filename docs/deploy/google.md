---
draft: false
title: 'Deploy to Google Cloud using OpenTofu/Terraform'
linkTitle: 'Google Cloud'
---

This guide deploys a persistent Truster issuer on Google Cloud with Google
sign-in and one kubelogin client. It uses the official OpenTofu/Terraform module
and creates a small Compute Engine deployment.

The module runs Truster and Caddy on one virtual machine. Caddy obtains the
HTTPS certificate, SQLite stores login state, and the instance can read only the
Secret Manager secrets named in its configuration.

## Before you begin

You need:

- a Google Cloud project with billing enabled;
- permission to manage Compute Engine, IAM, Secret Manager, and Cloud DNS;
- a public Cloud DNS managed zone, such as `example.com`;
- [OpenTofu](https://opentofu.org/) or Terraform 1.5 or later;
- the Google Cloud CLI, OpenSSL, and curl; and
- a Google account that can create an OAuth application.

This guide uses these examples. Replace them consistently with your values.

| Setting | Example |
|---|---|
| Project ID | `my-project` |
| Region | `us-central1` |
| Zone | `us-central1-a` |
| Cloud DNS zone name | `example-com` |
| Truster hostname | `auth.example.com` |
| Google callback URL | `https://auth.example.com/callback/google` |
| kubelogin client ID | `kubelogin-prod` |
| Allowed user | `alice@example.com` |

The hostname must be final before you create the Google OAuth application,
because Google accepts only callback URLs registered in advance.

## 1. Enable the Google Cloud APIs

Select the project and enable the APIs used by the module and this example:

```console
gcloud config set project my-project
gcloud services enable \
  compute.googleapis.com \
  dns.googleapis.com \
  iam.googleapis.com \
  secretmanager.googleapis.com \
  cloudresourcemanager.googleapis.com
```

## 2. Create the Google OAuth application

Follow the [Google sign-in provider guide](/docs/upstream/google/) to create a
web OAuth client. Register the callback URL from the table above, then keep the
client ID and client secret for the next step.

The provider guide also describes deployment-specific secret storage. Stop
before that section: this guide stores the credentials in Google Secret Manager.

## 3. Create the secrets

Put the Google client ID and secret in a temporary JSON file, then create a
Secret Manager secret from it:

```console
cat > google-credentials.json <<'EOF'
{"client_id":"YOUR_GOOGLE_CLIENT_ID","client_secret":"YOUR_GOOGLE_CLIENT_SECRET"}
EOF

gcloud secrets create truster-google \
  --replication-policy=automatic \
  --data-file=google-credentials.json

rm google-credentials.json
```

Generate the token-signing key directly into a second secret:

```console
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 | \
  gcloud secrets create truster-signing-key \
    --replication-policy=automatic \
    --data-file=-
```

Replacing a signing key invalidates tokens signed by the previous key. Rotate it
deliberately and expect users to sign in again.

Truster uses full Secret Manager version names. For this example they are:

```text
projects/my-project/secrets/truster-google/versions/latest
projects/my-project/secrets/truster-signing-key/versions/latest
```

The module grants its instance service account access to the referenced secrets.
Set `grant_secret_accessor = false` only if you manage those permissions outside
the module.

## 4. Create the OpenTofu configuration

Create an empty directory and save the following as `main.tf`. Change the
project, location, DNS zone, hostname, and allowed email address.

```hcl
terraform {
  required_version = ">= 1.5"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0"
    }
  }
}

locals {
  project_id    = "my-project"
  region        = "us-central1"
  zone          = "us-central1-a"
  dns_zone_name = "example-com"
  oidc_hostname = "auth.example.com"
}

provider "google" {
  project = local.project_id
  region  = local.region
  zone    = local.zone
}

resource "google_compute_network" "main" {
  name                    = "truster"
  auto_create_subnetworks = false
}

module "truster" {
  source  = "truster/truster/google"
  version = "~> 2.0"

  project_id  = local.project_id
  region      = local.region
  zone        = local.zone
  network     = google_compute_network.main.self_link
  oidc_addr   = local.oidc_hostname
  enable_ipv6 = false

  truster_config = {
    secrets = {
      signing_key_name = "projects/${local.project_id}/secrets/truster-signing-key/versions/latest"
    }
    user_login_connectors = {
      google = {
        type               = "google"
        display_name       = "Google"
        credentials_secret = "projects/${local.project_id}/secrets/truster-google/versions/latest"
      }
    }
    static_policy = {
      user_group_mappings = {
        kubernetes-users = {
          "alice@example.com" = ["developers"]
        }
      }
      clients = {
        kubelogin-prod = {
          redirect_uris      = ["http://localhost:8000"]
          user_group_mapping = "kubernetes-users"
        }
      }
    }
  }
}

data "google_dns_managed_zone" "main" {
  name = local.dns_zone_name
}

resource "google_dns_record_set" "oidc" {
  managed_zone = data.google_dns_managed_zone.main.name
  name         = "${local.oidc_hostname}."
  type         = "A"
  ttl          = 300
  rrdatas      = [module.truster.public_ipv4]
}
```

The module creates a subnet, firewall rules for ports 80 and 443, a static IP,
an instance service account, and the Compute Engine instance. The example adds
the VPC and DNS record. It disables IPv6 to keep the first deployment simple;
the [module input reference](https://github.com/truster-dev/terraform-google-truster#variables)
documents dual-stack and existing-subnet options.

## 5. Deploy

Review the plan before applying it:

```console
tofu init
tofu plan
tofu apply
```

If you use Terraform, replace `tofu` with `terraform`. Certificate issuance can
take a few minutes after the DNS record appears.

## 6. Verify the issuer and sign in

Check that DNS points to the module's public address:

```console
dig auth.example.com A
```

Then check the OIDC discovery document:

```console
curl --fail https://auth.example.com/.well-known/openid-configuration
```

A successful request returns JSON containing the issuer and endpoint addresses.
If it fails, wait for DNS propagation and certificate issuance, then inspect the
instance's serial-port or service logs.

Install kubelogin as described in the [kubelogin guide](/docs/kubelogin/), then
test the browser flow:

```console
kubectl oidc-login setup \
  --oidc-issuer-url=https://auth.example.com \
  --oidc-client-id=kubelogin-prod \
  --oidc-pkce-method=S256
```

Sign in with the allowed Google account. kubelogin should report the email and
`developers` group configured above. This proves login works; it does not grant
access to a Kubernetes cluster.

## 7. Connect Kubernetes

Follow the [Kubernetes integration guide](/docs/kubernetes/) to make the API
server trust this issuer and client ID. Create RBAC bindings for the
`developers` group, then use the [kubelogin guide](/docs/kubelogin/) to add the
exec-based credentials to each user's kubeconfig.

## Configuration boundaries

The module supplies deployment-owned values for `issuer_url`,
`http_listen_addr`, `secrets.provider`, and the SQLite state path. Put the
remaining application settings under `truster_config`.

Migration credentials remain separate by default. For a PostgreSQL state
database, set `run_db_migrations = true` only if the instance should read the
migration secret and run `truster migrate` before every service start. See the
[state database guide](/docs/state-database/) for the least-privilege tradeoff.

Use the [module input reference](https://github.com/truster-dev/terraform-google-truster#variables)
for networking, service accounts, encryption, SSH, and version controls. Use the
[application configuration reference](/docs/config/) for sign-in methods,
clients, users, groups, and token settings.

## Troubleshooting

**Certificate errors**

- Verify the A record points to `module.truster.public_ipv4`.
- Verify ports 80 and 443 are reachable while Caddy obtains the certificate.
- Wait for DNS changes to propagate before restarting the instance.

**Secret access errors**

- Use full Secret Manager version names in `truster_config`.
- Verify the referenced secret exists in the named project.
- If `grant_secret_accessor` is false, grant the instance service account
  `roles/secretmanager.secretAccessor` on each required secret.

**OAuth callback errors**

- Verify the Google OAuth redirect URI is exactly
  `https://auth.example.com/callback/google`.
- Verify the connector ID in the configuration is `google`.

See [Troubleshooting](/docs/troubleshooting/) for application-level checks.

## Next Steps

- [Configure Kubernetes integration](/docs/kubernetes/)
- [Set up kubelogin](/docs/kubelogin/)
- [Add clients and groups](/docs/config/)
- [Review the module input reference](https://github.com/truster-dev/terraform-google-truster#variables)
