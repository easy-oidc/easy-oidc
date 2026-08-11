---
draft: false
title: 'Run locally for development and testing'
linkTitle: 'Local'
---

This guide runs Easy OIDC and a local email inbox on your computer. It is the
fastest way to try a complete sign-in flow without a cloud account, domain, or
real email service.

Use this setup only for development and testing. It listens on localhost over
HTTP and does not provide the availability or secret management needed for a
production issuer.

## Before you begin

You need:

- Go and OpenSSL;
- [kubelogin](https://github.com/int128/kubelogin); and
- a local checkout of the Easy OIDC repository.

## 1. Start a local email inbox

Run [Mailpit](https://mailpit.axllent.org/) in the first terminal:

```console
go run github.com/axllent/mailpit@latest
```

Mailpit accepts email on port 1025 and shows it at <http://localhost:8025>.
Messages remain on your computer instead of being delivered.

## 2. Try the temporary demo

In a second terminal, from the Easy OIDC repository, run:

```console
go run ./cmd/easy-oidc serve --demo
```

Begin a login in a third terminal:

```console
kubectl oidc-login setup \
  --oidc-issuer-url=http://localhost:8080 \
  --oidc-client-id=kubelogin-local \
  --oidc-pkce-method=S256
```

Enter any email address in the browser. Open Mailpit, read the new message, and
enter its code in the browser. kubelogin then prints the identity returned by
Easy OIDC.

Demo mode generates temporary keys and deletes its SQLite database when it
stops. Continue with the next section if you need the same local issuer across
restarts.

## 3. Keep local keys and state across restarts

Create a directory for local-only data and generate separate signing and email
code secrets:

```console
mkdir -p .easy-oidc-local/secrets
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  > .easy-oidc-local/secrets/signing-key.pem
openssl rand -hex 32 > .easy-oidc-local/secrets/otp-secret
chmod -R go-rwx .easy-oidc-local
```

Save this configuration as `.easy-oidc-local/config.jsonc`:

```jsonc
{
  "$schema": "https://easy-oidc.dev/schema/v2/config.schema.json",
  "issuer_url": "http://localhost:8080",
  "http_listen_addr": "127.0.0.1:8080",

  "secrets": {
    "provider": "file",
    "file_directory": ".easy-oidc-local/secrets",
    "signing_key_name": "signing-key.pem"
  },

  "state_database": {
    "driver": "sqlite",
    "path": ".easy-oidc-local/state.db"
  },

  "user_login_connectors": {
    "email": {
      "type": "email",
      "display_name": "Email code"
    }
  },

  "email": {
    "verification_mode": "disabled",
    "otp_secret_name": "otp-secret",
    "smtp": {
      "host": "localhost",
      "port": 1025,
      "tls_mode": "plaintext",
      "from_name": "Easy OIDC",
      "from_address": "auth@localhost"
    }
  },

  "static_policy": {
    "require_user_groups_from_policy": false,
    "default_redirect_uris": ["http://localhost:8000"],
    "clients": {
      "kubelogin-local": {}
    }
  }
}
```

Keep `.easy-oidc-local` out of version control because it contains private key
material. Check the configuration, then start the persistent local issuer:

```console
go run ./cmd/easy-oidc check config --config .easy-oidc-local/config.jsonc
go run ./cmd/easy-oidc serve --config .easy-oidc-local/config.jsonc
```

Use the same kubelogin command from step 2. The signing key and SQLite state now
remain in `.easy-oidc-local` when Easy OIDC stops.

## What this setup proves

You have now exercised the same main responsibilities as a deployed issuer:

- Easy OIDC authenticates a user through a configured sign-in method;
- the client begins a standard authorization-code flow with PKCE;
- Easy OIDC creates a signed ID token; and
- kubelogin verifies and displays the returned identity.

Kubernetes authorization is a separate step. Easy OIDC supplies identity and
groups; Kubernetes RBAC decides what they may do.

## Next Steps

- [Learn the main concepts and terminology](/docs/concepts/)
- [Configure Kubernetes to trust Easy OIDC](/docs/kubernetes/)
- [Configure kubelogin for a cluster](/docs/kubelogin/)
- [Deploy to AWS](/docs/deploy/aws/) or [Google Cloud](/docs/deploy/google/)
