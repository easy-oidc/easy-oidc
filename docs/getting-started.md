---
draft: false
title: 'Getting Started'
linkTitle: 'Getting Started'
weight: 2
---

Start with the local demo to see how Easy OIDC works, or choose a cloud guide to
deploy a persistent issuer. An issuer is the HTTPS address that Kubernetes and
other applications trust for login.

## Try it locally

You can see the complete email-code sign-in flow without a cloud account. You
need Go, [kubelogin](https://github.com/int128/kubelogin), and two terminals.

Start [Mailpit](https://mailpit.axllent.org/) in the first terminal. It captures
the demo email instead of sending it for real:

```console
go run github.com/axllent/mailpit@latest
```

Start Easy OIDC in the second terminal:

```console
go run ./cmd/easy-oidc serve --demo
```

Then begin a login:

```console
kubectl oidc-login setup \
  --oidc-issuer-url=http://localhost:8080 \
  --oidc-client-id=kubelogin-local \
  --oidc-use-pkce
```

Your browser will ask for an email address. Enter any address, open Mailpit at
<http://localhost:8025>, and copy the code from the new message back into the
browser. kubelogin will print the identity returned by Easy OIDC.

Demo mode is for local evaluation only. It generates temporary signing and
email-code secrets and removes its SQLite database when the process exits.

## Choose where to deploy

- **[AWS](/docs/deploy/aws/)** — Complete guide using the official
  OpenTofu/Terraform module.
- **Google Cloud** — The official
  [`terraform-google-easy-oidc`](https://github.com/easy-oidc/terraform-google-easy-oidc)
  module is available. A step-by-step guide will be added after the AWS guide is
  reviewed.
- **Local development or testing** — Use the demo above for now. A guide for a
  persistent local configuration will follow the cloud guides.

## What every deployment needs

Whichever target you choose, you will configure the same parts:

- **An issuer URL:** the address where Easy OIDC will run. Production issuers
  use HTTPS.
- **A sign-in method:** Google, GitHub, another OAuth2/OIDC provider, or email
  codes.
- **A signing key:** used to create tokens that Kubernetes can verify.
- **A client:** for example, kubelogin, with its allowed callback address.
- **Access policy:** the users and groups that Easy OIDC puts in each token.
- **Kubernetes trust and RBAC:** Kubernetes verifies the token and decides what
  its user and groups may do.

## Next Steps

1. Check the issuer's discovery endpoint to confirm that it is reachable.
2. [Configure Kubernetes](/docs/kubernetes/) to trust the issuer.
3. [Configure kubelogin](/docs/kubelogin/) on each user's computer.
4. Test a login and add the required Kubernetes RBAC bindings.
