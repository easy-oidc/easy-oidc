---
draft: false
title: 'Getting Started'
linkTitle: 'Getting Started'
weight: 2
---

Start with the local demo to see how Truster works. It takes only a few
minutes, needs no cloud account or domain, and walks through a complete sign-in.
When you are ready for a reusable issuer, continue with the local, AWS, or
Google Cloud guide below.

An issuer is the address that Kubernetes and other applications trust for login.
The demo can use HTTP on localhost; deployed issuers use HTTPS.

## Try it locally

You can see the complete email-code sign-in flow without a cloud account. You
need Go, [kubelogin](https://github.com/int128/kubelogin), and three terminals.

Start [Mailpit](https://mailpit.axllent.org/) in the first terminal. It captures
the demo email instead of sending it for real:

```console
go run github.com/axllent/mailpit@latest
```

Start Truster in the second terminal:

```console
go run ./cmd/truster serve --demo
```

Then begin a login:

```console
kubectl oidc-login setup \
  --oidc-issuer-url=http://localhost:8080 \
  --oidc-client-id=kubelogin-local \
  --oidc-pkce-method=S256
```

Your browser will ask for an email address. Enter any address, open Mailpit at
<http://localhost:8025>, and copy the code from the new message back into the
browser. kubelogin will print the identity returned by Truster.

Demo mode is for local evaluation only. It generates temporary signing and
email-code secrets and removes its SQLite database when the process exits.

## Choose where to setup/deploy

- **[Local development or testing](/docs/deploy/local/)** — Keep local keys and
  state across restarts while continuing to use Mailpit.
- **[AWS](/docs/deploy/aws/)** — Deploy a persistent HTTPS issuer with the
  official OpenTofu/Terraform module.
- **[Google Cloud](/docs/deploy/google/)** — Deploy the same application
  configuration on Compute Engine with Google Secret Manager.

## What every deployment needs

Whichever target you choose, you will configure the same parts:

- **An issuer URL:** the address where Truster will run. Production issuers
  use HTTPS.
- **A sign-in method:** Google, GitHub, another OAuth2/OIDC provider, or email
  codes.
- **A signing key:** used to create tokens that Kubernetes can verify.
- **A client:** for example, kubelogin, with its allowed callback address.
- **Access policy:** the users and groups that Truster puts in each token.
- **Kubernetes trust and RBAC:** Kubernetes verifies the token and decides what
  its user and groups may do.

## Next Steps

1. Check the issuer's discovery endpoint to confirm that it is reachable.
2. [Configure Kubernetes](/docs/kubernetes/) to trust the issuer.
3. [Configure kubelogin](/docs/kubelogin/) on each user's computer.
4. Test a login and add the required Kubernetes RBAC bindings.
