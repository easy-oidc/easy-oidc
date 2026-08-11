<!--
Easy OIDC <https://easy-oidc.dev>
Copyright The Easy OIDC Authors
SPDX-License-Identifier: Apache-2.0
-->

# Easy OIDC

Easy OIDC is designed to make setting up and operating an OIDC server straightforward:

- Supports Google/GitHub/other OIDC providers, or OTP email login.
- No passwords stored in its database.
- Stores state in SQLite (default), or an external PostgreSQL database for horizontal scaling.
- Policy configuration (like mapping users to groups) can be in a config file, or queried from any PostgreSQL database (even when SQLite is used for state).
- Can be used for Kubernetes control plane auth, simplifying RBAC.
- All HTML page and email templates can be customised without rebuilding the binary.
- Can run on a single VM instance for minimal cost.

Use Easy OIDC if you:

- want users to sign in with accounts they already have;
- want to manage email-to-group mapping policies in config files in git, or a database;
- want a small, self-hosted login service; and
- use Kubernetes RBAC to decide what each group can do, or just need an OIDC service for your app.

Official OpenTofu/Terraform modules are available
  for [AWS](https://github.com/easy-oidc/terraform-aws-easy-oidc) and
  [Google Cloud](https://github.com/easy-oidc/terraform-google-easy-oidc), and an OCI Helm chart is published for each release.

See [Why Easy OIDC?](docs/why-easy-oidc.md) for its intended scope and
operational limits.

## Try it locally

You can see the complete email-code sign-in flow without a cloud account. You
need Go, [kubelogin](https://github.com/int128/kubelogin), and three terminals.

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
  --oidc-pkce-method=S256
```

Your browser will ask for an email address. Enter any address, open Mailpit at
<http://localhost:8025>, and copy the code from the new message back into the
browser. kubelogin will print the identity returned by Easy OIDC.

Demo mode is for local evaluation only. It generates temporary signing and
email-code secrets and removes its SQLite database when the process exits.

## Deploy

Choose a deployment target when you are ready to deploy to a real environment:

- [AWS deployment guide](docs/deploy/aws.md)
- [Google Cloud deployment guide](docs/deploy/google.md)
- [Local development and testing guide](docs/deploy/local.md)
- [Kubernetes and Helm deployment guide](docs/deploy/kubernetes.md)

## Documentation

- [Getting started](docs/getting-started.md)
- [Configuration reference](docs/config.md)
- [Kubernetes integration](docs/kubernetes.md)
- [kubelogin setup](docs/kubelogin.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Example configurations](examples/config/)

## Development

Install the pinned development tools and Git hooks, then build and validate the project:

```console
make setup
make build
make precommit
make test
```

`make precommit` is the fast, read-only check used by the pre-commit hook and CI. Contributor commits must include a [Developer Certificate of Origin](https://developercertificate.org/) sign-off; use `git commit -s` to add it. See [DEV.md](DEV.md) for local OAuth configuration and end-to-end testing.

## License

Easy OIDC is licensed under the Apache License, Version 2.0.
Copyright The Easy OIDC Authors.
See the [LICENSE](./LICENSE) file for details.
