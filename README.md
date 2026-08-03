<!--
Easy OIDC <https://easy-oidc.dev>
Copyright The Easy OIDC Authors
SPDX-License-Identifier: Apache-2.0
-->

# Easy OIDC

Minimal OIDC server designed for use with Kubernetes, with Google/GitHub/Generic federation, typed email codes, and static user group mappings.

## Overview

`easy-oidc` is a lightweight, single-binary OIDC server designed specifically for Kubernetes clusters. Instead of managing passwords, it delegates authentication to one or more GitHub, Google, generic OAuth2/OIDC, or email-code connectors and maps emails to Kubernetes groups through static configuration.

**Perfect for:**
- Developers already using GitHub or GMail/Google Workspace or wanting email authentication
- Simple RBAC with static user group mappings
- Running on a single EC2 instance with minimal cost

Easy OIDC was created by [Nadrama](https://nadrama.com). Nadrama is an Open Source PaaS that helps you deploy containers, in your cloud account, in minutes.

## Key Features

- **Zero password management** - Delegates to GitHub, Google, or any OAuth2+UserInfo/OIDC provider
- **Multiple sign-in methods** - Configure several upstream providers and optional email codes behind one issuer
- **Consistent email identity** - Normalise sign-in methods to one email identity downstream, with configurable verification
- **Static user group mappings** - Map email addresses to groups in the JSONC config
- **PKCE-only downstream clients** - Secure public client flow with no downstream client secrets to leak
- **Custom templates** - Overlay embedded page and email templates without rebuilding the binary
- **Kubernetes-compatible signing** - RS256 by default, with all Kubernetes-supported algorithms plus EdDSA
- **Single binary** - Embedded SQLite with no external database to operate
- **Multi-cloud support** - OpenTofu/Terraform modules for [AWS](https://github.com/easy-oidc/terraform-aws-easy-oidc) and [Google Cloud](https://github.com/easy-oidc/terraform-google-easy-oidc); Azure is planned

## Quick Start

Deploy using the OpenTofu/Terraform module for:

- [AWS](https://github.com/easy-oidc/terraform-aws-easy-oidc?tab=readme-ov-file#prerequisites)
- [Google Cloud](https://github.com/easy-oidc/terraform-google-easy-oidc/blob/main/README.md#prerequisites)

## Documentation

- **[Local development](DEV.md)** - Set up dependencies and run Easy OIDC locally
- **[Configuration](docs/config.md)** - Connectors, email verification, secrets, clients, and templates
- **[State Database](docs/state-database.md)** - PostgreSQL protocol state for replicas and durable operations
- **[Policy Database](docs/policy-database.md)** - Clients, users, groups, and trust bindings supplied by database policy
- **[Example configurations](examples/config/)** - AWS, Azure, GCP, GitHub, Google, and generic connector examples
- **[Documentation](docs/)** - Deployment, Kubernetes integration, and operational guides
- **[AWS OpenTofu/Terraform module](https://github.com/easy-oidc/terraform-aws-easy-oidc)** - AWS infrastructure
- **[Google Cloud OpenTofu/Terraform module](https://github.com/easy-oidc/terraform-google-easy-oidc)** - Google Cloud infrastructure

## Architecture

```
                                    ┌─────────────────┐
                                    │ Secrets Manager │
                                    │ (AWS/GCP/Azure) │
                                    └──────┬──────────┘
                                           │
┌──────────┐        ┌─────────┐        ┌───▼─────┐
│kubelogin │───────▶│ Caddy   │───────▶│easy-oidc│
└──────────┘  HTTPS │ (TLS)   │  :8080 │  (Go)   │
              :443  └─────────┘        └────┬────┘
                                            │
                            ┌───────┴────┬───────────┬──────────┐
                            │            │           │          │
                      ┌─────▼────┐  ┌────▼───┐  ┌────▼────┐ ┌───▼───┐
                      │  Google  │  │ GitHub │  │ Generic │ │ SMTP  │
                      │   OAuth  │  │ OAuth  │  │  OAuth  │ │ email │
                      └──────────┘  └────────┘  └─────────┘ └───────┘
```

- Single VM instance (minimal footprint)
- Caddy handles automatic TLS (via Let's Encrypt)
- Embedded SQLite for OAuth state and authorization code storage with replay protection
- Secrets from cloud-native stores (AWS/GCP/Azure)

## Development

Install the pinned development tools and Git hooks, then build and validate the project:

```console
make setup
make build
make precommit
make test
```

`make precommit` is the fast, read-only check used by the pre-commit hook and CI. Contributor commits must include a [Developer Certificate of Origin](https://developercertificate.org/) sign-off; use `git commit -s` to add it. See [DEV.md](DEV.md) for local OAuth configuration and end-to-end testing.

## Releases

Releases are built from semantic-version tags such as `v2.0.0`. The release workflow validates the source and uses GoReleaser to publish Linux AMD64 and ARM64 archives. Each release includes SHA-512 checksums, SPDX JSON SBOMs, a keyless Cosign bundle for the checksum file, and GitHub build provenance. Create a release tag with:

```console
make tag VERSION=v2.0.0
git push origin v2.0.0
```

## License

Easy OIDC is licensed under the Apache License, Version 2.0.
Copyright The Easy OIDC Authors.
See the [LICENSE](./LICENSE) file for details.
