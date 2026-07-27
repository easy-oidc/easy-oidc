<!--
Easy OIDC <https://easy-oidc.dev>
Copyright The Easy OIDC Authors
SPDX-License-Identifier: Apache-2.0
-->

# Easy OIDC

Minimal OIDC server designed for use with Kubernetes, with Google/GitHub/Generic federation, and support for static group overrides.

## Overview

`easy-oidc` is a lightweight, single-binary OIDC server designed specifically for Kubernetes clusters. Instead of managing passwords, it delegates authentication to GitHub, Google, or generic OAuth2+UserInfo or OIDC providers (including Dex, Keycloak, etc) and maps users to Kubernetes groups via simple static configuration.

**Perfect for:**
- Developers already using GitHub or GMail/Google Workspace
- Simple RBAC with static group overrides
- Running on a single EC2 instance with minimal cost

Easy OIDC was created by [Nadrama](https://nadrama.com). Nadrama is an Open Source PaaS that helps you deploy containers, in your cloud account, in minutes.

## Key Features

- **Zero password management** - Delegates to GitHub, Google, or any OAuth2+UserInfo/OIDC provider
- **Static group overrides** - Map a list of emails to groups in the JSONC config
- **PKCE-only** - Secure public client flow (no client secrets to leak)
- **Kubernetes-compatible signing** - RS256 by default, with all Kubernetes-supported algorithms plus EdDSA
- **Single binary** - Embedded SQLite (no external database), no external dependencies
- **Multi-cloud support** - Terraform modules for your cloud (AWS [here](https://github.com/easy-oidc/terraform-aws-easy-oidc), GCP/Azure planned)

## Quick Start

See [AWS Terraform Module](https://github.com/easy-oidc/terraform-aws-easy-oidc?tab=readme-ov-file#prerequisites) for instructions on how to deploy to AWS.

## Documentation

- **[Local development](DEV.md)** - Set up dependencies and run Easy OIDC locally
- **[Example configurations](examples/config/)** - AWS, Azure, GCP, GitHub, Google, and generic connector examples
- **[Terraform Module](https://github.com/easy-oidc/terraform-aws-easy-oidc)** - AWS infrastructure module

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
                                  ┌─────────┼─────────┐
                                  │         │         │
                        ┌─────────▼─┐ ┌─────▼───┐ ┌───▼──────┐
                        │  Google   │ │  GitHub │ │  Generic │
                        │   OAuth   │ │   OAuth │ │   OAuth  │
                        └───────────┘ └─────────┘ └──────────┘
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

Releases are built from semantic-version tags such as `v1.4.0`. The release workflow validates the source and uses GoReleaser to publish Linux AMD64 and ARM64 archives. Each release includes SHA-512 checksums, SPDX JSON SBOMs, a keyless Cosign bundle for the checksum file, and GitHub build provenance. Create a release tag with:

```console
make tag VERSION=v1.5.0
git push origin v1.5.0
```

## License

Easy OIDC is licensed under the Apache License, Version 2.0.
Copyright The Easy OIDC Authors.
See the [LICENSE](./LICENSE) file for details.
