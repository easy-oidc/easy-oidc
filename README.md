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
- **Ed25519 signing** - State-of-the-art cryptography
- **Single binary** - Embedded SQLite (no external database), no external dependencies
- **Multi-cloud support** - Terraform modules for your cloud (AWS [here](https://github.com/easy-oidc/terraform-aws-easy-oidc), GCP/Azure planned)

## Quick Start

See [AWS Terraform Module](https://github.com/easy-oidc/terraform-aws-easy-oidc?tab=readme-ov-file#prerequisites) for instructions on how to deploy to AWS.

## Documentation

- **[SPEC.md](SPEC.md)** - Full specification, architecture, and configuration reference
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

## License

Easy OIDC is licensed under the Apache License, Version 2.0.
Copyright 2025 Nadrama Pty Ltd.
See the [LICENSE](./LICENSE) file for details.
