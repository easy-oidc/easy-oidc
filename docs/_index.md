---
draft: false
title: 'Documentation'
weight: 1
---

Easy OIDC lets people sign in to your app or Kubernetes cluster with an existing account or a code sent by email. These guides take you from a quick local demonstration to a persistent deployment and Kubernetes access.

## Start here

- [Getting Started](/docs/getting-started/) - Try Easy OIDC locally or choose a deployment target
- [Why Easy OIDC?](/docs/why-easy-oidc/) - Decide whether its scope fits your team
- [OIDC Primer](/docs/oidc-primer/) - Learn how OAuth2 and OIDC work with Easy OIDC
- [Concepts and terminology](/docs/concepts/) - Look up the practical identity and protocol terms used in these guides

## Set up Easy OIDC

- [Sign-in Providers](/docs/upstream/) - Configure Google, GitHub, generic OAuth2/OIDC, or email codes
- [Deployment](/docs/deploy/) - Deploy to AWS or Google Cloud using the official OpenTofu/Terraform modules
- [Kubernetes Integration](/docs/kubernetes/) - Configure your cluster
- [kubelogin](/docs/kubelogin/) - Authenticate with kubectl
- [Application Integration](/docs/app-integration/) - Connect a browser or server application

## Reference

- [Configuration Reference](/docs/config/) - Connectors, email verification, secrets, clients, and templates
- [System Specification](/docs/spec/) - Architecture, security properties, and protocol behavior
- [State Database](/docs/state-database/) - Store login and token state in SQLite or PostgreSQL
- [Policy Database](/docs/policy-database/) - Supply clients, users, groups, and trust policy from PostgreSQL
- [DPoP Integration](/docs/dpop/) - Sender-constrained clients, BFFs, and resource servers
- [Troubleshooting](/docs/troubleshooting/) - Common issues and solutions
