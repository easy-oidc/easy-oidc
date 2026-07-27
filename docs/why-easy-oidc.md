---
draft: false
title: 'Why Easy OIDC?'
linkTitle: 'Why Easy OIDC?'
weight: 2
---

Easy OIDC simplifies Kubernetes authentication by providing a minimal, opinionated OIDC provider. This page explains why you might choose Easy OIDC over alternatives.

## The Problem

Kubernetes supports multiple authentication methods, but each has trade-offs:

**Static Certificates/Tokens**:
- ✅ Simple to set up
- ❌ Long-lived credentials (security risk)
- ❌ No centralized revocation
- ❌ Credentials stored in kubeconfig files (can be leaked)
- ❌ Manual rotation required

**Cloud Provider IAM** (EKS/GKE/AKS):
- ✅ Integrated with cloud identity
- ❌ Vendor lock-in
- ❌ Doesn't work for on-prem or multi-cloud
- ❌ Complex IAM policies to manage

**Full-Featured Identity Providers** (Dex, Keycloak):
- ✅ Feature-rich (SSO, LDAP, SAML, dynamic groups, etc.)
- ❌ Complex to deploy and operate
- ❌ Requires persistent storage, databases, high availability
- ❌ Overkill if you just need Google/GitHub auth

## Easy OIDC's Approach

Easy OIDC is purpose-built for a common use case: **federated authentication to Kubernetes using Google or GitHub, with static group mappings**.

### Key Benefits

**1. Minimal Infrastructure**

A single VM instance. No databases, no load balancers, no complex HA setup (if you need to redeploy to another region/zone, it only takes 90 seconds). Caddy handles TLS automatically via Let's Encrypt.

**2. No Local Passwords**

Users authenticate with Google or GitHub. You don't manage passwords, 2FA, or password resets—Google/GitHub handles that.

**3. Short-Lived Tokens**

ID tokens expire after 1 hour. If a user leaves the organization, remove them from Google/GitHub and their access is revoked within the hour.

**4. Infrastructure as Code**

Entire deployment is Terraform-managed. Group mappings, client configurations, and all settings are in version control.

**5. Secure by Default**

- PKCE-only flows (prevents token theft)
- Kubernetes-compatible RS256 signing by default
- Automatic HTTPS via Let's Encrypt
- Secrets stored in cloud provider Secrets Manager (never in Terraform state)

## Comparison with Alternatives

### vs. Static Certificates

| Feature | Static Certs | Easy OIDC |
|---------|--------------|-----------|
| **Setup complexity** | Low | Medium |
| **Token expiry** | Manual (months/years) | Automatic |
| **Revocation** | Manual rotation | Remove from IdP |
| **Credential storage** | kubeconfig files | Browser-based flow |
| **Audit trail** | kubectl logs only | Upstream IdP + kubectl logs |

**Choose Easy OIDC if**: You want automatic expiry and centralized revocation.

### vs. Dex

[Dex](https://dexidp.io) is a fantastic OIDC provider with support for many identity backends (LDAP, SAML, GitHub, Google, OAuth2, etc.).

| Feature | Dex | Easy OIDC |
|---------|-----|-----------|
| **Upstream IdPs** | Many (LDAP, SAML, GitHub, Google, etc.) | Google or GitHub only |
| **Group resolution** | Dynamic (from IdP) | Static (config file) |
| **Deployment** | Kubernetes pod, persistent storage | Single EC2 instance |
| **Operational complexity** | Medium-High | Low |
| **Configuration** | CRDs/ConfigMaps | Terraform variables |

**Choose Easy OIDC if**: You only need Google/GitHub and prefer static group mappings over dynamic resolution.

**Choose Dex if**: You need LDAP, SAML, multiple IdPs, or dynamic group resolution.

### vs. Cloud Provider IAM (EKS, GKE, AKS)

| Feature | Cloud IAM | Easy OIDC |
|---------|-----------|-----------|
| **Vendor lock-in** | Yes | No |
| **Multi-cloud** | No | Yes |
| **Integration** | Native | Manual API server config |
| **Setup** | Automatic | Manual |

**Choose Easy OIDC if**: You're on-prem, multi-cloud, or want portability.

**Choose Cloud IAM if**: You're all-in on a single cloud provider and want tight integration.

### vs. Full IdP Solutions (Keycloak, Okta)

| Feature | Keycloak/Okta | Easy OIDC |
|---------|---------------|-----------|
| **Feature set** | Extensive (SSO, LDAP, SAML, etc.) | Minimal (OIDC only) |
| **Deployment** | Complex (HA, DB, etc.) | Single instance |
| **Cost** | High (ops time or SaaS fees) | Low (single t4g.nano) |
| **Learning curve** | Steep | Minimal |

**Choose Easy OIDC if**: You need simple Google/GitHub auth and don't want operational overhead.

**Choose Keycloak/Okta if**: You need enterprise SSO, SAML, LDAP integration, or advanced identity management.

## When NOT to Use Easy OIDC

Easy OIDC is intentionally minimal. Don't use it if you need:

- **Dynamic group resolution** from upstream IdP (e.g., Google Workspace groups, GitHub teams)
- **Multiple upstream IdPs** (e.g., both LDAP and Google)
- **SAML or other protocols** (Easy OIDC is OIDC-only)
- **High availability** (Easy OIDC is a single instance; downtime during replacement - though deployment takes less than 90 seconds)
- **Local user/password management** (Easy OIDC delegates all auth to Google/GitHub)

In these cases, consider [Dex](https://dexidp.io), [Keycloak](https://www.keycloak.org), or a commercial IdP.

## Use Cases

Easy OIDC works well for:

- **Small-to-medium teams** (<100 engineers) using Kubernetes
- **Startups** that want secure auth without IdP complexity
- **Platform teams** managing multiple clusters with different RBAC policies
- **On-prem Kubernetes** where cloud IAM isn't available
- **Multi-cloud deployments** needing consistent auth across clouds

## Security Model

Easy OIDC's security is based on:

1. **Upstream IdP trust**: Google/GitHub verifies user identity (email verification, 2FA, etc.)
2. **Short-lived tokens**: ID tokens expire after 1 hour (configurable)
3. **Cryptographic signing**: Configurable asymmetric keys sign all tokens; Kubernetes validates signatures
4. **PKCE enforcement**: Prevents authorization code interception attacks
5. **HTTPS everywhere**: Caddy provides automatic TLS with Let's Encrypt

**Threat model**:
- ✅ Protects against: Credential leaks (short-lived), token interception (PKCE), unauthorized access (upstream IdP)
- ❌ Single instance (no HA): Downtime during instance replacement (<90 seconds)
- ❌ Static group mappings: Changes require Terraform apply + restart

## Cost

**AWS resources** (us-east-1, approximate):
- EC2 t4g.nano: ~$3/month
- Data transfer: Minimal (<$1/month for typical usage)
- Secrets Manager: ~$0.80/month (2 secrets)

**Total**: ~$5/month for a single Easy OIDC instance serving multiple Kubernetes clusters.

Compare to:
- **Dex** (on Kubernetes): Similar cost, but requires persistent storage + operational overhead
- **Okta**: $2-$8/user/month (SaaS)
- **Keycloak** (self-hosted): Higher instance costs (needs database, HA setup)

## Next Steps

Ready to get started?

- [Understand OIDC basics](/docs/oidc-primer/)
- [Follow the Getting Started guide](/docs/getting-started/)
- [Deploy to AWS](/docs/deploy/aws/)
