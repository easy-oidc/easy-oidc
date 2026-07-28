---
draft: false
title: 'Why Easy OIDC?'
linkTitle: 'Why Easy OIDC?'
weight: 2
---

Easy OIDC provides a small, opinionated bridge between the identity systems a
team already uses and Kubernetes OIDC authentication.

## The problem

Kubernetes supports several authentication approaches, but the common choices
have different operational and security costs:

- **Static certificates and tokens** are easy to bootstrap, but are commonly
  long-lived, copied into kubeconfig files, manually rotated, and difficult to
  revoke centrally.
- **Cloud-provider IAM** integrates tightly with a managed Kubernetes service,
  but couples access to one cloud's identity and policy model and does not provide
  one portable approach for on-premises or multi-cloud clusters.
- **Full identity providers** such as Dex and Keycloak support broader protocols,
  directories, and policy, but also introduce more configuration and operational
  surface than every team needs.

Easy OIDC targets the gap between static credentials and a general-purpose
identity platform: browser-based, short-lived Kubernetes credentials backed by
existing sign-in methods and reviewable static group policy.

## The approach

Easy OIDC runs as one binary with embedded SQLite. It delegates authentication
to Google, GitHub, generic OAuth2/OIDC providers, or typed email codes, then maps
the resulting email to static groups.

You can configure several sign-in methods behind one issuer. That is useful when
teams span multiple Google Workspace or Dex instances, or when email codes are a
fallback. A normalized email remains the downstream identity regardless
of which connector was used.

### Key benefits

1. **Small infrastructure footprint.** One process and an embedded SQLite
   database; no external database, directory, or administration service is
   required. The AWS and Google Cloud modules can deploy it behind Caddy for
   automatic TLS.
2. **No local passwords.** OAuth connectors delegate account security and MFA to
   the upstream provider. Direct email authentication uses short-lived typed
   codes rather than creating a password database.
3. **Portable identity.** The issuer and Kubernetes configuration are independent
   of EKS, GKE, or AKS IAM, and one issuer can serve clusters in several
   environments.
4. **Reviewable policy.** Client definitions and static email-to-group mappings
   live in JSONC configuration and can be deployed through normal review and
   infrastructure-as-code workflows. Official OpenTofu/Terraform deployment
   modules are available for AWS and Google Cloud.
5. **Secure defaults.** PKCE S256 is mandatory, downstream clients are public,
   authorization codes are opaque and single-use, and RS256 is the default token
   signing algorithm for broad Kubernetes compatibility.

## Why it stays small

Easy OIDC deliberately avoids becoming a general identity-management system:

- No passwords or password-reset flows.
- No SAML, LDAP, or dynamic upstream-group synchronization.
- No administration UI or local user directory.
- No external database to provision.
- No downstream confidential clients or non-PKCE authorization flows.

Static email-to-group policy works well when access lists are small enough to
review in configuration and Kubernetes RBAC remains the authorization layer.

## Security defaults

- Authorization Code flow with mandatory PKCE S256.
- Short-lived, asymmetrically signed tokens.
- Opaque, single-use authorization codes and replay-protected browser state.
- Email verification can be disabled, provider-aware, or strict.
- Optional strict local email verification regardless of provider assertions.
- Authenticated SMTP with TLS by default and optional Turnstile protection for
  direct email.
- Secrets loaded from cloud secret stores or environment variables at startup.

The security model relies on five boundaries:

1. **Upstream identity trust.** OAuth providers supply stable account identities
   and email assertions. Easy OIDC can require local email verification when an
   assertion is unverified, or always in strict mode.
2. **Downstream identity normalization.** Only a normalized email is exposed as
   `sub`, so provider-specific account IDs remain internal. The
   `email_verified` claim reports whether verification evidence was accepted.
3. **Short credential lifetime.** ID tokens default to a one-hour lifetime and
   can be configured shorter. Existing tokens remain valid until expiry.
4. **Cryptographic separation.** Signing, OTP, SMTP, challenge, and encryption
   secrets have distinct purposes; selection-token keys are derived with
   versioned domain separation.
5. **TLS boundaries.** Public OIDC endpoints are expected to be served over HTTPS.
   SMTP uses TLS by default. Plaintext SMTP is restricted to `localhost` and emits
   a prominent startup warning.

These properties reduce the impact of copied kubeconfig data and intercepted
authorization codes. They do not provide immediate token revocation, protect a
compromised signing key, or make a single-instance deployment highly available.

## Comparison with alternatives

### Static certificates and tokens

| Capability | Static credentials | Easy OIDC |
|---|---|---|
| Credential lifetime | Commonly months or years | Short-lived and configurable |
| User authentication | Possession of a file or token | Browser-based upstream authentication |
| Rotation | Manual replacement | Automatic re-authentication after expiry |
| Central access policy | Limited | Static group maps plus upstream account controls |
| Local kubeconfig | Contains the credential | Uses an exec plugin and token cache |
| Authentication records | Primarily Kubernetes audit logs | Upstream provider plus Kubernetes audit logs |

Choose Easy OIDC when automatic expiry, browser sign-in, and centrally reviewed
group policy justify operating an issuer.

### Dex

[Dex](https://dexidp.io) is a mature OIDC provider with connectors for LDAP,
SAML, and other identity systems. Easy OIDC can itself use Dex as one or more
generic upstream connectors.

| Capability | Dex | Easy OIDC |
|---|---|---|
| Upstream connectors | Broad, including LDAP and SAML | Google, GitHub, OAuth2/OIDC, and email codes |
| Multiple upstreams | Yes | Yes |
| Group resolution | Connector-dependent and often dynamic | Deliberately static configuration |
| Typical deployment | Commonly Kubernetes-managed | Single binary, commonly on one VM |
| Intended scope | Federation service | Narrow Kubernetes identity bridge |

Choose Easy OIDC when email identity and static group mappings are the desired
policy model. Choose Dex when LDAP, SAML, additional connector types, or dynamic
upstream claims are requirements. They are also complementary when Dex handles a
complex upstream and Easy OIDC provides the downstream email and group policy.

### Cloud-provider IAM

| Capability | EKS/GKE/AKS IAM | Easy OIDC |
|---|---|---|
| Managed-service integration | Native | Requires OIDC configuration |
| Portability between clouds | Provider-specific | One issuer and identity model |
| On-premises clusters | Generally unavailable | Supported where Kubernetes accepts OIDC |
| Policy model | Cloud IAM and cluster integration | Email identity plus Kubernetes RBAC groups |

Choose cloud IAM when all clusters and users already live within one provider's
identity model. Choose Easy OIDC when portability or a consistent cross-cloud
login experience matters more than native integration.

### Keycloak, Okta, and other full identity platforms

| Capability | Full identity platform | Easy OIDC |
|---|---|---|
| SAML, LDAP, directories, lifecycle workflows | Usually available | Not provided |
| Local users and passwords | Usually available | Not provided |
| Advanced policy and application SSO | Broad | Narrow Kubernetes-focused policy |
| High-availability options | Common | Deployment responsibility of the operator |
| Operational and configuration surface | Broader | Smaller |

Choose a full platform when identity lifecycle, enterprise protocols, application
SSO, advanced policy, or a managed HA identity tier is required. Choose Easy OIDC
when those capabilities already exist upstream or are unnecessary.

## Good fits

- Small and medium platform teams using Kubernetes.
- Multiple clusters sharing one issuer but using different client group maps.
- On-premises or multi-cloud clusters where cloud-specific IAM is undesirable.
- Teams aggregating a small number of existing OAuth2/OIDC providers.
- Environments that want email-code authentication without maintaining passwords.

## When not to use Easy OIDC

Use a different solution when you require:

- LDAP, SAML, local users, passwords, or account lifecycle management.
- Dynamic Google Workspace groups, GitHub teams, or other upstream group claims.
- Immediate revocation of already-issued tokens.
- A supported, built-in high-availability control plane.
- Non-Kubernetes application SSO features or OAuth flows beyond Authorization
  Code with PKCE.
- Policy that cannot be represented safely as reviewed static email-to-group
  mappings.

Dex, Keycloak, a cloud-provider IAM integration, or a commercial identity
platform may be a better fit in those cases.

## Cost model

Easy OIDC's direct infrastructure is normally one small compute instance, its
root storage, DNS and network traffic, and whichever secret store is selected.
One issuer can serve multiple Kubernetes clusters, so those costs do not
necessarily scale per cluster.

Exact prices vary by region and provider and should be checked against current
pricing. AWS Secrets Manager charges per secret, while standard AWS Systems
Manager Parameter Store parameters are free. Advanced parameters and higher API
throughput can incur charges. The larger cost distinction is usually operational:
Easy OIDC avoids an external database and identity-management tier, whereas a
fuller self-hosted IdP may require both. A SaaS identity provider moves that work
to a subscription, often priced per user.

## Operational boundaries

Easy OIDC is a single process and does not itself provide a high-availability
deployment architecture. Group policy changes require configuration deployment,
and existing tokens remain valid until their configured expiry. Removing a user
from one upstream provider does not revoke another configured sign-in method that
can verify the same email; authorization policy must account for every enabled
method.

## Next steps

- [Understand the OIDC flow](/docs/oidc-primer/)
- [Read the configuration reference](/docs/config/)
- [Follow the getting started guide](/docs/getting-started/)
- [Configure Kubernetes](/docs/kubernetes/)
- [Deploy to AWS](/docs/deploy/aws/)
- [Deploy to Google Cloud](https://github.com/easy-oidc/terraform-google-easy-oidc/blob/main/README.md#usage)
