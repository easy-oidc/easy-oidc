---
draft: false
title: 'Why Easy OIDC?'
linkTitle: 'Why Easy OIDC?'
weight: 2
---

Easy OIDC lets people sign in to Kubernetes with an account they already have or
a code sent by email. It gives Kubernetes a verified email address and the
groups you configured, without storing user passwords.

## The problem it solves

Kubernetes can verify short-lived login tokens, but it does not provide a login
page or manage human identities. Teams therefore need a trusted service that can
authenticate each user and tell Kubernetes who they are.

Easy OIDC provides that service. Users sign in through a browser instead of
sharing long-lived certificates or tokens. Kubernetes still owns authorization:
its role-based access control (RBAC) rules decide what each user and group may do.

## How it works

Easy OIDC runs as one binary. It delegates authentication to Google, GitHub, a
compatible OAuth2/OIDC provider, or a one-time code sent by email. It then
normalises the email address and looks up the groups configured for that user.

Several sign-in methods can share one issuer URL, which is the address that Kubernetes
trusts. A user receives the same downstream identity when different methods
verify the same email address.

## Why teams choose it

1. **Small infrastructure footprint.** A single replica can use embedded SQLite,
   with no separate database or administration service. PostgreSQL is available
   for shared protocol state and multiple replicas.
2. **No local passwords.** Sign-in providers keep responsibility for account
   security and multi-factor authentication. Email sign-in uses short-lived
   codes instead of creating a password database.
3. **Consistent identity.** Every sign-in method produces the same simple email
   identity and configured group claims for Kubernetes.
4. **Reviewable policy.** Client definitions and email-to-group mappings can live
   in JSONC configuration and follow the same review process as other
   infrastructure. Policy can also come from PostgreSQL when needed.
5. **Short-lived access.** Tokens expire automatically, login codes are
   single-use, and public clients must use PKCE to complete the login they
   started.

## A good fit when

- You run Kubernetes and want browser-based login for people.
- Your users already have Google, GitHub, or compatible OAuth2/OIDC accounts, or
  you can send them email codes.
- Email addresses are appropriate stable identities in your environment.
- User and group lists are small enough to review as configuration, or you can
  provide them from the policy database.
- You want the same issuer and identity model across several clusters or
  environments.

## Not a fit when

Choose an identity system designed for broader requirements when you need:

- LDAP, SAML, local users, passwords, or account lifecycle management;
- dynamic Google Workspace groups, GitHub teams, or other upstream group claims;
- immediate revocation of already-issued tokens;
- a built-in, supported high-availability control plane;
- identity features or OAuth flows beyond Easy OIDC's documented scope; or
- policy that cannot be represented safely as email-to-group mappings.

## Security and operational boundaries

Easy OIDC uses short-lived, asymmetrically signed tokens. Authorization codes are
opaque and single-use, clients must use PKCE, and production endpoints are
expected to use HTTPS. Email verification can trust a provider's assertion,
verify only when needed, or always require a local email code.

These safeguards limit the value of a copied login code or cached token. They do
not provide immediate revocation of an issued token, recover a compromised
signing key, or make a single-replica deployment highly available.

The simplest deployment is one process with SQLite. PostgreSQL can provide
shared state for replicas, but operators remain responsible for the deployment's
availability.

Static group policy changes require a configuration deployment. Database-backed
policy changes take effect when policy is next evaluated, subject to documented
caches. In both cases, an existing token remains valid until it expires.

Disabling one sign-in method does not block another enabled method that can
verify the same email. Access policy must account for every enabled method and
for the possibility that an email address is renamed or reassigned.

## Next steps

- [Try Easy OIDC or choose a deployment](/docs/getting-started/)
- [Deploy to AWS](/docs/deploy/aws/)
- [Understand the login flow](/docs/oidc-primer/)
- [Read the configuration reference](/docs/config/)
