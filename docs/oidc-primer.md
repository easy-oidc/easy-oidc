---
draft: false
title: 'Understanding OAuth2 and OIDC'
linkTitle: 'OIDC Primer'
weight: 1
---

This page provides a beginner-friendly introduction to OAuth2 and OpenID
Connect (OIDC), the technologies that power Truster. See
[Concepts and terminology](/docs/concepts/) for a concise reference to the
terms used throughout the documentation.

## What is OAuth2?

OAuth2 is a protocol that lets applications request access to user accounts on
other services. Think of it as a secure way to sign in through an existing
identity provider without giving your password to the application.

### Key concepts

**Authorization server:** The service that manages user authentication, such
as Google, GitHub, or Truster.

**Client:** The application requesting access, such as kubectl or your own
application.

**Resource owner:** The user granting access.

**Redirect URI:** The registered URL where the authorization server sends the
browser after login.

## What is OpenID Connect (OIDC)?

OIDC is a layer on top of OAuth2 that adds **identity**. While OAuth2 focuses on
authorization—“can this application access a protected resource?”—OIDC answers
“who is this user?”

OIDC provides:

- **ID token:** A signed JWT containing identity claims such as the subject,
  email, and groups.
- **UserInfo endpoint:** An API through which a client can retrieve identity
  claims using an access token.
- **Standard claims:** Predictable fields such as `sub`, `email`, and
  `email_verified`.

## How Truster uses OIDC

When you authenticate to a Kubernetes cluster using Truster:

1. **kubectl**, through kubelogin, starts an OIDC login.
2. **Truster** selects the only configured provider or displays its sign-in
   selector.
3. You authenticate with an upstream provider or an email code.
4. **Truster** establishes an email identity, applies the configured email
   verification policy, and looks up your groups.
5. **Truster** issues an ID token—a signed JWT—containing your email and
   groups.
6. **kubectl** sends this token with each Kubernetes API request.
7. The **Kubernetes API server** validates the token and enforces RBAC using
   its subject and groups.

Truster handles authentication and identity claims. Kubernetes remains
responsible for authorization: its RBAC rules decide what that identity may do.

## PKCE: extra security for public clients

Truster requires **PKCE** (Proof Key for Code Exchange, pronounced “pixie”).
This protects clients such as kubelogin and browser applications that cannot
safely keep a client secret.

**Without PKCE:** An attacker who intercepts an authorization code may be able
to exchange it for tokens.

**With PKCE:** The client generates a random `code_verifier`, sends a hash of it
as the `code_challenge` when starting authorization, and must provide the
original verifier when exchanging the code. An attacker who obtains only the
authorization code cannot complete that exchange.

## Why use OIDC for Kubernetes?

**Traditional approach:** Distribute kubeconfig files containing long-lived
certificates or static tokens.

- Credentials may remain valid for a long time.
- Revocation often requires replacing credentials or certificate authority
  configuration.
- Credential files can be copied or leaked.

**OIDC approach:** Users authenticate through an existing identity provider and
receive short-lived tokens.

- Truster ID tokens expire after 15 minutes by default.
- Upstream access can be removed through the relevant identity provider and
  Truster policy.
- kubelogin can start a new login when fresh credentials are needed.
- Kubernetes audit records identify the token subject and groups used for each
  request.

## Next steps

- [Review concepts and terminology](/docs/concepts/)
- [Set up an upstream provider](/docs/upstream/)
- [Deploy Truster](/docs/deploy/)
- [Configure Kubernetes to use OIDC](/docs/kubernetes/)
