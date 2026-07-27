---
draft: false
title: 'Understanding OAuth2 and OIDC'
linkTitle: 'OIDC Primer'
weight: 1
---

This page provides a beginner-friendly introduction to OAuth2 and OpenID Connect (OIDC), the technologies that power Easy OIDC.

## What is OAuth2?

OAuth2 is a protocol that lets applications request access to user accounts on other services. Think of it as a secure way to say "I'd like to log in using my Google/GitHub account" without giving your password to the application.

### Key Concepts

**Authorization Server**: The service that manages user authentication (e.g., Google, GitHub)

**Client**: The application requesting access (e.g., kubectl, your Kubernetes cluster)

**Resource Owner**: The user (you!)

**Redirect URI**: Where the authorization server sends the user back after login

## What is OpenID Connect (OIDC)?

OIDC is a layer on top of OAuth2 that adds **identity**. While OAuth2 focuses on authorization ("can this app access my data?"), OIDC answers "who is this user?"

OIDC provides:
- **ID Token**: A signed JWT containing user information (email, name, groups)
- **UserInfo Endpoint**: An API to fetch additional user details
- **Standard Claims**: Predictable fields like `email`, `sub` (subject/user ID), `email_verified`

## How Easy OIDC Uses OIDC

When you authenticate to a Kubernetes cluster using Easy OIDC:

1. **kubectl** (via kubelogin) initiates an OIDC login
2. **Easy OIDC** redirects you to Google or GitHub to log in
3. After successful login, **Google/GitHub** redirects back to Easy OIDC
4. **Easy OIDC** verifies your email and looks up your groups
5. **Easy OIDC** issues an **ID token** (a signed JWT) containing your email and groups
6. **kubectl** sends this token with every API request
7. **Kubernetes API server** validates the token and enforces RBAC based on your groups

## PKCE: Extra Security for Public Clients

Easy OIDC requires **PKCE** (Proof Key for Code Exchange, pronounced "pixie"). This prevents token theft when the OAuth client (kubectl) can't keep secrets secure.

**Without PKCE**: An attacker could intercept the authorization code and exchange it for tokens

**With PKCE**: The client generates a random `code_verifier`, sends a hashed `code_challenge` during authorization, and must provide the original `code_verifier` when exchanging the code for tokens. An attacker can't do this without the original verifier.

## Why OIDC for Kubernetes?

**Traditional approach**: Distribute kubeconfig files with long-lived certificates or static tokens
- ❌ Credentials live forever (or until manual expiration)
- ❌ No centralized revocation
- ❌ Credentials stored in files that can be leaked

**OIDC approach**: Users authenticate with their corporate identity provider
- ✅ Tokens expire automatically (typically 1 hour)
- ✅ Revoke access by removing user from upstream IdP (Google/GitHub)
- ✅ Tokens are short-lived and refreshed automatically
- ✅ Centralized audit trail of who accessed what

## Next Steps

Now that you understand the basics, you can:
- [Set up an upstream provider](/docs/upstream/)
- [Deploy Easy OIDC to AWS](/docs/deploy/aws/)
- [Configure Kubernetes to use OIDC](/docs/kubernetes/)
