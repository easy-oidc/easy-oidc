---
draft: false
title: 'Concepts and terminology'
linkTitle: 'Concepts'
weight: 2
---

Truster sits between the service that signs a user in, and the application or
Kubernetes cluster that uses the resulting identity. This page defines the
terms needed to configure and integrate it.

## People, applications, and identity

- An **issuer** is the authority that creates tokens. Its URL identifies that
  authority and must exactly match the token's `iss` claim. In a downstream
  login, Truster is the issuer.
- A **client** is an application that asks Truster to sign someone in or
  issue tokens. Each client has an ID and an explicit configuration.
- A **redirect URI** is the exact client URL to which Truster returns the
  browser after sign-in. It must be registered for the client; it is not an
  arbitrary destination.
- An **upstream connector** (or **provider**) connects Truster to the service
  where the person signs in, such as Google, GitHub, a generic OIDC provider,
  or email-code authentication.
- A **subject** is the identity named by a token's `sub` claim. Truster
  normally uses a normalized email address for an interactive user's subject.
- An **audience** identifies who a token is intended for through its `aud`
  claim. A recipient must reject a token not intended for it.
- A **claim** is a named fact in a token, such as `sub`, `email`, `groups`,
  `iss`, or `aud`.

The upstream provider authenticates its own account. Truster decides whether
to accept that result and maps it to the identity, subject, and claims it
issues. Truster does not decide what that identity may do in an application
or cluster: downstream APIs enforce application authorization, and Kubernetes
enforces its own RBAC.

## Tokens and keys

A **token** is a credential issued for a specific purpose. Truster issues
short-lived ID and access tokens as signed JSON Web Tokens (JWTs); both have a
15-minute lifetime by default.

- An **ID token** tells the client who completed the login. Clients validate it
  as part of the sign-in flow. Kubernetes integrations intentionally use an ID
  token as the API credential.
- An **access token** is sent to a protected API. The API must validate the
  token and decide whether its claims permit the requested operation.
- A **refresh token** is a longer-lived credential used to obtain new tokens
  without another login. Refresh tokens are optional and require stronger
  storage and revocation handling.
- A **JWT** (JSON Web Token) is a signed, compact set of claims. A **JWK**
  (JSON Web Key) describes a cryptographic key; Truster publishes a set of
  public JWKs (a JWKS) so token recipients can verify JWT signatures.

Truster signs tokens, but each downstream API and Kubernetes API server
remains responsible for validating the signature, issuer, audience, expiry,
token purpose, and any required claims before trusting one.

## Flow protections

- **PKCE** binds an authorization code to the client that started the login.
  Truster requires it for every client, preventing an intercepted code from
  being redeemed without the original verifier.
- **PAR** (Pushed Authorization Requests) sends the authorization request
  directly to Truster before the browser redirect. The redirect carries a
  short-lived reference, so browser URL changes cannot alter protected request
  details such as the redirect URI, PKCE challenge, or DPoP key binding.
- **DPoP** binds access and refresh tokens to a client-held cryptographic key.
  Copying a token is then insufficient to use it elsewhere. The client creates
  a fresh proof for each request, and every receiving API must validate both
  the token and proof. DPoP does not bind ID tokens or replace authorization.

## State, policy, and external trust

**Protocol state** is operational data needed to complete secure flows, such as
pending browser logins, authorization codes, and refresh grants. It belongs in
the state database. 

**Policy** is the current decision data—such as configured clients, allowed 
users, groups, and trust bindings—that controls whether Truster may issue
credentials and which claims they contain.

For non-human external OIDC and CI identities, Truster separates trust into
three practical layers:

- A **trust issuer** (`service_token_issuers`) defines an external token
  authority Truster can verify.
- A **trust policy** defines reusable claim requirements for tokens from that
  issuer.
- A **trust binding** authorizes one of those policies for a particular Truster
  client, adds any narrower claim requirements, and maps a successful
  match to a subject and groups.

Trust evaluation requires exactly one matching binding. Truster and its
policy database **fail closed**: when required data is invalid or unavailable,
or a trustworthy decision cannot be made, Truster refuses to issue a token
rather than using stale data or guessing.

## Next steps

- [Learn how OAuth2 and OIDC work](/docs/oidc-primer/)
- [Set up a sign-in provider](/docs/upstream/)
- [Integrate an application](/docs/app-integration/)
- [Configure Kubernetes](/docs/kubernetes/)
- [Read the configuration reference](/docs/config/)
