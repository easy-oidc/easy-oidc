---
draft: false
title: 'App Integration Guide For Developers'
linkTitle: 'App Integration'
weight: 7
---

# App Integration Guide For Developers

This page describes a recommended way for developers to use Easy OIDC with their apps, using an SPA backed by a Go HTTP API as a reference example.

The goal is for browser apps, CLIs, and other clients to call the same API using
a consistent OIDC token model, while the application can still list active
sessions and revoke them immediately. See
[Concepts and terminology](/docs/concepts/) for definitions of the tokens and
protocol protections used below.

A **BFF** (backend for frontend) is an application backend that keeps OAuth tokens and
keys away from browser JavaScript and gives the browser a session cookie instead.

## Choose a browser architecture

For a browser application, choose one of two designs:

1. **Direct SPA with DPoP:** the browser owns the OAuth tokens and a non-extractable
  signing key, then calls the API directly.
2. **Backend for frontend (BFF):** the browser receives only an opaque, `HttpOnly`
  session cookie. The BFF owns the OAuth tokens and DPoP key.

Do not put ordinary Bearer tokens in browser JavaScript. A copied Bearer token can be
used from another machine until it expires or is revoked. DPoP binds a token to a key,
so copying the token alone is not enough.

DPoP does not make an SPA immune to cross-site scripting. Malicious same-origin code can
still ask the browser to sign requests while it is running. Continue to use a strict CSP,
escape untrusted content, minimize third-party scripts, and keep access tokens short-lived.

## Option 1: Direct SPA with DPoP

Use this design when the SPA must call the API directly rather than via a BFF.

```text
┌───────────────┐  code + PKCE + DPoP   ┌───────────┐
│ SPA + DPoP key│──────────────────────▶│ Easy OIDC │
└───────┬───────┘                       └───────────┘
        │ DPoP access token
┌───────▼───────┐
│ API           │
└───────────────┘
```

Configure a dedicated client with `dpop.mode: required` and `require_par: true`. Also set
`refresh_tokens.enabled: true` when the SPA needs refresh tokens, `sid`-based application
sessions, or grant revocation.

1. Create a non-extractable P-256 Web Crypto key for the login. Give each saved account
   or login session its own key; do not share one key across accounts.
2. Start Authorization Code + PKCE through `/par`, binding the request to that key.
3. Preserve `state`, the expected ID-token `nonce`, PKCE verifier, key, and key thumbprint
   as one pending login. On callback, verify and consume `state`.
4. Exchange the code with a fresh proof. Validate the ID token's signature, issuer,
   audience, expiry, and `nonce`, then compare `token_type` case-insensitively with
   `DPoP`.
5. Send the access token and a new proof to the API on every request.
6. Refresh and revoke with new proofs from the same key.

If the SPA and Easy OIDC use different origins, put a reverse proxy, API gateway, or CDN
configuration that you control in front of Easy OIDC. Configure it to answer browser
`OPTIONS` requests and allow only the SPA's exact origin. Permit `Content-Type` and
`DPoP` for `/par`, `/token`, and `/revoke`; permit `Authorization` and `DPoP` for
`/userinfo`; and let browser code read `WWW-Authenticate`. Easy OIDC does not provide
these CORS headers itself. The proxy must not change the public scheme, host, or path
advertised by Easy OIDC because each proof names the exact URL it was created for. If
the API is also on another origin, configure its CORS policy to allow `Authorization`
and `DPoP` from the SPA's exact origin.

Web Crypto prevents JavaScript from exporting a non-extractable private key, but the
SPA can still read its access and refresh tokens. Keep access tokens in memory where
possible. Keeping a refresh token in browser storage allows login to survive a reload,
but also makes that token available to malicious same-origin JavaScript. If persistence
is necessary, use a short refresh-token lifetime, bind the token with DPoP, and do not
treat `localStorage` as secure storage. If the browser loses the key or clears its
storage, the user must log in again.

See [DPoP integration](/docs/dpop/) for proof construction and endpoint details.

## Option 2: BFF with DPoP

Use this design when you can operate a same-site backend. It provides the strongest
browser token isolation because JavaScript in the browser cannot access the OAuth
tokens.

```text
┌─────────┐  opaque HttpOnly cookie  ┌──────────────────┐
│ SPA     │─────────────────────────▶│ BFF + DPoP key   │
└─────────┘                          └────────┬─────────┘
                                              │ DPoP tokens
                                  ┌───────────┴───────────┐
                                  ▼                       ▼
                            ┌───────────┐           ┌───────────┐
                            │ Easy OIDC │           │    API    │
                            └───────────┘           └───────────┘
```

The BFF performs Authorization Code + PKCE and owns the DPoP key, access token, and
refresh token. Configure refresh tokens when the application needs persistent sessions
or grant revocation. Before `/par`, create the key and a short-lived, single-use pending
login containing `state`, expected ID-token `nonce`, PKCE verifier, key, and thumbprint,
bound to the initiating browser.

If Easy OIDC is cross-site, use a separate opaque `Secure`, `HttpOnly`, `SameSite=Lax`
transaction cookie for the top-level callback. On callback, consume the pending login,
exchange the code with a fresh proof, and validate the ID token including `nonce`. Only
then issue or rotate the random application session cookie:

```http
Set-Cookie: __Host-app-session=<random-id>; Path=/; Secure; HttpOnly; SameSite=Strict
```

Store tokens and the DPoP key in server-side session storage, encrypted where practical.
If BFF replicas can serve the same session, they need shared access to that session's key
or deterministic routing to its owner. Never place the raw OAuth tokens in cookies.

The SPA calls the BFF with its session cookie. The BFF applies CSRF protection, then
either handles the operation itself or calls a downstream API with the DPoP access token
and a fresh proof. The BFF also creates fresh proofs for token refresh and revocation.

Cookie-authenticated state changes must verify `Origin` and require a custom header or
CSRF token in addition to an appropriate `SameSite` policy.

## Sessions and multiple accounts

Easy OIDC access tokens issued with a refresh grant contain its stable session ID
(`sid`), which the grant retains across rotation. When `sid` is present, keep an
application session record containing it, the issuer, subject, client ID, creation and
expiry times, and revocation state. Do not reactivate a revoked `sid` merely because an
old access token is presented again.

For multiple simultaneous accounts, give each saved login a local slot. For example, an
SPA might store work account `user+work@example.com` as slot `1` and personal account
`user+personal@example.com` as slot `2`; each slot has its own DPoP key, tokens, and cached data.
A BFF can use the slot in the session-cookie name, while a direct SPA can use it in its
local account record. The slot only selects local state—it does not prove who the user
is. Include it in cache keys so one account cannot reuse another account's cached data.

## API validation

This section applies to both designs whenever an API receives a DPoP access token. With
Option 1, the SPA sends the token to the API. With Option 2, the BFF sends it to the API;
the browser-to-BFF request uses the session cookie instead.

Validate the JWT before reading application session state:

1. Verify its signature using Easy OIDC's JWKS. Cache keys and rate-limit refreshes so
   forged tokens cannot cause an upstream request flood.
2. Validate issuer, intended audience, expiry, token purpose, and required scopes or
   groups.
3. Inspect `cnf.jkt`. If present, require `Authorization: DPoP`, validate the proof and
   `ath`, match its key thumbprint, and reserve its `jti` in replay storage shared by all
   API replicas. Never accept that token as Bearer.
4. If `cnf.jkt` is absent, accept only Bearer and only for a client intentionally
   configured for Bearer access.
5. If `sid` is present, apply a bounded per-`sid` rate limit, then reject expired or
   revoked application sessions.

Resource servers that do not share the application session check may continue accepting
an otherwise valid access token until it expires.

## Logout and revocation

Logging out should:

1. mark the application session's `sid` revoked;
2. revoke the refresh grant with Easy OIDC using the correct DPoP proof; and
3. delete browser, BFF, or local credentials even if remote revocation fails.

The application session check makes logout immediate for that API. Easy OIDC's
`GET /grants` also lets a user list and revoke active refresh grants without creating a
new token-bearing session. Already-issued stateless access tokens remain valid at APIs
that do not consult application revocation state.

## CLI and other direct clients

Register CLIs and automation under separate client IDs. Prefer DPoP when the client can
protect a persistent signing key; use Authorization Code + PKCE with a loopback callback
for interactive CLIs. Store tokens and keys in the operating-system credential store,
or in files with restrictive permissions when no credential store exists.

Bearer can remain available for clients that cannot implement DPoP, but keep those
clients separate and accept the greater consequence of token theft. Browser and BFF
endpoints must reject requests that present conflicting cookie and `Authorization`
credentials.
