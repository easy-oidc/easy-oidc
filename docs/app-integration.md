---
draft: false
title: 'App Integration Guide For Developers'
linkTitle: 'App Integration'
weight: 7
---

# App Integration Guide For Developers

This page describes a recommended way for developers to use Easy OIDC with their apps, using an SPA backed by a Go HTTP API as a reference example.

The goal is to use the same OIDC access tokens for browser, CLI, and direct API access while retaining API-managed session listing and immediate revocation.

## Requirements & Assumptions

This design assumes:

- A single-page application (SPA) with a Go HTTP API backend
- Browser credentials must only be stored in `Secure`, `HttpOnly` cookies
- One browser may be logged in as multiple users concurrently
- CLI and other API clients use OAuth bearer tokens
- The Go API records sessions and revocations in its database (for example, PostgreSQL), but does not store raw access tokens
- Easy OIDC issues access and rotating refresh tokens with a stable session identifier (`sid`), and supports refresh-token revocation
- Refresh re-evaluates whether the user is still permitted by current Easy OIDC & upstream provider policy

> **Important:** Easy OIDC does not currently issue refresh tokens. Refresh tokens, a stable `sid`, and refresh-token revocation are prerequisites for implementing this design as written.

## Architecture

```text
SPA/browser ── HttpOnly cookies ──┐
                                  ▼
CLI/API ────── Bearer JWT ─────▶ Go HTTP API ◀── Code + PKCE ──▶ Easy OIDC
                                  │
                                  │ session state
                                  ▼
                   Application database (e.g. PostgreSQL)
```

Easy OIDC authenticates users and issues tokens. The Go API validates those tokens and remains authoritative for application session revocation.

The application database stores the token's stable `sid`, user identity, timestamps, client ID, and revocation status. It does not store the raw access token. Revoked session records must remain until all associated tokens can no longer be used.

## SPA and browser sessions

The Go API handles the OAuth flow on behalf of the SPA:

1. The Go API starts Authorization Code + PKCE with `state` and `nonce` flow.
2. Its callback handler exchanges the authorization code with Easy OIDC.
3. It creates an application session for the token's `sid`.
4. It places the access and refresh tokens in `Secure`, `HttpOnly` cookies. Access token cookies should use a short `Max-Age` matching the token lifetime. Refresh token cookies should use a longer `Max-Age` matching the refresh token lifetime. This ensures cookies expire even if the browser is not open when a server-side revocation occurs.
5. It refreshes the tokens when the access token approaches expiry.

Tokens are never exposed to SPA JavaScript due to the use of `HttpOnly` cookies.

### Multiple concurrent users

Assign each logged-in account a non-secret, browser-local slot number and include it in that account's cookie names:

```http
Set-Cookie: __Host-easy-oidc-access-0=<access-token>; Path=/; Secure; HttpOnly; SameSite=Strict
Set-Cookie: __Host-easy-oidc-refresh-0=<refresh-token>; Path=/; Secure; HttpOnly; SameSite=Strict

Set-Cookie: __Host-easy-oidc-access-1=<access-token>; Path=/; Secure; HttpOnly; SameSite=Strict
Set-Cookie: __Host-easy-oidc-refresh-1=<refresh-token>; Path=/; Secure; HttpOnly; SameSite=Strict
```

The SPA sends the selected slot in the URL, query parameter, or a header such as `X-Auth-Slot: 0`. The Go API uses that value to select the matching cookie. The slot number is only a selector and must never be accepted as proof of authentication.

This allows one tab to use slot `0` while another uses slot `1`. Include the slot number in client-side query cache keys so data from different users cannot share a cache entry.

Cookie-authenticated requests require CSRF protection. Use `SameSite`, verify `Origin`, and require a custom header or CSRF token for state-changing requests.

### Session management

The Go API can expose endpoints that list active and recent sessions from its database. A session record should include:

- `sid`, issuer, subject, and client ID
- Creation, last-used, expiry, and revocation times
- A user-provided device name and approximate user agent/IP metadata

Logging out a session should:

1. Mark its `sid` revoked in the application database.
2. Revoke its refresh token with Easy OIDC.
3. Expire its access and refresh cookies when logging out the current browser.

Revoking the database session makes logout immediate for this application even if an access JWT has not expired. Remote logout cannot delete another browser's cookies immediately, but the revoked `sid` causes the API to reject them. On the browser's next request, the API should expire the selected slot's cookies and return `401 Unauthorized`; the SPA can then start a new login flow.

## CLI access

A CLI should be registered as its own public client and use Authorization Code + PKCE with a loopback callback:

1. Open the user's browser for authentication.
2. Exchange the authorization code for access and refresh tokens.
3. Store tokens using the operating system credential store, or a file with restrictive permissions when no credential store is available.
4. Send the access token as `Authorization: Bearer <token>`.
5. Refresh it directly with Easy OIDC when needed.

The Go API validates the token and creates or updates its application session from `sid`. A revoked `sid` must never be recreated as active merely because the same token is presented again.

A CLI logout command should:

1. Call the Go API to revoke the current `sid`.
2. Revoke the refresh token with Easy OIDC.
3. Delete its locally cached access and refresh tokens, even if either remote revocation request fails.

## Direct API access

Scripts, `curl`, and other OAuth-capable clients use the same bearer-token interface:

```http
Authorization: Bearer <access-token>
```

Each client should have a registered client ID, and the Go API must allow only expected audiences. Direct clients obtain tokens through Authorization Code + PKCE; direct API access is not a separate grant and does not imply password, static-token, or client-credentials support.

Browser endpoints should use cookies, while non-browser endpoints should use the `Authorization` header. Reject requests that provide conflicting credentials through both mechanisms.

## API validation

For every authenticated request, the Go API must:

1. Verify the JWT signature using Easy OIDC's JWKS. Cache the JWKS locally and refresh it periodically (for example, every 5 minutes). If a signature verification fails and the JWKS has not been refreshed within the last 60 seconds, fetch it again before rejecting the token — this handles key rotation gracefully. Do not allow verification failures to trigger fetches more frequently than this floor to prevent an attacker from using forged tokens to force excessive upstream requests.
2. Validate issuer, audience, expiry, and required claims.
3. Apply authorization using the token's groups or scopes.
4. Look up `sid` and reject expired or revoked application sessions.

Refresh tokens improve continuity, but application revocation still requires the database check. Any other resource server that does not check the same session state may continue accepting an access token until it expires.

To protect the session database from request floods, validate the JWT first, then apply a per-`sid` rate limit before looking up the session. Keep limiter entries in a bounded in-memory LRU so they cannot consume unbounded memory. Because `sid` is read only from a verified token, an attacker must possess valid tokens for enough distinct sessions to churn the LRU.
