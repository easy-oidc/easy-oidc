# End-to-end login flows

The E2E test runs a DPoP login followed by four bearer-token login flows against
one Dex server. The static flows run before their database policy equivalents.
Distinct client IDs ensure both policy sources are exercised in the same
Truster replica pair.

PostgreSQL supplies both read-only policy and authoritative protocol state. Two
Truster replicas share it and all secrets behind a local round-robin proxy, so
the complete login and refresh flows naturally cross replicas. The script
restarts both replicas before refresh, rejects any SQLite `.db` file, then stops
PostgreSQL to verify fail-closed readiness and protocol behavior before proving
both running replicas recover when PostgreSQL returns.

The test opens Dex interactively in a terminal and runs its mock connector
headlessly under CI or other non-interactive runners. Set `E2E_HEADLESS=true` or
`E2E_HEADLESS=false` to override detection.

Install the external clients with `brew install oauth2c kubelogin` before
running `make e2e`. The suite is pinned to a `oauth2c` version; CI downloads that
release directly.

## DPoP Login with PAR

The Go-based `oauth2c` client independently discovers Truster, pushes an
authorization request with PAR, completes an authorization-code flow with PKCE,
exchanges the code using DPoP, and refreshes with the same key. A small helper
built on `go-dpop` then checks token binding, UserInfo access, cross-replica
replay rejection, bearer downgrade rejection, revocation, and post-revocation
failure. Its separate Go module keeps E2E-only dependencies out of the server.

## Trusted Service Login

```mermaid
sequenceDiagram
    autonumber
    participant Script as E2E Script<br/>(simulated service)
    participant Truster as Truster Server
    participant Dex as Dex Server

    Script->>Dex: Request external OIDC token<br/>client: static-ci-token-exchange-e2e
    Dex-->>Script: Dex ID token<br/>An OIDC token like a CI provider supplies<br/>aud: static-ci-token-exchange-e2e
    Script->>Truster: Login using trusted token<br/>client: static-ci-token-exchange-e2e
    activate Truster
    Truster->>Dex: Fetch OIDC metadata and signing keys
    Dex-->>Truster: OIDC metadata and signing keys
    Truster->>Truster: Verify signature and validate claims
    Truster->>Truster: Match dex-static-e2e policy
    Truster->>Truster: Apply dex-static-exchange-e2e binding
    Truster->>Truster: Mint service token
    Truster-->>Script: Truster service token<br/>sub: trusted:e2e:static<br/>groups: [e2e:static]
    deactivate Truster
```

## User Interactive Login

```mermaid
sequenceDiagram
    autonumber
    participant Script as E2E Script<br/>(kubelogin + browser)
    participant Truster as Truster Server
    participant Dex as Dex Server

    Script->>Truster: Begin user login<br/>client: static-kubelogin-interactive-e2e
    Truster->>Dex: Delegate user authentication<br/>client: truster-interactive-e2e
    Dex-->>Script: Show sign-in page
    Script->>Dex: Sign in as test user
    Dex-->>Truster: Return user identity
    activate Truster
    Truster->>Truster: Validate identity and apply static user group mapping
    Truster->>Truster: Mint authorization code
    Truster-->>Script: Return authorization code to kubelogin
    deactivate Truster
    Script->>Truster: Exchange authorization code
    activate Truster
    Truster->>Truster: Mint user and refresh tokens
    Truster-->>Script: Truster user token
    deactivate Truster
    Script->>Script: Wait for user token to expire
    Script->>Truster: Refresh without another browser login
    Truster-->>Script: Fresh Truster user token with configured groups
```

The server log is checked after these flows to prove neither static client
caused a policy database query.

## Trusted Service Login from Database Policy

```mermaid
sequenceDiagram
    autonumber
    participant Script as E2E Script<br/>(simulated service)
    participant Truster as Truster Server
    participant PG as Policy database<br/>(PostgreSQL)
    participant Dex as Dex Server

    Script->>Dex: Request external OIDC token<br/>client: db-ci-token-exchange-e2e
    Dex-->>Script: Dex ID token<br/>An OIDC token like a CI provider supplies<br/>aud: db-ci-token-exchange-e2e
    Script->>Truster: Login using trusted token<br/>client: db-ci-token-exchange-e2e
    activate Truster
    Truster->>Dex: Fetch OIDC metadata and signing keys
    Dex-->>Truster: OIDC metadata and signing keys
    Truster->>Truster: Verify signature and validate claims
    Truster->>PG: Resolve current trust binding from database policy
    PG-->>Truster: Subject, groups, and claim schemas
    Truster->>Truster: Mint service token
    Truster-->>Script: Truster service token<br/>sub: trusted:e2e:ci<br/>groups: [e2e:ci]
    deactivate Truster
```

## User Interactive Login from Database Policy

```mermaid
sequenceDiagram
    autonumber
    participant Script as E2E Script<br/>(kubelogin + browser)
    participant Truster as Truster Server
    participant PG as Policy database<br/>(PostgreSQL)
    participant Dex as Dex Server

    Script->>Truster: Begin user login<br/>client: db-kubelogin-interactive-e2e
    Truster->>Dex: Delegate user authentication<br/>client: truster-interactive-e2e
    Dex-->>Script: Show sign-in page
    Script->>Dex: Sign in as test user
    Dex-->>Truster: Return user identity
    activate Truster
    Truster->>PG: Authorize current user and load groups
    PG-->>Truster: Current groups
    Truster->>Truster: Mint authorization code
    Truster-->>Script: Return authorization code to kubelogin
    deactivate Truster
    Script->>Truster: Exchange authorization code
    activate Truster
    Truster->>Truster: Mint user and refresh tokens
    Truster-->>Script: Truster user token
    deactivate Truster
    Script->>Script: Wait for user token to expire
    Script->>Truster: Refresh without another browser login
    Truster->>PG: Re-authorize client and user
    Truster-->>Script: Fresh Truster user token
```
