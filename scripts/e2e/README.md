# End-to-end login flows

The E2E test runs four login flows against one Dex server, in this order. The
static flows run first, followed by their database policy equivalents. Distinct
client IDs ensure both policy sources are exercised in the same Easy OIDC
process.

## Trusted Service Login

```mermaid
sequenceDiagram
    autonumber
    participant Script as E2E Script<br/>(simulated service)
    participant Easy as Easy OIDC Server
    participant Dex as Dex Server

    Script->>Dex: Request external OIDC token<br/>client: static-ci-token-exchange-e2e
    Dex-->>Script: Dex ID token<br/>An OIDC token like a CI provider supplies<br/>aud: static-ci-token-exchange-e2e
    Script->>Easy: Login using trusted token<br/>client: static-ci-token-exchange-e2e
    activate Easy
    Easy->>Dex: Fetch OIDC metadata and signing keys
    Dex-->>Easy: OIDC metadata and signing keys
    Easy->>Easy: Verify signature and validate claims
    Easy->>Easy: Match dex-static-e2e policy
    Easy->>Easy: Apply dex-static-exchange-e2e binding
    Easy->>Easy: Mint service token
    Easy-->>Script: Easy OIDC service token<br/>sub: trusted:e2e:static<br/>groups: [e2e:static]
    deactivate Easy
```

## User Interactive Login

```mermaid
sequenceDiagram
    autonumber
    participant Script as E2E Script<br/>(kubelogin + browser)
    participant Easy as Easy OIDC Server
    participant Dex as Dex Server

    Script->>Easy: Begin user login<br/>client: static-kubelogin-interactive-e2e
    Easy->>Dex: Delegate user authentication<br/>client: easy-oidc-interactive-e2e
    Dex-->>Script: Show sign-in page
    Script->>Dex: Sign in as test user
    Dex-->>Easy: Return user identity
    activate Easy
    Easy->>Easy: Validate identity and apply static group override
    Easy->>Easy: Mint authorization code
    Easy-->>Script: Return authorization code to kubelogin
    deactivate Easy
    Script->>Easy: Exchange authorization code
    activate Easy
    Easy->>Easy: Mint user and refresh tokens
    Easy-->>Script: Easy OIDC user token
    deactivate Easy
    Script->>Script: Wait for user token to expire
    Script->>Easy: Refresh without another browser login
    Easy-->>Script: Fresh Easy OIDC user token with configured groups
```

The server log is checked after these flows to prove neither static client
caused a policy database query.

## Trusted Service Login from Database Policy

```mermaid
sequenceDiagram
    autonumber
    participant Script as E2E Script<br/>(simulated service)
    participant Easy as Easy OIDC Server
    participant PG as Policy database<br/>(PostgreSQL)
    participant Dex as Dex Server

    Script->>Dex: Request external OIDC token<br/>client: db-ci-token-exchange-e2e
    Dex-->>Script: Dex ID token<br/>An OIDC token like a CI provider supplies<br/>aud: db-ci-token-exchange-e2e
    Script->>Easy: Login using trusted token<br/>client: db-ci-token-exchange-e2e
    activate Easy
    Easy->>Dex: Fetch OIDC metadata and signing keys
    Dex-->>Easy: OIDC metadata and signing keys
    Easy->>Easy: Verify signature and validate claims
    Easy->>PG: Resolve current trust binding from database policy
    PG-->>Easy: Subject, groups, and claim schemas
    Easy->>Easy: Mint service token
    Easy-->>Script: Easy OIDC service token<br/>sub: trusted:e2e:ci<br/>groups: [e2e:ci]
    deactivate Easy
```

## User Interactive Login from Database Policy

```mermaid
sequenceDiagram
    autonumber
    participant Script as E2E Script<br/>(kubelogin + browser)
    participant Easy as Easy OIDC Server
    participant PG as Policy database<br/>(PostgreSQL)
    participant Dex as Dex Server

    Script->>Easy: Begin user login<br/>client: db-kubelogin-interactive-e2e
    Easy->>Dex: Delegate user authentication<br/>client: easy-oidc-interactive-e2e
    Dex-->>Script: Show sign-in page
    Script->>Dex: Sign in as test user
    Dex-->>Easy: Return user identity
    activate Easy
    Easy->>PG: Authorize current user and load groups
    PG-->>Easy: Current groups
    Easy->>Easy: Mint authorization code
    Easy-->>Script: Return authorization code to kubelogin
    deactivate Easy
    Script->>Easy: Exchange authorization code
    activate Easy
    Easy->>Easy: Mint user and refresh tokens
    Easy-->>Script: Easy OIDC user token
    deactivate Easy
    Script->>Script: Wait for user token to expire
    Script->>Easy: Refresh without another browser login
    Easy->>PG: Re-authorize client and user
    Easy-->>Script: Fresh Easy OIDC user token
```
