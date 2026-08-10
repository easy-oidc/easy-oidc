---
title: Sign-in Providers
weight: 3
---

Easy OIDC can expose several sign-in methods behind one issuer. A single OAuth
connector is selected automatically; multiple connectors are presented on a
selector page.

An upstream provider, such as Google or GitHub, verifies an account for Easy
OIDC. A connector tells Easy OIDC how to send users to that provider and uses a
client ID and client secret to identify your Easy OIDC installation. The
provider then returns the user to the connector's callback URL.

Provider authentication is only the first boundary. Easy OIDC applies its own
identity and access policy to decide whether to accept the account and which
downstream identity and groups to issue. Each connector is evaluated
independently: disabling one connector does not necessarily block the same
person or email address from signing in through another enabled connector.

- [GitHub](/docs/upstream/github/)
- [Google](/docs/upstream/google/)
- [Generic OAuth2/OIDC and email codes](/docs/config/#connectors)
