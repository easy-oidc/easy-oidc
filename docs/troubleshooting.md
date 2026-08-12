---
draft: false
title: 'Troubleshooting'
linkTitle: 'Troubleshooting'
weight: 8
---

Start with the component that reports the error. Keep issuer URLs, client IDs,
timestamps, and redacted logs when escalating; never share tokens or secrets.

## Check the issuer first

Confirm that discovery is reachable and describes the issuer URL you configured:

```console
curl --fail --silent --show-error \
  https://auth.example.com/.well-known/openid-configuration \
  | jq '{issuer, authorization_endpoint, token_endpoint, jwks_uri}'
```

The `issuer` value must exactly match the URL configured in Truster, kubelogin,
and the Kubernetes API server. Fetch the reported `jwks_uri` as well. A failure
before either request reaches Truster usually points to DNS, TLS, routing, or
firewall configuration rather than an OIDC setting.

## kubectl reports Unauthorized or Forbidden

- `Unauthorized` means authentication failed. Check the API server issuer,
  audience, CA/JWKS access, token expiry, and claim settings in
  [Kubernetes integration](/docs/kubernetes/).
- `Forbidden` means the token was accepted but RBAC denied the resulting user or
  groups. Compare token claims with RBAC subjects in the same guide.
- Browser launch, local callback-listener, and cache failures are user-side
  kubelogin issues;
  follow [kubelogin troubleshooting](/docs/kubelogin/#user-side-troubleshooting).

Truster ID tokens expire after 15 minutes by default. Expiry is not normally an
error: kubelogin refreshes when refresh tokens are enabled and available, or
starts a new browser login otherwise. Offline grants additionally require the
client to allow them and an `offline_access` request.

To inspect the identity and groups returned by Truster, run `kubectl oidc-login
setup` as shown in the [kubelogin guide](/docs/kubelogin/). Do not paste a token
into a third-party JWT website.

If you need to inspect a token locally, this command decodes its payload without
verifying its signature:

```console
kubectl oidc-login get-token \
  --oidc-issuer-url=https://auth.example.com \
  --oidc-client-id=kubelogin-prod \
  --oidc-pkce-method=S256 \
  | python3 -c 'import base64,json,sys; t=json.load(sys.stdin)["status"]["token"]; p=t.split(".")[1]; print(json.dumps(json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4))), indent=2))'
```

Check `iss`, `aud`, `exp`, `email`, and `groups`. Treat the output as sensitive.

## Browser sign-in fails

- For OIDC callback, token, or refresh errors, inspect Truster logs and the
  relevant client and refresh-token settings in the
  [configuration reference](/docs/config/).
- For an upstream `redirect_uri_mismatch`, configure the OAuth application with
  `https://auth.example.com/callback/<connector-id>` and ensure the connector ID
  matches [Truster configuration](/docs/config/).
- For an empty `groups` claim, verify the client's `user_group_mapping`, the
  normalized user email, and the referenced mapping in the
  [configuration reference](/docs/config/), then restart Truster.
- For `invalid_grant` or an expired authorization code, synchronize system clocks
  and retry the browser flow once; authorization codes are short-lived and
  single-use.

If the browser does not open, the callback port is busy, or refresh repeatedly
fails, use the focused [kubelogin troubleshooting guide](/docs/kubelogin/#user-side-troubleshooting).

## The service does not start

On a systemd deployment, check the unit and startup logs first:

```console
sudo systemctl status truster --no-pager
sudo journalctl -u truster -b --no-pager
sudo /usr/local/bin/truster check config \
  --config /etc/truster/config.jsonc
```

Truster exits rather than serving with invalid configuration, inaccessible
secrets, an invalid signing key, or invalid templates. The log should identify
which startup check failed. Check that the configured state database path is
writable by the service user, or that PostgreSQL is reachable with the runtime
credentials.

If a newly provisioned VM never completed setup, inspect cloud-init and verify
the installed files:

```console
sudo journalctl -u cloud-init -b --no-pager
sudo tail -n 200 /var/log/cloud-init-output.log
sudo ls -l /usr/local/bin/truster /etc/truster/config.jsonc
```

Do not include the full configuration or secret values in an issue.

## DNS and TLS fail

Check public DNS from outside the deployment network:

```console
dig auth.example.com A
dig auth.example.com AAAA
curl --verbose https://auth.example.com/.well-known/openid-configuration
```

DNS must point to the current deployment, and ports 80 and 443 must be reachable
as required by its certificate setup. On deployments using Caddy, inspect its
service log for ACME and proxy errors:

```console
sudo systemctl status caddy --no-pager
sudo journalctl -u caddy -b --no-pager
```

After changing DNS, allow time for cached records to expire. For a private CA,
the Kubernetes control plane, kubelogin users, and any other clients must all
trust that CA.

## Kubernetes cannot reach discovery or JWKS

Test the discovery and JWKS URLs from the control-plane network, not only from
your workstation. Check routing, firewall rules, DNS resolution, and private-CA
trust between the API server and Truster. A browser login can succeed while
Kubernetes authentication fails if only the user's network can reach the issuer.

## Infrastructure cannot read a secret

Create the connector, signing-key, and other required secrets before applying
the deployment. Check the secret name, region or project, provider selection,
and the VM or pod's runtime identity. Follow the canonical guide under
[Deployment](/docs/deploy/) for provider-specific permissions. Migration-only
database credentials may deliberately be unavailable to the server process.

## Rotate a signing key

Truster loads its signing key at startup and currently publishes one key.
Replacing it therefore makes tokens signed by the previous key unusable once
verifiers refresh the JWKS document.

1. Back up the current secret according to your secret manager's recovery policy.
2. Generate and store a new key compatible with `signing_algorithm`.
3. If `jwks_kid` is omitted, Truster derives a new ID from the key. If it is
   fixed, change it so the new public key is not published under the old ID.
4. Restart every Truster replica so they all use the same key.
5. Confirm discovery and JWKS are reachable, then test a new login.
6. Expect users with tokens from the old key to authenticate again.

For the default `RS256` algorithm, generate a PKCS8 RSA key with:

```console
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  -out signing-key.pem
```

Store it using your deployment's secret provider, then securely remove the local
file. Avoid rotating during an unrelated deployment so rollback responsibility
remains clear.

## Useful diagnostics

```bash
# Validate discovery metadata
curl https://auth.example.com/.well-known/openid-configuration | jq

# Follow Truster logs on a systemd deployment
sudo journalctl -u truster -f

# Follow reverse-proxy logs on a Caddy deployment
sudo journalctl -u caddy -f

# Increase kubelogin verbosity
kubectl oidc-login get-token \
  --oidc-issuer-url=https://auth.example.com \
  --oidc-client-id=kubelogin-prod \
  --oidc-pkce-method=S256 \
  --v=1
```

## Getting help

Review the [configuration reference](/docs/config/) and
[system design](/docs/spec/), then search
[GitHub issues](https://github.com/truster-dev/truster/issues). A new issue should
include reproduction steps, version, deployment method, and redacted relevant
logs and configuration. Include the exact error text, but never include ID
tokens, refresh tokens, authorization codes, private keys, or client secrets.
