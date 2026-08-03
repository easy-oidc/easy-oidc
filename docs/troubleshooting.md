---
draft: false
title: 'Troubleshooting'
linkTitle: 'Troubleshooting'
weight: 8
---

Common issues and solutions when using Easy OIDC.

## Deployment Issues

### OpenTofu/Terraform apply fails with "secret does not exist"

**Symptom**: OpenTofu/Terraform fails with `Error: secret not found` when referencing Secrets Manager secrets.

**Cause**: Secrets must be created before running OpenTofu/Terraform.

**Solution**:

```bash
# Create OAuth secret
aws secretsmanager create-secret \
  --name easy-oidc-google-credentials \
  --secret-string '{
    "client_id": "your-client-id",
    "client_secret": "your-client-secret"
  }'

# Create a PKCS8 PEM private key for the default RS256 algorithm
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 | aws secretsmanager create-secret \
  --name easy-oidc-signing-key \
  --secret-string file:///dev/stdin
```

### Let's Encrypt certificate errors

**Symptom**: Browser shows "Certificate error" or Caddy logs show ACME errors.

**Cause**: Let's Encrypt cannot verify domain ownership.

**Solution**:
1. Verify DNS records are correct:
   ```bash
   dig auth.example.com A
   dig auth.example.com AAAA
   ```
   Should return the EC2 instance's public IPs.

2. Ensure security group allows HTTP (80) and HTTPS (443) from `0.0.0.0/0` (needed for ACME challenge).

3. Wait 5-10 minutes after updating DNS for propagation.

4. Check Caddy logs on the instance (requires SSH to be enabled via OpenTofu/Terraform module variables):
   ```bash
   ssh admin@<instance-ip>
   sudo journalctl -u caddy -f
   ```

### Instance fails to start

**Symptom**: EC2 instance is running but Easy OIDC is not responding.

**Cause**: User data script failed or services not started.

**Solution**:

SSH into the instance and check logs:

```bash
# Check user data execution
sudo cat /var/log/cloud-init-output.log

# Verify binaries downloaded
ls -lh /usr/local/bin/easy-oidc
ls -lh /usr/local/bin/caddy

# Verify config file was created
ls -lh /etc/easy-oidc/config.jsonc
cat /etc/easy-oidc/config.jsonc

# Check Easy OIDC service
sudo journalctl -u easy-oidc -f

# Check Caddy service
sudo journalctl -u caddy -f
```

Alternatively, on AWS Console you can view the System Log to see the user data / cloud init logs.

## Authentication Issues

### "Unable to authenticate the request" from kubectl

**Symptom**: kubectl returns `error: You must be logged in to the server (Unauthorized)`.

**Cause**: Multiple possible causes.

**Solutions**:

1. **Verify API server OIDC configuration**:
   - Check `--oidc-issuer-url` matches Easy OIDC issuer URL
   - Check `--oidc-client-id` matches the client you're using
   - Verify `--oidc-username-claim=email` and `--oidc-groups-claim=groups`

2. **Decode your ID token** to inspect claims:
   ```bash
   kubectl oidc-login get-token \
     --oidc-issuer-url=https://auth.example.com \
     --oidc-client-id=kubelogin-prod \
     --oidc-use-pkce | jq -R 'split(".") | .[1] | @base64d | fromjson'
   ```
   Verify `iss`, `aud`, and `email` claims are correct.

3. **Check token expiry**:
   - ID tokens expire after 1 hour by default
   - kubelogin should handle refresh automatically
   - Clear token cache: `rm -rf ~/.kube/cache/oidc-login/`

### Browser not opening during kubelogin authentication

**Symptom**: kubelogin says "authentication in progress" but browser doesn't open.

**Cause**: Running on a headless server or browser not detected.

**Solution**:

Use `--skip-open-browser` flag:

```yaml
args:
- get-token
- --oidc-issuer-url=https://auth.example.com
- --oidc-client-id=kubelogin-prod
- --oidc-use-pkce
- --skip-open-browser
```

kubelogin will print a URL. Copy and paste it into your local browser.

### "invalid_grant" or "code expired" errors

**Symptom**: OAuth error during token exchange.

**Cause**: Authorization code expired or was already used.

**Solution**:
- This is usually a transient error—retry the authentication
- Check system clock synchronization (use NTP)
- Verify redirect URI in OAuth app matches kubelogin's callback (`http://localhost:8000`)

### "User has no permissions" after successful login

**Symptom**: Authentication succeeds but `kubectl get pods` returns `Forbidden`.

**Cause**: User or groups not bound to any Kubernetes roles.

**Solution**:

1. **Check your groups** in the ID token:
   ```bash
   kubectl oidc-login setup \
     --oidc-issuer-url=https://auth.example.com \
     --oidc-client-id=kubelogin-prod \
     --oidc-use-pkce
   ```
   Look at the `groups` claim.

2. **Create RBAC bindings**:
   ```yaml
   apiVersion: rbac.authorization.k8s.io/v1
   kind: ClusterRoleBinding
   metadata:
     name: alice-admin
   subjects:
   - kind: User
     name: alice@example.com
     apiGroup: rbac.authorization.k8s.io
   roleRef:
     kind: ClusterRole
     name: cluster-admin
     apiGroup: rbac.authorization.k8s.io
   ```

3. **Verify groups are configured** in Easy OIDC:
   - Check `static_policy.user_group_mappings`
   - Ensure `user_group_mapping` is set for your client

### OAuth redirect URI mismatch

**Symptom**: Google/GitHub shows "redirect_uri_mismatch" error.

**Cause**: Redirect URI in OAuth app doesn't match Easy OIDC's callback URL.

**Solution**:

1. Ensure the upstream OAuth application's redirect URI is
   `https://auth.example.com/callback/<connector-id>`.
2. Check that `<connector-id>` matches a key under `user_login_connectors`.
3. **For kubelogin**: Ensure its callback is allowed by the static client policy.

## Configuration Issues

### Groups claim is empty

**Symptom**: ID token has `groups: []` even though user should have groups.

**Cause**: Client doesn't have a `user_group_mapping` configured, or the mapping does not contain the email.

**Solution**:

1. **Check the application configuration**:
   ```jsonc
   {
     "static_policy": {
       "clients": {
         "kubelogin-prod": {
           "user_group_mapping": "prod-groups"
         }
       },
       "user_group_mappings": {
         "prod-groups": {
           "alice@example.com": ["admins"]
         }
       }
     }
   }
   ```

2. **Verify email matches** (emails are case-insensitive):
   - Check the `email` claim in your ID token
   - Ensure it matches the key in `static_policy.user_group_mappings` exactly

3. **Restart Easy OIDC** after updating its configuration. Module users should
   update `easy_oidc_config` and run `tofu apply`.

### Can't connect to Easy OIDC from Kubernetes API server

**Symptom**: API server logs show "dial tcp: i/o timeout" when validating tokens.

**Cause**: Network connectivity issue between Kubernetes and Easy OIDC.

**Solution**:

1. **Test connectivity** from a cluster node:
   ```bash
   curl https://auth.example.com/.well-known/openid-configuration
   ```

2. **Check security group** allows traffic from Kubernetes nodes.

3. **If using private networking**, ensure Easy OIDC is accessible (may need internal load balancer or VPC peering).

## Operational Issues

### How to rotate signing keys

**Symptom**: Need to rotate signing keys for security compliance.

**Solution**:

1. **Generate a new RSA-3072 key**:
   ```bash
   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out new-key.pem
   ```

2. **Update the secret in Secrets Manager**:
   ```bash
   aws secretsmanager update-secret \
     --secret-id easy-oidc-signing-key \
     --secret-string file://new-key.pem
   ```

3. **Update or remove a fixed `jwks_kid`** so clients do not cache a new public
   key under the old key ID. When omitted, Easy OIDC derives it from the key.

4. **Restart the service** because secrets are loaded only during startup. For
   the AWS module, replace the instance without changing its stable network
   interface:
   ```bash
   tofu apply -replace=module.easy_oidc.aws_instance.main
   ```

5. **Users re-authenticate** automatically (existing tokens remain valid until expiry).

### Instance was terminated/replaced and users can't login

**Symptom**: After instance replacement, authentication fails.

**Cause**: DNS records not updated or Caddy hasn't obtained new certificates yet.

**Solution**:

1. **Verify DNS** points to the new instance IP.

2. **Wait for Caddy** to obtain Let's Encrypt certificates (2-5 minutes).

3. **Check Caddy logs**:
   ```bash
   ssh admin@<new-instance-ip>
   sudo journalctl -u caddy -f
   ```

4. **If certificates fail**, verify security group allows HTTP (80) for ACME challenge.

### Port 8000 already in use

**Symptom**: kubelogin fails with "address already in use" on port 8000.

**Cause**: Another service is using port 8000 locally.

**Solution**:

Use a different port for kubelogin:

```yaml
args:
- get-token
- --oidc-issuer-url=https://auth.example.com
- --oidc-client-id=kubelogin-prod
- --oidc-use-pkce
- --listen-address=127.0.0.1:18000
```

Update `static_policy.default_redirect_uris`:

```jsonc
"static_policy": {
  "default_redirect_uris": ["http://localhost:18000"],
  "clients": { "kubelogin-prod": {} }
}
```

## Debugging

### Enable verbose logging in kubelogin

```bash
kubectl oidc-login get-token \
  --oidc-issuer-url=https://auth.example.com \
  --oidc-client-id=kubelogin-prod \
  --oidc-use-pkce \
  --v=1
```

### View Easy OIDC logs

SSH into the instance:

```bash
ssh admin@<instance-ip>
sudo journalctl -u easy-oidc -f
```

### View Caddy logs

```bash
ssh admin@<instance-ip>
sudo journalctl -u caddy -f
```

### Inspect ID token claims

Use [jwt.io](https://jwt.io) to decode your ID token and inspect claims.

Or use `jq`:

```bash
echo "your-id-token" | jq -R 'split(".") | .[1] | @base64d | fromjson'
```

### Test OIDC discovery endpoint

```bash
curl https://auth.example.com/.well-known/openid-configuration | jq
```

Should return:

```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/authorize",
  "token_endpoint": "https://auth.example.com/token",
  "jwks_uri": "https://auth.example.com/jwks",
  "userinfo_endpoint": "https://auth.example.com/userinfo",
  ...
}
```

## Getting Help

If you're still stuck:

1. **Check the specification**: [System Design](/docs/spec/)
2. **Review configuration**: [Configuration Reference](/docs/config/)
3. **Search GitHub Issues**: [github.com/easy-oidc/easy-oidc/issues](https://github.com/easy-oidc/easy-oidc/issues)
4. **Open a new issue** with:
   - OpenTofu/Terraform configuration (please REDACT any secrets or confidential/personal information!)
   - Easy OIDC logs (`journalctl -u easy-oidc`)
   - Steps to reproduce
